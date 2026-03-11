const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = @import("mem");

const windows = @cImport({
    @cDefine("UNICODE", "1");
    @cDefine("_UNICODE", "1");
    @cInclude("windows.h");
    @cInclude("psapi.h");
});

const DllHandle = struct {
    allocator: Allocator,
    memory: []u8,

    pub fn deinit(self: *@This()) void {
        var old: windows.DWORD = 0;
        _ = windows.VirtualProtect(self.memory.ptr, self.memory.len, windows.PAGE_READWRITE, &old);
        self.allocator.free(self.memory);
    }
};

const LoadDllError = error{
    InvalidFile,
    InvalidDosSignature,
    InvalidNtSignature,
    OutOfMemory,
    VirtualProtectFailed,
};

fn getPageProtectFlags(characteristics: windows.DWORD) windows.DWORD {
    const exec = characteristics & windows.IMAGE_SCN_MEM_EXECUTE != 0;
    const read = characteristics & windows.IMAGE_SCN_MEM_READ != 0;
    const write = characteristics & windows.IMAGE_SCN_MEM_WRITE != 0;

    var flags: u3 = 0;
    if (exec) flags |= 0b100;
    if (read) flags |= 0b010;
    if (write) flags |= 0b001;

    var protect: windows.DWORD = switch (flags) {
        0b111 => windows.PAGE_EXECUTE_READWRITE,
        0b110 => windows.PAGE_EXECUTE_READ,
        0b101 => windows.PAGE_EXECUTE_WRITECOPY,
        0b100 => windows.PAGE_EXECUTE,
        0b011 => windows.PAGE_READWRITE,
        0b010 => windows.PAGE_READONLY,
        0b001 => windows.PAGE_WRITECOPY,
        0b000 => windows.PAGE_NOACCESS,
    };

    if (characteristics & windows.IMAGE_SCN_MEM_NOT_CACHED != 0) {
        protect |= windows.PAGE_NOCACHE;
    }

    return protect;
}

const RelocItem = packed struct {
    offset: u12,
    type: u4,
};

const SectionProtectValue = struct {
    protect: windows.DWORD,
    address: [*]u8,
    size: usize,
};

const ImageImportDescriptor = packed struct {
    OriginalFirstThunk: windows.DWORD,
    TimeDateStamp: windows.DWORD,
    ForwarderChain: windows.DWORD,
    Name: windows.DWORD,
    FirstThunk: windows.DWORD,
};

pub fn getLoadedDll() void {
    const currentProcess: windows.HANDLE = windows.GetCurrentProcess();

    var modules: [1024]windows.HMODULE = undefined;
    @memset(&modules, 0);
    var cbNeeded: windows.DWORD = 0;
    const result = windows.EnumProcessModules(currentProcess, &modules, @sizeOf(@TypeOf(modules)), &cbNeeded);
    if (result != windows.TRUE) {
        const lastError = windows.GetLastError();
        std.debug.print("EnumProcessModules failed: 0x{x}\n", .{lastError});
        return;
    }

    const moduleCount = cbNeeded / @sizeOf(windows.HMODULE);
    var pathBuffer: [100]u8 = undefined;
    for (0..moduleCount) |i| {
        const module = modules[i];
        const path = windows.GetModuleFileNameExA(currentProcess, module, &pathBuffer, 100);
        if (path == 0) {
            const lastError = windows.GetLastError();
            std.debug.print("GetModuleFileNameExW failed: 0x{x}\n", .{lastError});
            continue;
        }
        std.debug.print("Module {}: {s}\n", .{ i, pathBuffer[0..path] });
    }
}

pub fn loadDll(allocator: Allocator, path: []const u8) LoadDllError!DllHandle {
    // 加载文件
    const file = std.fs.cwd().openFile(path, .{}) catch return LoadDllError.InvalidFile;
    defer file.close();

    const fileSize = file.getEndPos() catch return LoadDllError.InvalidFile;
    const peFile =
        file.readToEndAlloc(allocator, fileSize) catch return LoadDllError.OutOfMemory;
    defer allocator.free(peFile);

    // 加载pe
    const dosHeader: *windows.IMAGE_DOS_HEADER = @ptrCast(@alignCast(peFile.ptr));
    std.debug.print("e_magic: 0x{x}\n", .{dosHeader.*.e_magic});
    if (dosHeader.*.e_magic != windows.IMAGE_DOS_SIGNATURE) {
        return LoadDllError.InvalidDosSignature;
    }
    const ntHeadersOffset: usize = @intCast(dosHeader.e_lfanew);

    const ntHeaders: *windows.IMAGE_NT_HEADERS = @ptrCast(@alignCast(peFile.ptr + ntHeadersOffset));
    if (ntHeaders.Signature != windows.IMAGE_NT_SIGNATURE) {
        return LoadDllError.InvalidNtSignature;
    }

    const pageAllocator = std.heap.page_allocator;
    const peMemory = pageAllocator.alloc(u8, ntHeaders.OptionalHeader.SizeOfImage) catch return LoadDllError.OutOfMemory;
    const delta: i64 = @intCast(@intFromPtr(peMemory.ptr) - ntHeaders.OptionalHeader.ImageBase);

    // 复制PE头
    const headerSize = ntHeaders.OptionalHeader.SizeOfHeaders;
    mem.memcpy(peMemory, peFile, headerSize);

    var sectionProtectList: std.ArrayList(SectionProtectValue) = .empty;
    defer sectionProtectList.deinit(allocator);

    // 复制节区数据
    const sectionHeaders: [*]const windows.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(peFile.ptr + ntHeadersOffset + @sizeOf(windows.IMAGE_NT_HEADERS)));
    const sectionHeadersSlice: []const windows.IMAGE_SECTION_HEADER = sectionHeaders[0..ntHeaders.FileHeader.NumberOfSections];
    for (sectionHeadersSlice) |section| {
        const fileOffset = section.PointerToRawData;
        const memoryOffset = section.VirtualAddress;
        const dataSize = section.SizeOfRawData;
        const memSize = section.Misc.VirtualSize;

        if (dataSize > 0) {
            mem.memcpy(&peMemory[memoryOffset], &peFile[fileOffset], dataSize);
        }
        if (memSize > dataSize) {
            mem.memset(&peMemory[memoryOffset + dataSize], 0, memSize - dataSize);
        }

        // 设置节区保护
        const protect = getPageProtectFlags(section.Characteristics);
        sectionProtectList.append(allocator, SectionProtectValue{
            .protect = protect,
            .address = peMemory.ptr + memoryOffset,
            .size = memSize,
        }) catch return LoadDllError.OutOfMemory;
    }

    // 修补重定位表
    const relocAddress = ntHeaders.OptionalHeader.DataDirectory[windows.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    var relocOffset: usize = 0;

    while (true) {
        const relocBaseData: *const windows.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(peMemory.ptr + relocAddress + relocOffset));
        std.debug.print("relocBaseData: 0x{x}, SizeOfBlock: 0x{x}, VirtualAddress: 0x{x}\n", .{ @intFromPtr(relocBaseData), relocBaseData.SizeOfBlock, relocBaseData.VirtualAddress });
        if (relocBaseData.SizeOfBlock == 0) break;
        relocOffset += relocBaseData.SizeOfBlock;

        const itemCount = (relocBaseData.SizeOfBlock - @sizeOf(windows.IMAGE_BASE_RELOCATION)) / @sizeOf(windows.WORD);
        const relocItems: [*]windows.WORD = @ptrFromInt(@intFromPtr(relocBaseData) + @sizeOf(windows.IMAGE_BASE_RELOCATION));
        const relocItemsSlice: []windows.WORD = relocItems[0..itemCount];
        for (relocItemsSlice) |relocWord| {
            const relocItem: *const RelocItem = @ptrCast(&relocWord);
            const patchAddr = peMemory.ptr + relocBaseData.VirtualAddress + relocItem.offset;
            if (relocItem.type == windows.IMAGE_REL_BASED_DIR64) {
                const ptr: *u64 = @ptrCast(@alignCast(patchAddr));
                const newAddr = @as(i128, ptr.*) + delta;
                const asUnsigned: u128 = @bitCast(newAddr);
                ptr.* = @truncate(asUnsigned);
            } else if (relocItem.type == windows.IMAGE_REL_BASED_HIGHLOW and ntHeaders.OptionalHeader.Magic == windows.IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                const ptr: *u32 = @ptrCast(@alignCast(patchAddr));
                const newAddr = @as(i64, ptr.*) + delta;
                const asUnsigned: u64 = @bitCast(newAddr);
                ptr.* = @truncate(asUnsigned);
            }
        }
    }

    // 修补导入表
    const importAddress = ntHeaders.OptionalHeader.DataDirectory[windows.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const importDescriptor: [*]const ImageImportDescriptor = @ptrCast(@alignCast(peMemory.ptr + importAddress));
    var i: usize = 0;
    while (true) {
        const importDesc = importDescriptor[i];
        i += 1;
        if (importDesc.OriginalFirstThunk == 0) break;

        const thunk_rva32: windows.DWORD =
            if (importDesc.OriginalFirstThunk != 0)
                importDesc.OriginalFirstThunk
            else
                importDesc.FirstThunk;

        var thunkOffset: usize = thunk_rva32;
        while (true) {
            const thunkItem: *align(1) windows.ULONGLONG = @ptrCast(@alignCast(peMemory.ptr + thunkOffset));
            if (thunkItem.* == 0) break;
            if (windows.IMAGE_SNAP_BY_ORDINAL(thunkItem.*)) {
                const ordinal: windows.ULONGLONG = windows.IMAGE_ORDINAL(thunkItem.*);
                std.debug.print("Import by ordinal: {}\n", .{ordinal});
            } else {
                const rva: usize = @intCast(thunkItem.* & 0xFFFF_FFFF);
                if (rva > ntHeaders.OptionalHeader.SizeOfImage) {
                    continue;
                }
                const namePtr: [*:0]u8 = @ptrCast(@alignCast(peMemory.ptr + rva + 2));
                std.debug.print("Import by name: {s}\n", .{namePtr});
            }
            thunkOffset += @sizeOf(windows.ULONGLONG);
        }
    }

    // 恢复节区保护
    for (sectionProtectList.items) |sectionProtect| {
        var oldProtect: windows.DWORD = 0;
        const result = windows.VirtualProtect(sectionProtect.address, sectionProtect.size, sectionProtect.protect, &oldProtect);
        if (result != windows.TRUE) {
            const lastError = windows.GetLastError();
            std.debug.print("VirtualProtect failed: 0x{x}\n", .{lastError});
            return LoadDllError.VirtualProtectFailed;
        }
    }

    return DllHandle{
        .allocator = pageAllocator,
        .memory = peMemory,
    };
}
