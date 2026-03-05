const std = @import("std");
const Allocator = std.mem.Allocator;

const windows = @cImport({
    @cDefine("UNICODE", "1");
    @cDefine("_UNICODE", "1");
    @cInclude("windows.h");
});

const DllHandle = struct {
    allocator: Allocator,
    memory: []u8,

    pub fn deinit(self: *@This()) void {
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
    std.debug.print("e_magic: {x}\n", .{dosHeader.*.e_magic});
    if (dosHeader.*.e_magic != windows.IMAGE_DOS_SIGNATURE) {
        return LoadDllError.InvalidDosSignature;
    }
    const ntHeadersOffset: usize = @intCast(dosHeader.*.e_lfanew);

    const ntHeaders: *windows.IMAGE_NT_HEADERS = @ptrCast(@alignCast(peFile.ptr + ntHeadersOffset + @sizeOf(windows.IMAGE_NT_HEADERS)));
    if (ntHeaders.Signature != windows.IMAGE_NT_SIGNATURE) {
        return LoadDllError.InvalidNtSignature;
    }

    const pageAllocator = std.heap.page_allocator;
    const peMemory = pageAllocator.alloc(u8, ntHeaders.OptionalHeader.SizeOfImage) catch return LoadDllError.OutOfMemory;

    // 复制dos头与nt头
    const headerSize = ntHeaders.OptionalHeader.SizeOfHeaders;
    @memcpy(peMemory[0..headerSize], peFile[0..headerSize]);

    // 复制节区数据
    const sectionHeaders: [*]const windows.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(peFile.ptr + ntHeadersOffset + @sizeOf(windows.IMAGE_NT_HEADERS)));
    const sectionHeadersSlice: []const windows.IMAGE_SECTION_HEADER = @ptrCast(sectionHeaders[0..ntHeaders.FileHeader.NumberOfSections]);
    for (sectionHeadersSlice) |section| {
        const fileOffset = section.PointerToRawData;
        const memoryOffset = section.VirtualAddress;
        const dataSize = section.SizeOfRawData;
        const memSize = section.Misc.VirtualSize;

        const characteristics = section.Characteristics;

        // 拷贝节数据到内存
        if (characteristics & (windows.IMAGE_SCN_CNT_CODE | windows.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0) {
            @memcpy(peMemory[memoryOffset..(memoryOffset + dataSize)], peFile[fileOffset..(fileOffset + dataSize)]);
            if (memSize > dataSize) {
                @memset(peMemory[memoryOffset + dataSize .. (memoryOffset + memSize)], 0);
            }
        } else if (characteristics & windows.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0) {
            @memset(peMemory[memoryOffset..(memoryOffset + memSize)], 0);
        } else {
            continue;
        }

        // 设置页保护
        const protect = getPageProtectFlags(characteristics);
        const result = windows.VirtualProtect(peMemory.ptr + memoryOffset, memSize, protect, null);
        if (result != windows.TRUE) {
            return LoadDllError.VirtualProtectFailed;
        }
    }

    return DllHandle{
        .allocator = pageAllocator,
        .memory = peMemory,
    };
}
