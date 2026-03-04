const std = @import("std");
const ptr = @import("ptr");
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
};

pub fn loadDll(allocator: Allocator, path: []const u8) LoadDllError!DllHandle {
    // 加载文件
    const file = std.fs.cwd().openFile(path, .{}) catch return LoadDllError.InvalidFile;
    defer file.close();

    const fileSize = file.getEndPos() catch return LoadDllError.InvalidFile;
    const fileContents =
        file.readToEndAlloc(allocator, fileSize) catch return LoadDllError.OutOfMemory;
    defer allocator.free(fileContents);

    // 加载pe
    const dosHeader = ptr.asPtr(windows.IMAGE_DOS_HEADER, fileContents.ptr);
    std.debug.print("e_magic: {x}\n", .{dosHeader.e_magic});
    if (dosHeader.e_magic != windows.IMAGE_DOS_SIGNATURE) {
        return LoadDllError.InvalidDosSignature;
    }

    const ntHeaders: *windows.IMAGE_NT_HEADERS = ptr.asPtrWithOffset(windows.IMAGE_NT_HEADERS, fileContents.ptr, dosHeader.e_lfanew);
    if (ntHeaders.Signature != windows.IMAGE_NT_SIGNATURE) {
        return LoadDllError.InvalidNtSignature;
    }

    // 打印基础nt头信息
    std.debug.print("Magic: {x}\n", .{ntHeaders.Signature});
    std.debug.print("Machine: {x}\n", .{ntHeaders.FileHeader.Machine});
    std.debug.print("NumberOfSections: {}\n", .{ntHeaders.FileHeader.NumberOfSections});
    std.debug.print("TimeDateStamp: {}\n", .{ntHeaders.FileHeader.TimeDateStamp});
    std.debug.print("PointerToSymbolTable: {}\n", .{ntHeaders.FileHeader.PointerToSymbolTable});
    std.debug.print("NumberOfSymbols: {}\n", .{ntHeaders.FileHeader.NumberOfSymbols});
    std.debug.print("SizeOfOptionalHeader: {}\n", .{ntHeaders.FileHeader.SizeOfOptionalHeader});

    const pageAllocator = std.heap.page_allocator;

    const peMemory = pageAllocator.alloc(u8, ntHeaders.OptionalHeader.SizeOfImage) catch return LoadDllError.OutOfMemory;

    return DllHandle{
        .allocator = pageAllocator,
        .memory = peMemory,
    };
}
