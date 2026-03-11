const std = @import("std");
const dllLoader = @import("dll_loader");

pub fn main() !void {
    const dll = "C:/Windows/System32/version.dll";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    dllLoader.getLoadedDll();

    var dllHandle = dllLoader.loadDll(allocator, dll) catch |err| {
        std.debug.print("Error loading DLL: {}\n", .{err});
        return err;
    };
    defer dllHandle.deinit();
    std.debug.print("DLL loaded successfully\n", .{});
}
