pub fn asPtr(comptime T: type, ptr: *anyopaque) *T {
    return @ptrCast(@alignCast(ptr));
}

pub fn asPtrWithOffset(comptime T: type, ptr: *anyopaque, offset: anytype) *T {
    const byteOffset: usize = switch (@typeInfo(@TypeOf(offset))) {
        .int => @intCast(offset),
        .comptime_int => @intCast(offset),
        else => @compileError("offset must be an integer type"),
    };

    const base: [*]u8 = @ptrCast(@alignCast(ptr));
    return @ptrCast(@alignCast(base + byteOffset));
}
