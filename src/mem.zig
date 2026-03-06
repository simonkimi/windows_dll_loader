pub inline fn memcpy(dest: anytype, src: anytype, size: usize) void {
    const dest_slice: [*]u8 = @ptrCast(dest);
    const src_slice: [*]const u8 = @ptrCast(src);
    @memcpy(dest_slice[0..size], src_slice[0..size]);
}

pub inline fn memset(dest: anytype, value: u8, size: usize) void {
    const dest_slice: [*]u8 = @ptrCast(dest);
    @memset(dest_slice[0..size], value);
}


