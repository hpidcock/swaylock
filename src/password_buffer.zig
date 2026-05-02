//! Secure mlocked password buffer management. Breaks the
//! comm/password circular dependency.

const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

/// Allocates a page-aligned, mlocked buffer of the given size.
/// Returns null on failure.
pub fn create(size: usize) ?[]u8 {
    const flags: std.posix.MAP = .{
        .TYPE = .PRIVATE,
        .ANONYMOUS = true,
        .LOCKED = true,
    };
    const slice = std.posix.mmap(
        null,
        size,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        flags,
        0,
        0,
    ) catch |err| {
        log.slog(
            log.LogImportance.err,
            @src(),
            "failed to alloc password buffer: {s}",
            .{@errorName(err)},
        );
        return null;
    };
    return slice;
}

/// Zeros then unmaps a buffer previously created by create.
pub fn destroy(buffer: []u8) void {
    zero(buffer);
    const aligned: []align(std.heap.page_size_min) u8 = @as([*]align(std.heap.page_size_min) u8, @ptrCast(
        @alignCast(buffer),
    ))[0..buffer.len];
    std.posix.munmap(aligned);
}

/// Volatile-zeros a buffer to prevent compiler optimisation.
pub fn zero(buf: ?[]u8) void {
    const vbuf: [*]volatile u8 = @ptrCast(buf.?.ptr);
    for (0..buf.?.len) |i|
        vbuf[i] = 0;
}

/// Zeros the password buffer and resets length to zero.
pub fn clear(pw: *types.SwaylockPassword) void {
    zero(pw.buffer);
    pw.len = 0;
}
