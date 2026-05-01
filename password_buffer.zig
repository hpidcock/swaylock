//! password_buffer.zig – Secure mlocked password buffer management.
//! Extracted from password.zig to break the comm↔password circular
//! dependency. Both comm.zig and password.zig import this module.

const std = @import("std");
const types = @import("types.zig");

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    @cInclude("stdlib.h");
    @cInclude("sys/mman.h");
    @cInclude("unistd.h");
});

const log = @import("log.zig");

var mlock_supported: bool = true;

fn slogErrno(
    verbosity: log.LogImportance,
    src: std.builtin.SourceLocation,
    comptime fmt: []const u8,
) void {
    log.slog(verbosity, src, fmt ++ ": errno {d}", .{std.c._errno().*});
}

/// Expects addr to be page-aligned.
fn passwordBufferLock(addr: [*]u8, size: usize) bool {
    var retries: i32 = 5;
    while (c.mlock(@ptrCast(addr), size) != 0 and retries > 0) {
        const err = std.c._errno().*;
        if (err == @intFromEnum(std.posix.E.AGAIN)) {
            retries -= 1;
            if (retries == 0) {
                log.slog(
                    log.LogImportance.err,
                    @src(),
                    "mlock() supported but failed too often.",
                    .{},
                );
                return false;
            }
        } else if (err == @intFromEnum(std.posix.E.PERM)) {
            slogErrno(
                log.LogImportance.err,
                @src(),
                "Unable to mlock() password memory: Unsupported!",
            );
            mlock_supported = false;
            return true;
        } else {
            slogErrno(
                log.LogImportance.err,
                @src(),
                "Unable to mlock() password memory.",
            );
            return false;
        }
    }
    return true;
}

/// Expects addr to be page-aligned.
fn passwordBufferUnlock(addr: [*]u8, size: usize) bool {
    if (mlock_supported) {
        if (c.munlock(@ptrCast(addr), size) != 0) {
            slogErrno(
                log.LogImportance.err,
                @src(),
                "Unable to munlock() password memory.",
            );
            return false;
        }
    }
    return true;
}

/// Allocates a page-aligned, mlocked buffer of the given size.
/// Returns a pointer to the buffer on success, or null on failure.
pub fn passwordBufferCreate(size: usize) ?[*]u8 {
    var buffer: ?*anyopaque = null;
    // posix_memalign requires page-size alignment; use sysconf to
    // retrieve the runtime page size portably.
    const page_size: usize = @intCast(c.sysconf(c._SC_PAGESIZE));
    const result = c.posix_memalign(
        &buffer,
        page_size,
        size,
    );
    if (result != 0) {
        // posix_memalign does not set errno per the man page.
        std.c._errno().* = result;
        slogErrno(
            log.LogImportance.err,
            @src(),
            "failed to alloc password buffer",
        );
        return null;
    }
    const buf: [*]u8 = @ptrCast(buffer.?);
    if (!passwordBufferLock(buf, size)) {
        c.free(buffer);
        return null;
    }
    return buf;
}

/// Clears and frees a buffer previously created by passwordBufferCreate.
pub fn passwordBufferDestroy(buffer: ?[*]u8, size: usize) void {
    clearBuffer(buffer, size);
    _ = passwordBufferUnlock(buffer.?, size);
    c.free(@ptrCast(buffer));
}

/// Clears a buffer using volatile writes so the compiler cannot
/// optimise the zeroing away.
pub fn clearBuffer(buf: ?[*]u8, size: usize) void {
    const vbuf: [*]volatile u8 = @ptrCast(buf.?);
    for (0..size) |i|
        vbuf[i] = 0;
}

/// Clears the password buffer and resets the length to zero.
pub fn clearPasswordBuffer(pw: *types.SwaylockPassword) void {
    clearBuffer(pw.buffer, pw.buffer_len);
    pw.len = 0;
}
