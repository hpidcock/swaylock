//! pool-buffer.zig – Zig port of pool-buffer.c.
//! Manages pairs of Wayland shared-memory buffers backed by
//! Cairo image surfaces.

const std = @import("std");
const types = @import("types");

// Only system headers here — wayland/cairo/time come from types.c.
const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("sys/mman.h");
    @cInclude("unistd.h");
});

const wl = types.c;

/// Returns the address of the thread-local errno variable (Linux/glibc).
extern fn __errno_location() *c_int;

/// Opens an anonymous POSIX shared-memory object by trying
/// time-stamped names until one does not already exist.
/// Returns a file descriptor on success, or -1 on failure.
fn anonymous_shm_open() i32 {
    var retries: i32 = 100;
    while (retries > 0) : (retries -= 1) {
        var ts: wl.struct_timespec = undefined;
        _ = wl.clock_gettime(wl.CLOCK_MONOTONIC, &ts);
        const pid = c.getpid();
        // Truncate tv_nsec to u32 without panicking on a
        // signed-to-unsigned conversion.
        const nsec: u32 = @truncate(
            @as(u64, @bitCast(@as(i64, ts.tv_nsec))),
        );
        var name: [50]u8 = undefined;
        // bufPrintZ guarantees null-termination for shm_open.
        _ = std.fmt.bufPrintZ(
            &name,
            "/swaylock-{x}-{x}",
            .{ @as(u32, @intCast(pid)), nsec },
        ) catch continue;
        // shm_open guarantees that O_CLOEXEC is set.
        const fd = c.shm_open(
            @as([*c]const u8, @ptrCast(&name)),
            c.O_RDWR | c.O_CREAT | c.O_EXCL,
            @as(c.mode_t, 0o600),
        );
        if (fd >= 0) {
            _ = c.shm_unlink(@as([*c]const u8, @ptrCast(&name)));
            return fd;
        }
        if (__errno_location().* != c.EEXIST) break;
    }
    return -1;
}

fn buffer_release(
    data: ?*anyopaque,
    wl_buf: ?*wl.wl_buffer,
) callconv(.c) void {
    _ = wl_buf;
    const buffer: *types.PoolBuffer = @ptrCast(@alignCast(data.?));
    buffer.busy = false;
}

const buffer_listener: wl.wl_buffer_listener = .{
    .release = buffer_release,
};

/// Creates a Wayland shared-memory buffer of the given dimensions
/// and pixel format, populating buf in place.
/// Returns buf on success, or null on failure.
pub export fn create_buffer(
    shm: ?*wl.wl_shm,
    buf: *types.PoolBuffer,
    width: i32,
    height: i32,
    format: u32,
) ?*types.PoolBuffer {
    const stride: u32 = @as(u32, @intCast(width)) * 4;
    const size: usize = @as(usize, stride) * @as(usize, @intCast(height));
    var data: ?*anyopaque = null;
    if (size > 0) {
        const fd = anonymous_shm_open();
        if (fd == -1) return null;
        if (c.ftruncate(fd, @as(i64, @intCast(size))) < 0) {
            _ = c.close(fd);
            return null;
        }
        data = c.mmap(
            null,
            size,
            c.PROT_READ | c.PROT_WRITE,
            c.MAP_SHARED,
            fd,
            0,
        );
        const pool = wl.wl_shm_create_pool(
            shm,
            fd,
            @as(i32, @intCast(size)),
        );
        buf.buffer = wl.wl_shm_pool_create_buffer(
            pool,
            0,
            width,
            height,
            @as(i32, @intCast(stride)),
            format,
        );
        _ = wl.wl_buffer_add_listener(
            buf.buffer,
            &buffer_listener,
            @ptrCast(buf),
        );
        wl.wl_shm_pool_destroy(pool);
        _ = c.close(fd);
    }
    buf.size = size;
    buf.width = @as(u32, @intCast(width));
    buf.height = @as(u32, @intCast(height));
    buf.data = data;
    buf.surface = wl.cairo_image_surface_create_for_data(
        @as([*c]u8, @ptrCast(data)),
        wl.CAIRO_FORMAT_ARGB32,
        width,
        height,
        @as(c_int, @intCast(stride)),
    );
    buf.cairo = wl.cairo_create(buf.surface);
    return buf;
}

/// Releases all resources held by buffer and zeroes the struct.
pub export fn destroy_buffer(buffer: *types.PoolBuffer) void {
    if (buffer.buffer != null)
        wl.wl_buffer_destroy(buffer.buffer);
    if (buffer.cairo != null)
        wl.cairo_destroy(buffer.cairo);
    if (buffer.surface != null)
        wl.cairo_surface_destroy(buffer.surface);
    if (buffer.data != null)
        _ = c.munmap(buffer.data, buffer.size);
    buffer.* = std.mem.zeroes(types.PoolBuffer);
}

/// Returns a pointer to a non-busy buffer from pool[0..2],
/// allocating or reallocating it if its dimensions have changed.
/// Returns null if all buffers are busy or allocation fails.
pub export fn get_next_buffer(
    shm: ?*wl.wl_shm,
    pool: [*]types.PoolBuffer,
    width: u32,
    height: u32,
) ?*types.PoolBuffer {
    var buffer: ?*types.PoolBuffer = null;
    for (0..2) |i| {
        if (pool[i].busy) continue;
        buffer = &pool[i];
    }
    const buf = buffer orelse return null;
    if (buf.width != width or buf.height != height)
        destroy_buffer(buf);
    if (buf.buffer == null) {
        if (create_buffer(
            shm,
            buf,
            @as(i32, @intCast(width)),
            @as(i32, @intCast(height)),
            wl.WL_SHM_FORMAT_ARGB8888,
        ) == null) return null;
    }
    buf.busy = true;
    return buf;
}
