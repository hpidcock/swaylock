//! comm.zig – Zig port of comm.c.
//! IPC pipes between the main swaylock process and the PAM child.

const std = @import("std");
const types = @import("types");

const log_err: c_int = @intFromEnum(types.LogImportance.err);

extern fn _swaylock_log(verbosity: c_int, fmt: [*c]const u8, ...) void;
extern fn _swaylock_strip_path(filepath: [*c]const u8) [*c]const u8;
extern fn password_buffer_create(size: usize) [*c]u8;
extern fn password_buffer_destroy(buffer: [*c]u8, size: usize) void;
extern fn clear_password_buffer(pw: *types.SwaylockPassword) void;

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/types.h");
    @cInclude("unistd.h");
});

extern fn run_pw_backend_child() void;

/// Maximum payload size accepted from the pipe (1 MiB).
const comm_max_payload: usize = 1 << 20;

// comm_fds[0]: main→child  (main writes [1], child reads [0])
// comm_fds[1]: child→main  (child writes [1], main reads [0])
var comm_fds: [2][2]c_int = .{ .{ -1, -1 }, .{ -1, -1 } };

fn slog(
    verbosity: anytype,
    src: std.builtin.SourceLocation,
    comptime fmt: []const u8,
    args: anytype,
) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    _swaylock_log(
        verbosity,
        "[%s:%d] %s",
        _swaylock_strip_path(src.file.ptr),
        @as(c_int, @intCast(src.line)),
        msg.ptr,
    );
}

fn slogErrno(
    verbosity: anytype,
    src: std.builtin.SourceLocation,
    comptime msg: []const u8,
) void {
    const err = c.__errno_location().*;
    var buf: [512]u8 = undefined;
    const fmtd = std.fmt.bufPrintZ(
        &buf,
        msg ++ ": {s}",
        .{std.mem.sliceTo(c.strerror(err), 0)},
    ) catch return;
    _swaylock_log(
        verbosity,
        "[%s:%d] %s",
        _swaylock_strip_path(src.file.ptr),
        @as(c_int, @intCast(src.line)),
        fmtd.ptr,
    );
}

fn readFull(fd: c_int, dst: []u8) isize {
    var offset: usize = 0;
    while (offset < dst.len) {
        const n = c.read(fd, @ptrCast(dst[offset..].ptr), dst.len - offset);
        if (n < 0) {
            if (c.__errno_location().* == c.EINTR) continue;
            slogErrno(log_err, @src(), "read() failed");
            return -1;
        } else if (n == 0) {
            if (offset == 0) return 0;
            slog(
                log_err,
                @src(),
                "read() failed: unexpected EOF",
                .{},
            );
            return -1;
        }
        offset += @intCast(n);
    }
    return @intCast(offset);
}

fn writeFull(fd: c_int, src: []const u8) bool {
    var offset: usize = 0;
    while (offset < src.len) {
        const n = c.write(
            fd,
            @ptrCast(src[offset..].ptr),
            src.len - offset,
        );
        if (n <= 0) {
            if (c.__errno_location().* == c.EINTR) continue;
            slogErrno(log_err, @src(), "write() failed");
            return false;
        }
        offset += @intCast(n);
    }
    return true;
}

fn loadLe32(b: *const [4]u8) u32 {
    return @as(u32, b[0]) |
        (@as(u32, b[1]) << 8) |
        (@as(u32, b[2]) << 16) |
        (@as(u32, b[3]) << 24);
}

fn storeLe32(b: *[4]u8, v: u32) void {
    b[0] = @truncate(v);
    b[1] = @truncate(v >> 8);
    b[2] = @truncate(v >> 16);
    b[3] = @truncate(v >> 24);
}

fn commRead(
    fd: c_int,
    payload: *[*c]u8,
    len: *usize,
) c_int {
    var msg_type: u8 = undefined;
    var n = readFull(fd, std.mem.asBytes(&msg_type));
    if (n <= 0) {
        payload.* = null;
        return @intCast(n);
    }
    var plen_buf: [4]u8 = undefined;
    n = readFull(fd, &plen_buf);
    if (n <= 0) {
        payload.* = null;
        return -1;
    }
    const plen: usize = loadLe32(&plen_buf);
    if (plen > comm_max_payload) {
        slog(
            log_err,
            @src(),
            "comm_read: payload too large: {d}",
            .{plen},
        );
        payload.* = null;
        return -1;
    }
    var buf: [*c]u8 = null;
    if (plen > 0) {
        buf = @ptrCast(c.malloc(plen + 1));
        if (buf == null) {
            slog(log_err, @src(), "allocation failed", .{});
            payload.* = null;
            return -1;
        }
        n = readFull(fd, buf[0..plen]);
        if (n <= 0) {
            c.free(buf);
            payload.* = null;
            return -1;
        }
        buf[plen] = 0;
    }
    payload.* = buf;
    len.* = plen;
    return @intCast(msg_type);
}

fn commWrite(
    fd: c_int,
    msg_type: u8,
    payload: [*c]const u8,
    len: usize,
) bool {
    if (!writeFull(fd, std.mem.asBytes(&msg_type))) return false;
    var plen_buf: [4]u8 = undefined;
    storeLe32(&plen_buf, @intCast(len));
    if (!writeFull(fd, &plen_buf)) return false;
    if (len > 0 and payload != null) {
        if (!writeFull(fd, payload[0..len])) return false;
    }
    return true;
}

/// Returns the fd the child reads incoming messages from.
export fn get_comm_child_fd() c_int {
    return comm_fds[0][0];
}

export fn comm_child_read(payload: *[*c]u8, len: *usize) c_int {
    return commRead(comm_fds[0][0], payload, len);
}

export fn comm_child_write(
    msg_type: u8,
    payload: [*c]const u8,
    len: usize,
) bool {
    return commWrite(comm_fds[1][1], msg_type, payload, len);
}

export fn comm_main_read(payload: *[*c]u8, len: *usize) c_int {
    return commRead(comm_fds[1][0], payload, len);
}

export fn comm_main_write(
    msg_type: u8,
    payload: [*c]const u8,
    len: usize,
) bool {
    return commWrite(comm_fds[0][1], msg_type, payload, len);
}

/// Returns the fd to poll for messages from the child.
export fn get_comm_reply_fd() c_int {
    return comm_fds[1][0];
}

/// Clears and sends the password buffer as a COMM_MSG_PASSWORD frame.
/// The password buffer is always cleared before returning.
export fn write_comm_password(pw: *types.SwaylockPassword) bool {
    const size = pw.len + 1;
    const copy = password_buffer_create(size);
    if (copy == null) {
        clear_password_buffer(pw);
        return false;
    }
    @memcpy(copy[0..size], pw.buffer[0..size]);
    clear_password_buffer(pw);
    const ok = commWrite(
        comm_fds[0][1],
        types.CommMsg.password,
        copy,
        size,
    );
    password_buffer_destroy(copy, size);
    return ok;
}

export fn spawn_comm_child() bool {
    if (c.pipe(&comm_fds[0][0]) != 0) {
        slogErrno(log_err, @src(), "failed to create pipe");
        return false;
    }
    if (c.pipe(&comm_fds[1][0]) != 0) {
        slogErrno(log_err, @src(), "failed to create pipe");
        return false;
    }
    const child = c.fork();
    if (child < 0) {
        slogErrno(log_err, @src(), "failed to fork");
        return false;
    } else if (child == 0) {
        _ = c.signal(c.SIGUSR1, c.SIG_IGN);
        _ = c.close(comm_fds[0][1]);
        _ = c.close(comm_fds[1][0]);
        // Redirect stdin and stdout to /dev/null so the PAM
        // module cannot fall back to prompting on the terminal
        // if the main process exits or authd is unavailable.
        const devnull = c.open("/dev/null", c.O_RDWR);
        if (devnull >= 0) {
            _ = c.dup2(devnull, c.STDIN_FILENO);
            _ = c.dup2(devnull, c.STDOUT_FILENO);
            if (devnull > c.STDOUT_FILENO) _ = c.close(devnull);
        }
        run_pw_backend_child();
        // run_pw_backend_child calls exit(); unreachable
        c.abort();
    }
    _ = c.close(comm_fds[0][0]);
    _ = c.close(comm_fds[1][1]);
    return true;
}
