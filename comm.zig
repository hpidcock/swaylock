//! comm.zig – Zig port of comm.c.
//! IPC pipes between the main swaylock process and the PAM child.

const std = @import("std");
const types = @import("types");

const log_err: i32 = @intFromEnum(types.LogImportance.err);

const log = @import("log");

extern fn password_buffer_create(size: usize) ?[*]u8;
extern fn password_buffer_destroy(buffer: ?[*]u8, size: usize) void;
extern fn clear_password_buffer(pw: *types.SwaylockPassword) void;

extern fn run_pw_backend_child() void;

/// Maximum payload size accepted from the pipe (1 MiB).
const comm_max_payload: usize = 1 << 20;

// comm_fds[0]: main→child  (main writes [1], child reads [0])
// comm_fds[1]: child→main  (child writes [1], main reads [0])
var comm_fds: [2][2]i32 = .{ .{ -1, -1 }, .{ -1, -1 } };

fn slogErrno(
    verbosity: i32,
    src: std.builtin.SourceLocation,
    comptime msg: []const u8,
    err: anyerror,
) void {
    log.slog(verbosity, src, msg ++ ": {s}", .{@errorName(err)});
}

fn readFull(fd: i32, dst: []u8) isize {
    var offset: usize = 0;
    while (offset < dst.len) {
        const n = std.posix.read(fd, dst[offset..]) catch |err| {
            if (err == error.Interrupted) continue;
            slogErrno(log_err, @src(), "read() failed", err);
            return -1;
        };
        if (n == 0) {
            if (offset == 0) return 0;
            log.slog(
                log_err,
                @src(),
                "read() failed: unexpected EOF",
                .{},
            );
            return -1;
        }
        offset += n;
    }
    return @intCast(offset);
}

fn writeFull(fd: i32, src: []const u8) bool {
    var offset: usize = 0;
    while (offset < src.len) {
        const n = std.posix.write(fd, src[offset..]) catch |err| {
            if (err == error.Interrupted) continue;
            slogErrno(log_err, @src(), "write() failed", err);
            return false;
        };
        if (n == 0) {
            log.slog(log_err, @src(), "write() returned 0", .{});
            return false;
        }
        offset += n;
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
    fd: i32,
    payload: *?[*]u8,
    len: *usize,
) i32 {
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
        log.slog(
            log_err,
            @src(),
            "comm_read: payload too large: {d}",
            .{plen},
        );
        payload.* = null;
        return -1;
    }
    var buf: ?[*]u8 = null;
    if (plen > 0) {
        buf = @ptrCast(std.c.malloc(plen + 1));
        if (buf == null) {
            log.slog(log_err, @src(), "allocation failed", .{});
            payload.* = null;
            return -1;
        }
        n = readFull(fd, buf.?[0..plen]);
        if (n <= 0) {
            std.c.free(@ptrCast(buf));
            payload.* = null;
            return -1;
        }
        buf.?[plen] = 0;
    }
    payload.* = buf;
    len.* = plen;
    return @intCast(msg_type);
}

fn commWrite(
    fd: i32,
    msg_type: u8,
    payload: ?[*]const u8,
    len: usize,
) bool {
    if (!writeFull(fd, std.mem.asBytes(&msg_type))) return false;
    var plen_buf: [4]u8 = undefined;
    storeLe32(&plen_buf, @intCast(len));
    if (!writeFull(fd, &plen_buf)) return false;
    if (len > 0 and payload != null) {
        if (!writeFull(fd, payload.?[0..len])) return false;
    }
    return true;
}

/// Returns the fd the child reads incoming messages from.
pub fn getCommChildFd() i32 {
    return comm_fds[0][0];
}

/// Reads a message from the child-facing pipe.
pub fn commChildRead(payload: *?[*]u8, len: *usize) i32 {
    return commRead(comm_fds[0][0], payload, len);
}

/// Writes a message to the child-facing pipe.
pub fn commChildWrite(
    msg_type: u8,
    payload: ?[*]const u8,
    len: usize,
) bool {
    return commWrite(comm_fds[1][1], msg_type, payload, len);
}

/// Reads a message from the main-facing pipe.
pub fn commMainRead(payload: *?[*]u8, len: *usize) i32 {
    return commRead(comm_fds[1][0], payload, len);
}

/// Writes a message to the main-facing pipe.
pub fn commMainWrite(
    msg_type: u8,
    payload: ?[*]const u8,
    len: usize,
) bool {
    return commWrite(comm_fds[0][1], msg_type, payload, len);
}

/// Returns the fd to poll for messages from the child.
pub fn getCommReplyFd() i32 {
    return comm_fds[1][0];
}

/// Clears and sends the password buffer as a COMM_MSG_PASSWORD frame.
/// The password buffer is always cleared before returning.
pub fn writeCommPassword(pw: *types.SwaylockPassword) bool {
    const size: usize = @intCast(pw.len + 1);
    const copy = password_buffer_create(size);
    if (copy == null) {
        clear_password_buffer(pw);
        return false;
    }
    @memcpy(copy.?[0..size], pw.buffer.?[0..size]);
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

/// Spawns the comm child process.
pub fn spawnCommChild() bool {
    const fds0 = std.posix.pipe() catch |err| {
        slogErrno(log_err, @src(), "failed to create pipe", err);
        return false;
    };
    comm_fds[0] = fds0;
    const fds1 = std.posix.pipe() catch |err| {
        slogErrno(log_err, @src(), "failed to create pipe", err);
        return false;
    };
    comm_fds[1] = fds1;
    const child = std.posix.fork() catch |err| {
        slogErrno(log_err, @src(), "failed to fork", err);
        return false;
    };
    if (child == 0) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.posix.empty_sigset,
            .flags = 0,
        };
        std.posix.sigaction(
            std.posix.SIG.USR1,
            &act,
            null,
        );
        std.posix.close(comm_fds[0][1]);
        std.posix.close(comm_fds[1][0]);
        // Redirect stdin and stdout to /dev/null so the PAM
        // module cannot fall back to prompting on the terminal
        // if the main process exits or authd is unavailable.
        if (std.posix.open(
            "/dev/null",
            .{ .ACCMODE = .RDWR },
            0,
        )) |devnull| {
            std.posix.dup2(devnull, 0) catch {};
            std.posix.dup2(devnull, 1) catch {};
            if (devnull > 1) std.posix.close(devnull);
        } else |_| {}
        run_pw_backend_child();
        // run_pw_backend_child calls exit(); unreachable
        unreachable;
    }
    std.posix.close(comm_fds[0][0]);
    std.posix.close(comm_fds[1][1]);
    return true;
}
