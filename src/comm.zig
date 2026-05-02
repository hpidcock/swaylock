//! IPC pipe communication between the main process and PAM child.

const std = @import("std");
const types = @import("types.zig");

const log = @import("log.zig");
const password_buffer = @import("password_buffer.zig");
const landlock = @import("landlock.zig");

/// Maximum payload size accepted from the pipe (1 MiB).
/// Prevents unbounded allocation from malformed messages.
const comm_max_payload: usize = 1 << 20;

// comm_fds[0]: main writes [1], child reads [0].
// comm_fds[1]: child writes [1], main reads [0].
var comm_fds: [2][2]i32 = .{ .{ -1, -1 }, .{ -1, -1 } };

fn slogErrno(
    verbosity: log.LogImportance,
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
            slogErrno(log.LogImportance.err, @src(), "read() failed", err);
            return -1;
        };
        if (n == 0) {
            if (offset == 0) return 0;
            log.slog(
                log.LogImportance.err,
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
            slogErrno(log.LogImportance.err, @src(), "write() failed", err);
            return false;
        };
        if (n == 0) {
            log.slog(log.LogImportance.err, @src(), "write() returned 0", .{});
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

/// Result of reading a message from the pipe.
/// msg_type <= 0: payload is empty (0 = EOF, -1 = error).
/// msg_type > 0: payload is malloc-allocated; caller frees.
pub const CommRead = struct {
    msg_type: i32,
    payload: []u8,
};

fn commRead(fd: i32) CommRead {
    var msg_type: u8 = undefined;
    var n = readFull(fd, std.mem.asBytes(&msg_type));
    if (n <= 0)
        return .{ .msg_type = @intCast(n), .payload = &.{} };
    var plen_buf: [4]u8 = undefined;
    n = readFull(fd, &plen_buf);
    if (n <= 0)
        return .{ .msg_type = -1, .payload = &.{} };
    const plen: usize = loadLe32(&plen_buf);
    if (plen > comm_max_payload) {
        log.slog(
            log.LogImportance.err,
            @src(),
            "comm_read: payload too large: {d}",
            .{plen},
        );
        return .{ .msg_type = -1, .payload = &.{} };
    }
    if (plen == 0)
        return .{ .msg_type = msg_type, .payload = &.{} };
    const raw = std.c.malloc(plen + 1) orelse {
        log.slog(
            log.LogImportance.err,
            @src(),
            "allocation failed",
            .{},
        );
        return .{ .msg_type = -1, .payload = &.{} };
    };
    const buf: [*]u8 = @ptrCast(raw);
    n = readFull(fd, buf[0..plen]);
    if (n <= 0) {
        std.c.free(raw);
        return .{ .msg_type = -1, .payload = &.{} };
    }
    buf[plen] = 0;
    return .{ .msg_type = msg_type, .payload = buf[0..plen] };
}

fn commWrite(
    fd: i32,
    msg_type: u8,
    payload: []const u8,
) bool {
    if (!writeFull(fd, std.mem.asBytes(&msg_type))) return false;
    var plen_buf: [4]u8 = undefined;
    storeLe32(&plen_buf, @intCast(payload.len));
    if (!writeFull(fd, &plen_buf)) return false;
    if (payload.len > 0) {
        if (!writeFull(fd, payload)) return false;
    }
    return true;
}

/// Returns the fd the child reads from.
pub fn getCommChildFd() i32 {
    return comm_fds[0][0];
}

/// Reads a message from the main-to-child pipe.
pub fn commChildRead() CommRead {
    return commRead(comm_fds[0][0]);
}

/// Writes a message on the child-to-main pipe.
pub fn commChildWrite(
    msg_type: u8,
    payload: []const u8,
) bool {
    return commWrite(comm_fds[1][1], msg_type, payload);
}

/// Reads a message from the child-to-main pipe.
pub fn commMainRead() CommRead {
    return commRead(comm_fds[1][0]);
}

/// Writes a message on the main-to-child pipe.
pub fn commMainWrite(
    msg_type: u8,
    payload: []const u8,
) bool {
    return commWrite(comm_fds[0][1], msg_type, payload);
}

/// Returns the fd to poll for child replies.
pub fn getCommReplyFd() i32 {
    return comm_fds[1][0];
}

/// Sends the password as a COMM_MSG_PASSWORD frame.
/// The password buffer is always zeroed before returning.
pub fn writeCommPassword(pw: *types.SwaylockPassword) bool {
    const size: usize = @intCast(pw.len + 1);
    const copy = password_buffer.create(size);
    if (copy == null) {
        password_buffer.clear(pw);
        return false;
    }
    @memcpy(copy.?[0..size], pw.buffer.?[0..size]);
    password_buffer.clear(pw);
    const ok = commWrite(
        comm_fds[0][1],
        types.CommMsg.password,
        copy.?[0..size],
    );
    password_buffer.destroy(copy.?[0..size]);
    return ok;
}

/// Forks the comm child process and sets up pipe fds.
pub fn spawnCommChild(child_fn: *const fn () void) bool {
    const fds0 = std.posix.pipe() catch |err| {
        slogErrno(log.LogImportance.err, @src(), "failed to create pipe", err);
        return false;
    };
    comm_fds[0] = fds0;
    const fds1 = std.posix.pipe() catch |err| {
        slogErrno(log.LogImportance.err, @src(), "failed to create pipe", err);
        return false;
    };
    comm_fds[1] = fds1;
    const child = std.posix.fork() catch |err| {
        slogErrno(log.LogImportance.err, @src(), "failed to fork", err);
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
        // Redirect stdio to /dev/null so PAM cannot fall
        // back to terminal prompting.
        if (std.posix.open(
            "/dev/null",
            .{ .ACCMODE = .RDWR },
            0,
        )) |devnull| {
            std.posix.dup2(devnull, 0) catch {};
            std.posix.dup2(devnull, 1) catch {};
            if (devnull > 1) std.posix.close(devnull);
        } else |_| {}
        landlock.applyToPamChild();
        child_fn();
        // child_fn never returns.
        unreachable;
    }
    std.posix.close(comm_fds[0][0]);
    std.posix.close(comm_fds[1][1]);
    return true;
}
