//! poll(2)-based event loop for Wayland clients.

const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

inline fn alloc() std.mem.Allocator {
    return @import("allocator").general();
}

/// Allocates and initialises a new event loop.
pub fn loopCreate() ?*types.Loop {
    const loop = alloc().create(types.Loop) catch {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Unable to allocate memory for loop",
            .{},
        );
        return null;
    };
    loop.* = .{
        .fd_events = .{},
        .timers = .{},
    };
    return loop;
}

/// Frees all registered fds, timers, and the loop itself.
pub fn loopDestroy(loop: *types.Loop) void {
    loop.fd_events.deinit(alloc());
    for (loop.timers.items) |t| alloc().destroy(t);
    loop.timers.deinit(alloc());
    alloc().destroy(loop);
}

/// Polls once, dispatching ready fds and expired timers.
/// Blocks until an event is ready or a timer fires.
pub fn loopPoll(loop: *types.Loop) void {
    var ms: i32 = std.math.maxInt(i32);
    if (loop.timers.items.len > 0) {
        const now = std.posix.clock_gettime(.MONOTONIC) catch
            std.posix.timespec{ .sec = 0, .nsec = 0 };
        for (loop.timers.items) |timer| {
            const sec_diff: i64 =
                @as(i64, timer.expiry.sec) - @as(i64, now.sec);
            const nsec_diff: i64 =
                @as(i64, timer.expiry.nsec) - @as(i64, now.nsec);
            const full: i64 =
                sec_diff * 1000 + @divTrunc(nsec_diff, 1_000_000);
            const timer_ms: i32 = @intCast(
                @min(full, @as(i64, std.math.maxInt(i32))),
            );
            if (timer_ms < ms) ms = timer_ms;
        }
    }
    if (ms < 0) ms = 0;

    // Stack-allocated pollfd array; 64 exceeds any realistic count.
    var poll_buf: [64]std.posix.pollfd = undefined;
    const n = loop.fd_events.items.len;
    std.debug.assert(n <= poll_buf.len);
    for (loop.fd_events.items, 0..) |ev, i| {
        poll_buf[i] = .{
            .fd = ev.fd,
            .events = ev.mask,
            .revents = 0,
        };
    }
    _ = std.posix.poll(poll_buf[0..n], ms) catch |err| {
        log.slog(
            log.LogImportance.err,
            @src(),
            "poll failed: {s}",
            .{@errorName(err)},
        );
        std.process.exit(1);
    };

    // Dispatch ready fd callbacks.
    for (loop.fd_events.items, 0..) |ev, i| {
        const pfd = poll_buf[i];
        const events: i16 =
            pfd.events | (std.posix.POLL.HUP | std.posix.POLL.ERR);
        if (pfd.revents & events != 0)
            ev.callback(pfd.fd, pfd.revents, ev.data);
    }

    // Dispatch and remove expired timers.
    if (loop.timers.items.len > 0) {
        const now = std.posix.clock_gettime(.MONOTONIC) catch
            std.posix.timespec{ .sec = 0, .nsec = 0 };
        var i: usize = 0;
        while (i < loop.timers.items.len) {
            const timer = loop.timers.items[i];
            if (timer.removed) {
                _ = loop.timers.orderedRemove(i);
                alloc().destroy(timer);
                continue;
            }
            const expired =
                timer.expiry.sec < now.sec or
                (timer.expiry.sec == now.sec and
                    timer.expiry.nsec < now.nsec);
            if (expired) {
                _ = loop.timers.orderedRemove(i);
                timer.callback(timer.data);
                alloc().destroy(timer);
                continue;
            }
            i += 1;
        }
    }
}

/// Registers an fd with the given event mask and callback.
pub fn loopAddFd(
    loop: *types.Loop,
    fd: i32,
    mask: i16,
    callback: types.FdCallback,
    data: ?*anyopaque,
) void {
    loop.fd_events.append(alloc(), .{
        .callback = callback,
        .data = data,
        .fd = fd,
        .mask = mask,
    }) catch {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Unable to allocate memory for event",
            .{},
        );
    };
}

/// Adds a one-shot timer firing after ms milliseconds.
/// Returns null on allocation failure.
pub fn loopAddTimer(
    loop: *types.Loop,
    ms: i32,
    callback: types.TimerCallback,
    data: ?*anyopaque,
) ?*types.LoopTimer {
    const timer = alloc().create(types.LoopTimer) catch {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Unable to allocate memory for timer",
            .{},
        );
        return null;
    };
    var expiry = std.posix.clock_gettime(.MONOTONIC) catch
        std.posix.timespec{ .sec = 0, .nsec = 0 };
    expiry.sec += @intCast(@divTrunc(ms, 1000));
    var nsec: isize = @as(isize, @rem(ms, 1000)) * 1_000_000;
    if (expiry.nsec + nsec >= 1_000_000_000) {
        expiry.sec += 1;
        nsec -= 1_000_000_000;
    }
    expiry.nsec += nsec;
    timer.* = .{
        .callback = callback,
        .data = data,
        .expiry = expiry,
        .removed = false,
    };
    loop.timers.append(alloc(), timer) catch {
        alloc().destroy(timer);
        log.slog(
            log.LogImportance.err,
            @src(),
            "Unable to allocate memory for timer",
            .{},
        );
        return null;
    };
    return timer;
}

/// Removes an fd from the loop. Returns true if found.
pub fn loopRemoveFd(loop: *types.Loop, fd: i32) bool {
    for (loop.fd_events.items, 0..) |ev, i| {
        if (ev.fd == fd) {
            _ = loop.fd_events.orderedRemove(i);
            return true;
        }
    }
    return false;
}

/// Marks a timer for deferred removal on next poll cycle.
pub fn loopRemoveTimer(
    loop: *types.Loop,
    remove: *types.LoopTimer,
) bool {
    for (loop.timers.items) |timer| {
        if (timer == remove) {
            timer.removed = true;
            return true;
        }
    }
    return false;
}
