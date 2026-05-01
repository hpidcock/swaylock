//! loop.zig – poll(2)-based event loop for Wayland clients.

const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

const wl = types.c;

const alloc = std.heap.c_allocator;

/// Converts a C pointer to wl_list to a non-null Zig pointer.
inline fn wlPtr(p: [*c]wl.wl_list) *wl.wl_list {
    return @ptrCast(@alignCast(p));
}

/// Returns a pointer to the struct enclosing the given wl_list member.
inline fn wlEntry(
    comptime T: type,
    comptime field: []const u8,
    node: *wl.wl_list,
) *T {
    return @ptrFromInt(@intFromPtr(node) - @offsetOf(T, field));
}

/// Creates a new event loop.
pub fn loopCreate() ?*types.Loop {
    const loop = alloc.create(types.Loop) catch {
        log.slog(log.LogImportance.err, @src(), "Unable to allocate memory for loop", .{});
        return null;
    };
    const fds = alloc.alloc(std.posix.pollfd, 10) catch {
        alloc.destroy(loop);
        log.slog(log.LogImportance.err, @src(), "Unable to allocate memory for loop", .{});
        return null;
    };
    loop.* = .{
        .fds = fds.ptr,
        .fd_length = 0,
        .fd_capacity = 10,
        .fd_events = undefined,
        .timers = undefined,
    };
    wl.wl_list_init(&loop.fd_events);
    wl.wl_list_init(&loop.timers);
    return loop;
}

/// Destroys the event loop, freeing all resources.
pub fn loopDestroy(loop: *types.Loop) void {
    var node = wlPtr(loop.fd_events.next);
    while (node != &loop.fd_events) {
        const next = wlPtr(node.next);
        const event = wlEntry(types.FdEvent, "link", node);
        wl.wl_list_remove(&event.link);
        alloc.destroy(event);
        node = next;
    }
    var tnode = wlPtr(loop.timers.next);
    while (tnode != &loop.timers) {
        const tnext = wlPtr(tnode.next);
        const timer = wlEntry(types.LoopTimer, "link", tnode);
        wl.wl_list_remove(&timer.link);
        alloc.destroy(timer);
        tnode = tnext;
    }
    alloc.free(loop.fds[0..@intCast(loop.fd_capacity)]);
    alloc.destroy(loop);
}

/// Polls the event loop once, dispatching ready fds and expired
/// timers. Blocks until at least one event is ready or a timer fires.
pub fn loopPoll(loop: *types.Loop) void {
    var ms: i32 = std.math.maxInt(i32);
    if (wl.wl_list_empty(&loop.timers) == 0) {
        const now = std.posix.clock_gettime(.MONOTONIC) catch
            std.posix.timespec{ .sec = 0, .nsec = 0 };
        var tnode = wlPtr(loop.timers.next);
        while (tnode != &loop.timers) {
            const timer = wlEntry(types.LoopTimer, "link", tnode);
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
            tnode = wlPtr(tnode.next);
        }
    }
    if (ms < 0) ms = 0;

    const fds = loop.fds[0..@intCast(loop.fd_length)];
    _ = std.posix.poll(fds, ms) catch |err| {
        log.slog(
            log.LogImportance.err,
            @src(),
            "poll failed: {s}",
            .{@errorName(err)},
        );
        std.process.exit(1);
    };

    // Dispatch fd events.
    var fd_index: usize = 0;
    var fnode = wlPtr(loop.fd_events.next);
    while (fnode != &loop.fd_events) {
        const event = wlEntry(types.FdEvent, "link", fnode);
        const pfd = loop.fds[fd_index];
        const events: i16 =
            pfd.events | (std.posix.POLL.HUP | std.posix.POLL.ERR);
        if (pfd.revents & events != 0)
            event.callback(pfd.fd, pfd.revents, event.data);
        fd_index += 1;
        fnode = wlPtr(fnode.next);
    }

    // Dispatch expired timers.
    if (wl.wl_list_empty(&loop.timers) == 0) {
        const now = std.posix.clock_gettime(.MONOTONIC) catch
            std.posix.timespec{ .sec = 0, .nsec = 0 };
        var tnode = wlPtr(loop.timers.next);
        while (tnode != &loop.timers) {
            const tnext = wlPtr(tnode.next);
            const timer = wlEntry(types.LoopTimer, "link", tnode);
            if (timer.removed) {
                wl.wl_list_remove(&timer.link);
                alloc.destroy(timer);
                tnode = tnext;
                continue;
            }
            const expired =
                timer.expiry.sec < now.sec or
                (timer.expiry.sec == now.sec and
                    timer.expiry.nsec < now.nsec);
            if (expired) {
                timer.callback(timer.data);
                wl.wl_list_remove(&timer.link);
                alloc.destroy(timer);
            }
            tnode = tnext;
        }
    }
}

/// Adds a file descriptor to the event loop.
pub fn loopAddFd(
    loop: *types.Loop,
    fd: i32,
    mask: i16,
    callback: types.FdCallback,
    data: ?*anyopaque,
) void {
    const event = alloc.create(types.FdEvent) catch {
        log.slog(log.LogImportance.err, @src(), "Unable to allocate memory for event", .{});
        return;
    };
    event.* = .{
        .callback = callback,
        .data = data,
        .link = undefined,
    };
    wl.wl_list_insert(loop.fd_events.prev, &event.link);

    if (loop.fd_length == loop.fd_capacity) {
        const old_cap: usize = @intCast(loop.fd_capacity);
        const new_cap: usize = old_cap + 10;
        const new_fds = alloc.realloc(
            loop.fds[0..old_cap],
            new_cap,
        ) catch {
            log.slog(log.LogImportance.err, @src(), "Unable to reallocate fd array", .{});
            return;
        };
        loop.fds = new_fds.ptr;
        loop.fd_capacity = @intCast(new_cap);
    }
    loop.fds[@intCast(loop.fd_length)] = .{
        .fd = fd,
        .events = mask,
        .revents = 0,
    };
    loop.fd_length += 1;
}

/// Adds a one-shot timer that fires after ms milliseconds.
/// Returns null on allocation failure.
pub fn loopAddTimer(
    loop: *types.Loop,
    ms: i32,
    callback: types.TimerCallback,
    data: ?*anyopaque,
) ?*types.LoopTimer {
    const timer = alloc.create(types.LoopTimer) catch {
        log.slog(log.LogImportance.err, @src(), "Unable to allocate memory for timer", .{});
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
        .link = undefined,
    };
    wl.wl_list_insert(&loop.timers, &timer.link);
    return timer;
}

/// Removes a file descriptor from the event loop.
/// Returns true if the fd was found and removed.
pub fn loopRemoveFd(
    loop: *types.Loop,
    fd: i32,
) bool {
    var fd_index: usize = 0;
    var node = wlPtr(loop.fd_events.next);
    while (node != &loop.fd_events) {
        const next = wlPtr(node.next);
        const event = wlEntry(types.FdEvent, "link", node);
        if (loop.fds[fd_index].fd == fd) {
            wl.wl_list_remove(&event.link);
            alloc.destroy(event);
            loop.fd_length -= 1;
            const len: usize = @intCast(loop.fd_length);
            std.mem.copyForwards(
                std.posix.pollfd,
                loop.fds[fd_index..len],
                loop.fds[fd_index + 1 .. len + 1],
            );
            return true;
        }
        fd_index += 1;
        node = next;
    }
    return false;
}

/// Marks a timer for deferred removal. The memory is freed on the
/// next loopPoll call.
pub fn loopRemoveTimer(
    loop: *types.Loop,
    remove: *types.LoopTimer,
) bool {
    var tnode = wlPtr(loop.timers.next);
    while (tnode != &loop.timers) {
        const timer = wlEntry(types.LoopTimer, "link", tnode);
        if (timer == remove) {
            timer.removed = true;
            return true;
        }
        tnode = wlPtr(tnode.next);
    }
    return false;
}
