//! loop.zig – Zig port of loop.c.
//! A simple poll(2)-based event loop for Wayland clients.

const std = @import("std");
const types = @import("types");

// All wayland/poll/time/errno types come from types.c.
// Only string.h is needed locally for strerror.
const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cInclude("string.h");
});

const wl = types.c;

// Log verbosity shorthands.
const log_err: c_int = @intFromEnum(types.LogImportance.err);

// Log functions via C ABI (defined in log.zig).
extern fn _swaylock_log(verbosity: c_int, fmt: [*c]const u8, ...) void;
extern fn _swaylock_strip_path(filepath: [*c]const u8) [*c]const u8;

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

/// Logs a formatted message via swaylock's log system with source
/// location prepended.
fn slog(
    verbosity: c_int,
    src: std.builtin.SourceLocation,
    comptime fmt: []const u8,
    args: anytype,
) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    _swaylock_log(
        verbosity,
        "[%s:%d] %s",
        _swaylock_strip_path(src.file.ptr),
        @as(c_int, @intCast(src.line)),
        msg.ptr,
    );
}

/// Creates a new event loop.
pub export fn loop_create() callconv(.c) ?*types.Loop {
    const loop = alloc.create(types.Loop) catch {
        slog(log_err, @src(), "Unable to allocate memory for loop", .{});
        return null;
    };
    const fds = alloc.alloc(wl.struct_pollfd, 10) catch {
        alloc.destroy(loop);
        slog(log_err, @src(), "Unable to allocate memory for loop", .{});
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
pub export fn loop_destroy(loop: *types.Loop) callconv(.c) void {
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
pub export fn loop_poll(loop: *types.Loop) callconv(.c) void {
    var ms: c_int = std.math.maxInt(c_int);
    if (wl.wl_list_empty(&loop.timers) == 0) {
        var now: wl.struct_timespec = undefined;
        _ = wl.clock_gettime(wl.CLOCK_MONOTONIC, &now);
        var tnode = wlPtr(loop.timers.next);
        while (tnode != &loop.timers) {
            const timer = wlEntry(types.LoopTimer, "link", tnode);
            const sec_diff: i64 =
                @as(i64, timer.expiry.tv_sec) - @as(i64, now.tv_sec);
            const nsec_diff: i64 =
                @as(i64, timer.expiry.tv_nsec) - @as(i64, now.tv_nsec);
            const full: i64 =
                sec_diff * 1000 + @divTrunc(nsec_diff, 1_000_000);
            const timer_ms: c_int = @intCast(
                @min(full, @as(i64, std.math.maxInt(c_int))),
            );
            if (timer_ms < ms) ms = timer_ms;
            tnode = wlPtr(tnode.next);
        }
    }
    if (ms < 0) ms = 0;

    const ret = wl.poll(
        @ptrCast(loop.fds),
        @as(wl.nfds_t, @intCast(loop.fd_length)),
        ms,
    );
    if (ret < 0 and wl.__errno_location().* != wl.EINTR) {
        slog(
            log_err,
            @src(),
            "poll failed: {s}",
            .{c.strerror(wl.__errno_location().*)},
        );
        std.c.exit(1);
    }

    // Dispatch fd events.
    var fd_index: usize = 0;
    var fnode = wlPtr(loop.fd_events.next);
    while (fnode != &loop.fd_events) {
        const event = wlEntry(types.FdEvent, "link", fnode);
        const pfd = loop.fds[fd_index];
        const events: c_short =
            pfd.events | @as(c_short, wl.POLLHUP | wl.POLLERR);
        if (pfd.revents & events != 0)
            event.callback(pfd.fd, pfd.revents, event.data);
        fd_index += 1;
        fnode = wlPtr(fnode.next);
    }

    // Dispatch expired timers.
    if (wl.wl_list_empty(&loop.timers) == 0) {
        var now: wl.struct_timespec = undefined;
        _ = wl.clock_gettime(wl.CLOCK_MONOTONIC, &now);
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
                timer.expiry.tv_sec < now.tv_sec or
                (timer.expiry.tv_sec == now.tv_sec and
                    timer.expiry.tv_nsec < now.tv_nsec);
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
pub export fn loop_add_fd(
    loop: *types.Loop,
    fd: c_int,
    mask: c_short,
    callback: types.FdCallback,
    data: ?*anyopaque,
) callconv(.c) void {
    const event = alloc.create(types.FdEvent) catch {
        slog(log_err, @src(), "Unable to allocate memory for event", .{});
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
            slog(log_err, @src(), "Unable to reallocate fd array", .{});
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
pub export fn loop_add_timer(
    loop: *types.Loop,
    ms: c_int,
    callback: types.TimerCallback,
    data: ?*anyopaque,
) callconv(.c) ?*types.LoopTimer {
    const timer = alloc.create(types.LoopTimer) catch {
        slog(log_err, @src(), "Unable to allocate memory for timer", .{});
        return null;
    };
    timer.* = .{
        .callback = callback,
        .data = data,
        .expiry = undefined,
        .removed = false,
        .link = undefined,
    };
    _ = wl.clock_gettime(wl.CLOCK_MONOTONIC, &timer.expiry);
    timer.expiry.tv_sec += @intCast(@divTrunc(ms, 1000));
    var nsec: i64 = @as(i64, @rem(ms, 1000)) * 1_000_000;
    if (@as(i64, timer.expiry.tv_nsec) + nsec >= 1_000_000_000) {
        timer.expiry.tv_sec += 1;
        nsec -= 1_000_000_000;
    }
    timer.expiry.tv_nsec += @intCast(nsec);
    wl.wl_list_insert(&loop.timers, &timer.link);
    return timer;
}

/// Removes a file descriptor from the event loop.
/// Returns true if the fd was found and removed.
pub export fn loop_remove_fd(
    loop: *types.Loop,
    fd: c_int,
) callconv(.c) bool {
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
                wl.struct_pollfd,
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
/// next loop_poll call.
pub export fn loop_remove_timer(
    loop: *types.Loop,
    remove: *types.LoopTimer,
) callconv(.c) bool {
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
