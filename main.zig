//! main.zig – Zig port of main.c.

const std = @import("std");
const opts = @import("main_options");
const clap = @import("clap");

const params = @import("params.zig");
const state = @import("state.zig");

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    if (opts.have_debug_overlay) @cDefine("HAVE_DEBUG_OVERLAY", "1");
    @cInclude("errno.h");
    @cInclude("fcntl.h");

    @cInclude("signal.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
    @cInclude("wordexp.h");
});

const types = @import("types.zig");
const wl = types.c;

const log = @import("log.zig");
const background_image = @import("background-image.zig");

const loop = @import("loop.zig");
const comm = @import("comm.zig");
const pool_buffer = @import("pool-buffer.zig");
const render = @import("render.zig");
const seat = @import("seat.zig");
const password_mod = @import("password.zig");
const password_buffer = @import("password_buffer.zig");

const pam_mod = @import("pam.zig");

var sigusr_fds: [2]i32 = .{ -1, -1 };
var g: types.SwaylockState = std.mem.zeroes(types.SwaylockState);

/// Duplicate a Zig slice into a C malloc-owned null-terminated string.
fn dupStr(s: []const u8) ?[*:0]u8 {
    const result = std.heap.c_allocator.dupeZ(u8, s) catch
        return null;
    return result.ptr;
}

fn lenientStrcmp(a: ?[*:0]const u8, b: ?[*:0]const u8) i32 {
    if (a == b) return 0;
    if (a == null) return -1;
    if (b == null) return 1;
    return c.strcmp(@ptrCast(a), @ptrCast(b));
}

fn daemonize() void {
    var fds: [2]i32 = undefined;
    if (c.pipe(&fds) != 0) {
        log.slog(log.LogImportance.err, @src(), "Failed to pipe", .{});
        c.exit(1);
    }
    if (c.fork() == 0) {
        _ = c.setsid();
        _ = c.close(fds[0]);
        const devnull = c.open("/dev/null", c.O_RDWR);
        _ = c.dup2(c.STDOUT_FILENO, devnull);
        _ = c.dup2(c.STDERR_FILENO, devnull);
        _ = c.close(devnull);
        var success: u8 = 0;
        if (c.chdir("/") != 0) {
            _ = c.write(fds[1], &success, 1);
            c.exit(1);
        }
        success = 1;
        if (c.write(fds[1], &success, 1) != 1) c.exit(1);
        _ = c.close(fds[1]);
    } else {
        _ = c.close(fds[1]);
        var success: u8 = undefined;
        if (c.read(fds[0], &success, 1) != 1 or success == 0) {
            log.slog(log.LogImportance.err, @src(), "Failed to daemonize", .{});
            c.exit(1);
        }
        _ = c.close(fds[0]);
        c.exit(0);
    }
}

fn destroySurface(surface: *types.SwaylockSurface) void {
    if (surface.frame != null)
        wl.wl_callback_destroy(surface.frame);
    if (surface.ext_session_lock_surface_v1 != null) {
        wl.ext_session_lock_surface_v1_destroy(
            surface.ext_session_lock_surface_v1,
        );
    }
    if (surface.subsurface != null)
        wl.wl_subsurface_destroy(surface.subsurface);
    if (surface.child != null)
        wl.wl_surface_destroy(surface.child);
    if (surface.surface != null)
        wl.wl_surface_destroy(surface.surface);
    pool_buffer.destroyBuffer(&surface.indicator_buffers[0]);
    pool_buffer.destroyBuffer(&surface.indicator_buffers[1]);
    if (comptime opts.have_debug_overlay) {
        if (surface.overlay_sub != null)
            wl.wl_subsurface_destroy(surface.overlay_sub);
        if (surface.overlay != null)
            wl.wl_surface_destroy(surface.overlay);
        pool_buffer.destroyBuffer(&surface.overlay_buffers[0]);
        pool_buffer.destroyBuffer(&surface.overlay_buffers[1]);
    }
    wl.wl_output_release(surface.output);
    std.heap.c_allocator.destroy(surface);
}

fn surfaceIsOpaque(surface: *types.SwaylockSurface) bool {
    if (surface.image != null) {
        return types.c.cairo_surface_get_content(surface.image) ==
            types.c.CAIRO_CONTENT_COLOR;
    }
    return (surface.g.?.args.colors.background & 0xff) == 0xff;
}

fn createSurface(surface: *types.SwaylockSurface) void {
    const st = surface.g.?;
    surface.image = selectImage(st, surface);
    surface.surface =
        wl.wl_compositor_create_surface(st.compositor);
    std.debug.assert(surface.surface != null);
    surface.child =
        wl.wl_compositor_create_surface(st.compositor);
    std.debug.assert(surface.child != null);
    surface.subsurface = wl.wl_subcompositor_get_subsurface(
        st.subcompositor,
        surface.child,
        surface.surface,
    );
    std.debug.assert(surface.subsurface != null);
    wl.wl_subsurface_set_sync(surface.subsurface);
    if (comptime opts.have_debug_overlay) {
        surface.overlay =
            wl.wl_compositor_create_surface(st.compositor);
        std.debug.assert(surface.overlay != null);
        surface.overlay_sub = wl.wl_subcompositor_get_subsurface(
            st.subcompositor,
            surface.overlay,
            surface.surface,
        );
        std.debug.assert(surface.overlay_sub != null);
        wl.wl_subsurface_set_desync(surface.overlay_sub);
    }
    surface.ext_session_lock_surface_v1 =
        wl.ext_session_lock_v1_get_lock_surface(
            st.ext_session_lock_v1,
            surface.surface,
            surface.output,
        );
    _ = wl.ext_session_lock_surface_v1_add_listener(
        surface.ext_session_lock_surface_v1,
        &ext_session_lock_surface_v1_listener,
        surface,
    );
    if (surfaceIsOpaque(surface) and
        st.args.mode != types.BackgroundMode.center and
        st.args.mode != types.BackgroundMode.fit)
    {
        const region =
            wl.wl_compositor_create_region(st.compositor);
        wl.wl_region_add(
            region,
            0,
            0,
            2147483647,
            2147483647,
        );
        wl.wl_surface_set_opaque_region(surface.surface, region);
        wl.wl_region_destroy(region);
    }
    surface.created = true;
}

fn extSessionLockSurfaceV1HandleConfigure(
    data: ?*anyopaque,
    lock_surface: ?*anyopaque,
    serial: u32,
    width: u32,
    height: u32,
) callconv(std.builtin.CallingConvention.c) void {
    const surface: *types.SwaylockSurface =
        @ptrCast(@alignCast(data.?));
    surface.width = width;
    surface.height = height;
    wl.ext_session_lock_surface_v1_ack_configure(
        @ptrCast(lock_surface),
        serial,
    );
    surface.dirty = true;
    render.render(surface);
}

const ext_session_lock_surface_v1_listener: wl.struct_ext_session_lock_surface_v1_listener = .{
    .configure = @ptrCast(&extSessionLockSurfaceV1HandleConfigure),
};

fn handleWlOutputGeometry(
    data: ?*anyopaque,
    output: ?*wl.wl_output,
    x: i32,
    y: i32,
    width_mm: i32,
    height_mm: i32,
    subpixel: i32,
    make: [*c]const u8,
    model: [*c]const u8,
    transform: i32,
) callconv(std.builtin.CallingConvention.c) void {
    _ = output;
    _ = x;
    _ = y;
    _ = width_mm;
    _ = height_mm;
    _ = make;
    _ = model;
    _ = transform;
    const surface: *types.SwaylockSurface =
        @ptrCast(@alignCast(data.?));
    surface.subpixel = @intCast(subpixel);
    if (surface.g.?.run_display) {
        surface.dirty = true;
        render.render(surface);
    }
}

fn handleWlOutputMode(
    data: ?*anyopaque,
    output: ?*wl.wl_output,
    flags: u32,
    width: i32,
    height: i32,
    refresh: i32,
) callconv(std.builtin.CallingConvention.c) void {
    _ = data;
    _ = output;
    _ = flags;
    _ = width;
    _ = height;
    _ = refresh;
}

fn handleWlOutputDone(
    data: ?*anyopaque,
    output: ?*wl.wl_output,
) callconv(std.builtin.CallingConvention.c) void {
    _ = output;
    const surface: *types.SwaylockSurface =
        @ptrCast(@alignCast(data.?));
    if (!surface.created and surface.g.?.run_display)
        createSurface(surface);
}

fn handleWlOutputScale(
    data: ?*anyopaque,
    output: ?*wl.wl_output,
    factor: i32,
) callconv(std.builtin.CallingConvention.c) void {
    _ = output;
    const surface: *types.SwaylockSurface =
        @ptrCast(@alignCast(data.?));
    surface.scale = factor;
    if (surface.g.?.run_display) {
        surface.dirty = true;
        render.render(surface);
    }
}

fn handleWlOutputName(
    data: ?*anyopaque,
    output: ?*wl.wl_output,
    name: [*c]const u8,
) callconv(std.builtin.CallingConvention.c) void {
    _ = output;
    const surface: *types.SwaylockSurface =
        @ptrCast(@alignCast(data.?));
    surface.output_name = @ptrCast(c.strdup(name));
}

fn handleWlOutputDescription(
    data: ?*anyopaque,
    output: ?*wl.wl_output,
    description: [*c]const u8,
) callconv(std.builtin.CallingConvention.c) void {
    _ = data;
    _ = output;
    _ = description;
}

var wl_output_listener: wl.wl_output_listener = .{
    .geometry = handleWlOutputGeometry,
    .mode = handleWlOutputMode,
    .done = handleWlOutputDone,
    .scale = handleWlOutputScale,
    .name = handleWlOutputName,
    .description = handleWlOutputDescription,
};

fn extSessionLockV1HandleLocked(
    data: ?*anyopaque,
    lock: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = lock;
    const st: *types.SwaylockState =
        @ptrCast(@alignCast(data.?));
    st.locked = true;
}

fn extSessionLockV1HandleFinished(
    data: ?*anyopaque,
    lock: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = lock;
    const st: *types.SwaylockState =
        @ptrCast(@alignCast(data.?));
    if (st.args.steal_unlock) {
        st.lock_failed = true;
        return;
    }
    log.slog(
        log.LogImportance.err,
        @src(),
        "Failed to lock session -- is another lockscreen running?",
        .{},
    );
    c.exit(2);
}

const ext_session_lock_v1_listener: wl.struct_ext_session_lock_v1_listener = .{
    .locked = @ptrCast(&extSessionLockV1HandleLocked),
    .finished = @ptrCast(&extSessionLockV1HandleFinished),
};

fn handleGlobal(
    data: ?*anyopaque,
    registry: ?*wl.wl_registry,
    name: u32,
    interface: [*c]const u8,
    version: u32,
) callconv(std.builtin.CallingConvention.c) void {
    _ = version;
    const st: *types.SwaylockState =
        @ptrCast(@alignCast(data.?));
    if (c.strcmp(interface, wl.wl_compositor_interface.name) == 0) {
        st.compositor = @ptrCast(wl.wl_registry_bind(
            registry,
            name,
            &wl.wl_compositor_interface,
            4,
        ));
    } else if (c.strcmp(
        interface,
        wl.wl_subcompositor_interface.name,
    ) == 0) {
        st.subcompositor = @ptrCast(wl.wl_registry_bind(
            registry,
            name,
            &wl.wl_subcompositor_interface,
            1,
        ));
    } else if (c.strcmp(interface, wl.wl_shm_interface.name) == 0) {
        st.shm = @ptrCast(wl.wl_registry_bind(
            registry,
            name,
            &wl.wl_shm_interface,
            1,
        ));
    } else if (c.strcmp(interface, wl.wl_seat_interface.name) == 0) {
        const se: ?*wl.wl_seat = @ptrCast(wl.wl_registry_bind(
            registry,
            name,
            &wl.wl_seat_interface,
            4,
        ));
        const swaylock_seat = std.heap.c_allocator.create(
            types.SwaylockSeat,
        ) catch @panic("OOM");
        swaylock_seat.* = std.mem.zeroes(types.SwaylockSeat);
        swaylock_seat.g = st;
        _ = wl.wl_seat_add_listener(
            se,
            &seat.seatListener,
            swaylock_seat,
        );
    } else if (c.strcmp(
        interface,
        wl.wl_output_interface.name,
    ) == 0) {
        const surface = std.heap.c_allocator.create(
            types.SwaylockSurface,
        ) catch @panic("OOM");
        surface.* = std.mem.zeroes(types.SwaylockSurface);
        surface.g = st;
        surface.output = @ptrCast(wl.wl_registry_bind(
            registry,
            name,
            &wl.wl_output_interface,
            4,
        ));
        surface.output_global_name = name;
        _ = wl.wl_output_add_listener(
            surface.output,
            &wl_output_listener,
            surface,
        );
        st.surfaces.append(
            std.heap.c_allocator,
            surface,
        ) catch @panic("OOM");
    } else if (c.strcmp(
        interface,
        wl.ext_session_lock_manager_v1_interface.name,
    ) == 0) {
        st.ext_session_lock_manager_v1 =
            @ptrCast(wl.wl_registry_bind(
                registry,
                name,
                &wl.ext_session_lock_manager_v1_interface,
                1,
            ));
    }
}

fn handleGlobalRemove(
    data: ?*anyopaque,
    registry: ?*wl.wl_registry,
    name: u32,
) callconv(std.builtin.CallingConvention.c) void {
    _ = registry;
    const st: *types.SwaylockState =
        @ptrCast(@alignCast(data.?));
    for (st.surfaces.items, 0..) |surface, i| {
        if (surface.output_global_name == name) {
            _ = st.surfaces.orderedRemove(i);
            destroySurface(surface);
            break;
        }
    }
}

const registry_listener: wl.wl_registry_listener = .{
    .global = handleGlobal,
    .global_remove = handleGlobalRemove,
};

fn doSigusr(
    sig: c_int,
) callconv(std.builtin.CallingConvention.c) void {
    _ = sig;
    _ = c.write(sigusr_fds[1], "1", 1);
}

fn debugUnlockOnExit() void {
    if (g.ext_session_lock_v1 == null) {
        return;
    }
    wl.ext_session_lock_v1_unlock_and_destroy(
        g.ext_session_lock_v1,
    );
    g.ext_session_lock_v1 = null;
    if (g.display != null)
        _ = wl.wl_display_flush(g.display);
}

fn debugUnlockOnCrash(
    sig: c_int,
) callconv(std.builtin.CallingConvention.c) void {
    debugUnlockOnExit();
    _ = c.raise(sig);
}

fn selectImage(
    st: *types.SwaylockState,
    surface: *types.SwaylockSurface,
) ?*types.c.cairo_surface_t {
    var default_image: ?*types.c.cairo_surface_t = null;
    for (st.images.items) |image| {
        if (lenientStrcmp(
            image.output_name,
            surface.output_name,
        ) == 0) {
            return image.cairo_surface;
        } else if (image.output_name == null) {
            default_image = image.cairo_surface;
        }
    }
    return default_image;
}

fn setDefaultColors(colors: *types.SwaylockColors) void {
    colors.background = 0xA3A3A3FF;
    colors.bs_highlight = 0xDB3300FF;
    colors.key_highlight = 0x33DB00FF;
    colors.caps_lock_bs_highlight = 0xDB3300FF;
    colors.caps_lock_key_highlight = 0x33DB00FF;
    colors.separator = 0x000000FF;
    colors.layout_background = 0x000000C0;
    colors.layout_border = 0x00000000;
    colors.layout_text = 0xFFFFFFFF;
    colors.inside = types.SwaylockColorSet{
        .input = 0x000000C0,
        .cleared = 0xE5A445C0,
        .caps_lock = 0x000000C0,
        .verifying = 0x0072FFC0,
        .wrong = 0xFA0000C0,
    };
    colors.line = types.SwaylockColorSet{
        .input = 0x000000FF,
        .cleared = 0x000000FF,
        .caps_lock = 0x000000FF,
        .verifying = 0x000000FF,
        .wrong = 0x000000FF,
    };
    colors.ring = types.SwaylockColorSet{
        .input = 0x337D00FF,
        .cleared = 0xE5A445FF,
        .caps_lock = 0xE5A445FF,
        .verifying = 0x3300FFFF,
        .wrong = 0x7D3300FF,
    };
    colors.text = types.SwaylockColorSet{
        .input = 0xE5A445FF,
        .cleared = 0x000000FF,
        .caps_lock = 0xE5A445FF,
        .verifying = 0x000000FF,
        .wrong = 0x000000FF,
    };
}

fn fileExists(path: []const u8) bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

// getConfigPath searches the standard locations for a swaylock config
// file, returning an allocated slice on success. The caller must free
// the returned slice using the same allocator.
fn getConfigPath(allocator: std.mem.Allocator) ?[]u8 {
    const home = std.posix.getenv("HOME") orelse return null;
    const xdg = std.posix.getenv("XDG_CONFIG_HOME");

    const path1 = std.fs.path.join(
        allocator,
        &.{ home, ".swaylock", "config" },
    ) catch return null;
    if (fileExists(path1)) return path1;
    allocator.free(path1);

    // sysconfdir path is comptime-known from build options.
    const path3 = opts.sysconfdir ++ "/swaylock/config";

    const path2 = if (xdg != null and xdg.?.len > 0)
        std.fs.path.join(
            allocator,
            &.{ xdg.?, "swaylock", "config" },
        ) catch return null
    else
        std.fs.path.join(
            allocator,
            &.{ home, ".config", "swaylock", "config" },
        ) catch return null;
    if (fileExists(path2)) return path2;
    allocator.free(path2);

    if (fileExists(path3))
        return allocator.dupe(u8, path3) catch null;
    return null;
}

fn loadConfig(
    path: []const u8,
    st: *types.SwaylockState,
    line_mode: *types.LineMode,
) c_int {
    const file = std.fs.openFileAbsolute(path, .{}) catch {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Failed to read config. Running without it.",
            .{},
        );
        return 0;
    };
    defer file.close();
    const allocator = std.heap.c_allocator;
    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();
    var line_buf: [4096]u8 = undefined;
    var line_number: usize = 0;
    var result: c_int = 0;
    while (reader.readUntilDelimiterOrEof(
        &line_buf,
        '\n',
    ) catch null) |line| {
        line_number += 1;
        const trimmed = std.mem.trimRight(u8, line, "\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        log.slog(
            log.LogImportance.debug,
            @src(),
            "Config Line #{d}: {s}",
            .{ line_number, trimmed },
        );
        const flag = std.fmt.allocPrintZ(
            allocator,
            "--{s}",
            .{trimmed},
        ) catch {
            log.slog(log.LogImportance.err, @src(), "Failed to allocate memory", .{});
            return 0;
        };
        defer allocator.free(flag);
        var fake_argv: [2][*c]u8 = .{
            @constCast("swaylock"),
            @ptrCast(flag.ptr),
        };
        result = params.parseOptions(2, &fake_argv, st, line_mode, null);
        if (result != 0) break;
    }
    return 0;
}

fn authStateStr(s: types.AuthState) []const u8 {
    if (s == .idle) return "idle";
    if (s == .validating) return "validating";
    if (s == .invalid) return "invalid";
    return "unknown";
}

fn authdStageStr(s: types.AuthdStage) []const u8 {
    if (s == .none) return "none";
    if (s == .broker) return "broker";
    if (s == .auth_mode) return "auth_mode";
    if (s == .challenge) return "challenge";
    return "unknown";
}

fn displayIn(
    fd: i32,
    mask: i16,
    data: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = fd;
    _ = mask;
    _ = data;
    if (wl.wl_display_dispatch(g.display) == -1)
        g.run_display = false;
}

fn commIn(
    fd: i32,
    mask: i16,
    data: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = fd;
    _ = data;
    if ((mask & wl.POLLERR) != 0) {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Password checking subprocess crashed; exiting.",
            .{},
        );
        c.exit(c.EXIT_FAILURE);
    }
    if ((mask & wl.POLLIN) == 0) {
        if ((mask & wl.POLLHUP) != 0) {
            log.slog(
                log.LogImportance.err,
                @src(),
                "Password checking subprocess exited unexpectedly; exiting.",
                .{},
            );
            c.exit(c.EXIT_FAILURE);
        }
        return;
    }
    var payload: ?[*]u8 = null;
    var len: usize = 0;
    const msg_type = comm.commMainRead(&payload, &len);
    defer c.free(@ptrCast(payload));
    if (msg_type <= 0) {
        if (msg_type == 0) c.exit(c.EXIT_FAILURE);
        log.slog(
            log.LogImportance.err,
            @src(),
            "comm_main_read failed; exiting.",
            .{},
        );
        c.exit(c.EXIT_FAILURE);
    }
    log.slog(
        log.LogImportance.debug,
        @src(),
        "comm_in: msg=0x{x:0>2} len={d} auth={s} stage={s}",
        .{
            msg_type,
            len,
            authStateStr(g.auth_state),
            authdStageStr(g.authd_stage),
        },
    );
    const payload_slice: []const u8 =
        if (payload) |p| p[0..len] else &.{};
    switch (msg_type) {
        types.CommMsg.auth_result => {
            if (len >= 1 and payload != null and payload.?[0] == 0x01) {
                log.slog(
                    log.LogImportance.debug,
                    @src(),
                    "comm_in: AUTH_RESULT granted -> unlocking",
                    .{},
                );
                g.run_display = false;
            } else {
                log.slog(
                    log.LogImportance.debug,
                    @src(),
                    "comm_in: AUTH_RESULT denied auth={s} -> invalid",
                    .{authStateStr(g.auth_state)},
                );
                g.auth_state = .invalid;
                password_mod.scheduleAuthIdle(&g);
                g.failed_attempts += 1;
                state.damageState(&g);
            }
        },
        types.CommMsg.brokers => {
            // Parse JSON array [{id, name}, ...]
            pam_mod.authdBrokersFree(
                @ptrCast(g.authd_brokers),
                g.authd_num_brokers,
            );
            g.authd_brokers = null;
            g.authd_num_brokers = 0;
            g.authd_sel_broker = 0;
            parseBrokers(payload_slice);
            g.authd_active = true;
            g.authd_stage = .broker;
            log.slog(
                log.LogImportance.debug,
                @src(),
                "comm_in: BROKERS n={d} -> stage=broker",
                .{g.authd_num_brokers},
            );
            state.damageState(&g);
        },
        types.CommMsg.auth_modes => {
            // Parse JSON array [{id, label}, ...]
            pam_mod.authdAuthModesFree(
                @ptrCast(g.authd_auth_modes),
                g.authd_num_auth_modes,
            );
            g.authd_auth_modes = null;
            g.authd_num_auth_modes = 0;
            g.authd_sel_auth_mode = 0;
            parseAuthModes(payload_slice);
            g.authd_active = true;
            g.authd_stage = .auth_mode;
            log.slog(
                log.LogImportance.debug,
                @src(),
                "comm_in: AUTH_MODES n={d} -> stage=auth_mode",
                .{g.authd_num_auth_modes},
            );
            state.damageState(&g);
        },
        types.CommMsg.ui_layout => {
            // Parse UILayout JSON object.
            pam_mod.authdUiLayoutClear(&g.authd_layout);
            c.free(@ptrCast(g.authd_error));
            g.authd_error = null;
            parseUiLayout(payload_slice);
            log.slog(
                log.LogImportance.debug,
                @src(),
                "comm_in: UI_LAYOUT type={s} label={s} entry={s} " ++
                    "wait={d} auth={s} -> idle/challenge",
                .{
                    if (g.authd_layout.type) |t| @as([*:0]const u8, t) else "(null)",
                    if (g.authd_layout.label) |l| @as([*:0]const u8, l) else "(null)",
                    if (g.authd_layout.entry) |e| @as([*:0]const u8, e) else "(null)",
                    @intFromBool(g.authd_layout.wait),
                    authStateStr(g.auth_state),
                },
            );
            g.auth_state = .idle;
            g.authd_stage = .challenge;
            state.damageState(&g);
        },
        types.CommMsg.stage => {
            if (len >= 1) {
                const new_stage: types.AuthdStage =
                    @enumFromInt(@as(c_int, payload.?[0]));
                if (g.auth_state == .validating) {
                    log.slog(
                        log.LogImportance.debug,
                        @src(),
                        "comm_in: STAGE {s} -> {s} while validating:" ++
                            " auth.Retry assumed, auth=validating -> invalid",
                        .{
                            authdStageStr(g.authd_stage),
                            authdStageStr(new_stage),
                        },
                    );
                    g.auth_state = .invalid;
                    password_mod.scheduleAuthIdle(&g);
                    g.failed_attempts += 1;
                } else {
                    log.slog(
                        log.LogImportance.debug,
                        @src(),
                        "comm_in: STAGE {s} -> {s} auth={s}",
                        .{
                            authdStageStr(g.authd_stage),
                            authdStageStr(new_stage),
                            authStateStr(g.auth_state),
                        },
                    );
                }
                g.authd_stage = new_stage;
                state.damageState(&g);
            }
        },
        types.CommMsg.auth_event => {
            // Intermediate result — show as error/info.
            c.free(@ptrCast(g.authd_error));
            g.authd_error = null;
            parseAuthEvent(payload_slice);
            log.slog(
                log.LogImportance.debug,
                @src(),
                "comm_in: AUTH_EVENT msg={s} auth={s} -> idle",
                .{
                    if (g.authd_error) |e| @as([*:0]const u8, e) else "(null)",
                    authStateStr(g.auth_state),
                },
            );
            g.auth_state = .idle;
            state.damageState(&g);
        },
        else => {},
    }
}

fn parseBrokers(json: []const u8) void {
    const BrokerItem = struct {
        id: ?[]const u8 = null,
        name: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        []BrokerItem,
        std.heap.c_allocator,
        json,
        .{ .ignore_unknown_fields = true },
    ) catch return;
    defer parsed.deinit();
    const n = @min(parsed.value.len, 256);
    const raw = c.calloc(n, @sizeOf(types.AuthdBroker));
    if (raw == null) return;
    const brokers: [*]types.AuthdBroker = @ptrCast(@alignCast(raw));
    g.authd_brokers = brokers;
    g.authd_num_brokers = @intCast(n);
    for (0..n) |i| {
        const item = parsed.value[i];
        brokers[i].id = if (item.id) |s| dupStr(s) else null;
        brokers[i].name = if (item.name) |s| dupStr(s) else null;
    }
}

fn parseAuthModes(json: []const u8) void {
    const ModeItem = struct {
        id: ?[]const u8 = null,
        label: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        []ModeItem,
        std.heap.c_allocator,
        json,
        .{ .ignore_unknown_fields = true },
    ) catch return;
    defer parsed.deinit();
    const n = @min(parsed.value.len, 256);
    const raw = c.calloc(n, @sizeOf(types.AuthdAuthMode));
    if (raw == null) return;
    const modes: [*]types.AuthdAuthMode = @ptrCast(@alignCast(raw));
    g.authd_auth_modes = modes;
    g.authd_num_auth_modes = @intCast(n);
    for (0..n) |i| {
        const item = parsed.value[i];
        modes[i].id = if (item.id) |s| dupStr(s) else null;
        modes[i].label = if (item.label) |s| dupStr(s) else null;
    }
}

fn parseUiLayout(json: []const u8) void {
    const Layout = struct {
        type: ?[]const u8 = null,
        label: ?[]const u8 = null,
        button: ?[]const u8 = null,
        entry: ?[]const u8 = null,
        wait: ?[]const u8 = null,
        content: ?[]const u8 = null,
        code: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        Layout,
        std.heap.c_allocator,
        json,
        .{ .ignore_unknown_fields = true },
    ) catch return;
    defer parsed.deinit();
    const layout = parsed.value;
    g.authd_layout.type =
        if (layout.type) |s| dupStr(s) else null;
    g.authd_layout.label =
        if (layout.label) |s| dupStr(s) else null;
    g.authd_layout.button =
        if (layout.button) |s| dupStr(s) else null;
    g.authd_layout.entry =
        if (layout.entry) |s| dupStr(s) else null;
    g.authd_layout.wait =
        if (layout.wait) |w| std.mem.eql(u8, w, "true") else false;
    g.authd_layout.qr_content =
        if (layout.content) |s| dupStr(s) else null;
    g.authd_layout.qr_code =
        if (layout.code) |s| dupStr(s) else null;
}

fn parseAuthEvent(json: []const u8) void {
    const Event = struct {
        msg: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(
        Event,
        std.heap.c_allocator,
        json,
        .{ .ignore_unknown_fields = true },
    ) catch return;
    defer parsed.deinit();
    g.authd_error =
        if (parsed.value.msg) |s| dupStr(s) else null;
}

fn termIn(
    fd: i32,
    mask: i16,
    data: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = fd;
    _ = mask;
    _ = data;
    g.run_display = false;
}

// Check for --debug early so the child process also gets the right
// Scan argv early for -d/--debug so the log level is set before
// full option parsing runs.
fn logInit(argc: c_int, argv: [*c][*c]u8) void {
    for (1..@as(usize, @intCast(argc))) |i| {
        const arg = std.mem.sliceTo(argv[i], 0);
        if (std.mem.eql(u8, arg, "-d") or
            std.mem.eql(u8, arg, "--debug"))
        {
            log.logInit(log.LogImportance.debug);
            return;
        }
    }
    log.logInit(log.LogImportance.err);
}

export fn main(argc: c_int, argv: [*c][*c]u8) c_int {
    defer if (comptime opts.have_debug_unlock_on_crash) debugUnlockOnExit();

    logInit(argc, argv);
    pam_mod.initializePwBackend(argc, argv);
    _ = c.srand(@intCast(wl.time(null)));

    var line_mode: types.LineMode = .line;
    g.failed_attempts = 0;
    g.authd_active = false;
    g.authd_stage = .none;
    g.authd_brokers = null;
    g.authd_num_brokers = 0;
    g.authd_sel_broker = -1;
    g.authd_auth_modes = null;
    g.authd_num_auth_modes = 0;
    g.authd_sel_auth_mode = -1;
    g.authd_layout = std.mem.zeroes(types.AuthdUiLayout);
    g.authd_error = null;
    g.args = std.mem.zeroes(types.SwaylockArgs);
    g.args.mode = .fill;
    g.args.font = @ptrCast(c.strdup("sans-serif"));
    g.args.font_size = 0;
    g.args.radius = 50;
    g.args.thickness = 10;
    g.args.indicator_x_position = 0;
    g.args.indicator_y_position = 0;
    g.args.override_indicator_x_position = false;
    g.args.override_indicator_y_position = false;
    g.args.ignore_empty = false;
    g.args.show_indicator = true;
    g.args.show_caps_lock_indicator = false;
    g.args.show_caps_lock_text = true;
    g.args.show_keyboard_layout = false;
    g.args.hide_keyboard_layout = false;
    g.args.show_failed_attempts = false;
    g.args.indicator_idle_visible = false;
    g.args.ready_fd = -1;

    setDefaultColors(&g.args.colors);

    var config_path_c: [*c]u8 = null;
    var result = params.parseOptions(argc, argv, null, null, &config_path_c);
    if (result != 0) {
        if (config_path_c != null) c.free(config_path_c);
        return result;
    }
    var config_path: ?[]u8 = null;
    if (config_path_c != null) {
        config_path = std.mem.sliceTo(config_path_c, 0);
    } else {
        config_path = getConfigPath(std.heap.c_allocator);
    }
    defer if (config_path) |p| std.heap.c_allocator.free(p);
    if (config_path) |path| {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "Found config at {s}",
            .{path},
        );
        const config_status = loadConfig(path, &g, &line_mode);
        if (config_status != 0) {
            c.free(@ptrCast(g.args.font));
            return config_status;
        }
    }
    if (argc > 1) {
        log.slog(log.LogImportance.debug, @src(), "Parsing CLI Args", .{});
        result = params.parseOptions(argc, argv, &g, &line_mode, null);
        if (result != 0) {
            c.free(@ptrCast(g.args.font));
            return result;
        }
    }
    if (line_mode == .inside) {
        g.args.colors.line = g.args.colors.inside;
    } else if (line_mode == .ring) {
        g.args.colors.line = g.args.colors.ring;
    }

    g.password.len = 0;
    g.password.buffer_len = 1024;
    g.password.buffer =
        password_buffer.passwordBufferCreate(g.password.buffer_len);
    if (g.password.buffer == null) return c.EXIT_FAILURE;
    g.password.buffer.?[0] = 0;

    if (c.pipe(@ptrCast(&sigusr_fds)) != 0) {
        log.slog(log.LogImportance.err, @src(), "Failed to pipe", .{});
        return c.EXIT_FAILURE;
    }
    if (c.fcntl(sigusr_fds[1], c.F_SETFL, c.O_NONBLOCK) == -1) {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Failed to make pipe end nonblocking",
            .{},
        );
        return c.EXIT_FAILURE;
    }

    g.xkb.context =
        types.c.xkb_context_new(types.c.XKB_CONTEXT_NO_FLAGS);
    g.display = wl.wl_display_connect(null);
    if (g.display == null) {
        c.free(@ptrCast(g.args.font));
        log.slog(
            log.LogImportance.err,
            @src(),
            "Unable to connect to the compositor. " ++
                "If your compositor is running, check or set the " ++
                "WAYLAND_DISPLAY environment variable.",
            .{},
        );
        return c.EXIT_FAILURE;
    }
    g.eventloop = loop.loopCreate();

    const registry =
        wl.wl_display_get_registry(g.display);
    _ = wl.wl_registry_add_listener(
        registry,
        &registry_listener,
        &g,
    );
    if (wl.wl_display_roundtrip(g.display) == -1) {
        log.slog(
            log.LogImportance.err,
            @src(),
            "wl_display_roundtrip() failed",
            .{},
        );
        return c.EXIT_FAILURE;
    }

    if (g.compositor == null) {
        log.slog(log.LogImportance.err, @src(), "Missing wl_compositor", .{});
        return 1;
    }
    if (g.subcompositor == null) {
        log.slog(log.LogImportance.err, @src(), "Missing wl_subcompositor", .{});
        return 1;
    }
    if (g.shm == null) {
        log.slog(log.LogImportance.err, @src(), "Missing wl_shm", .{});
        return 1;
    }
    if (g.ext_session_lock_manager_v1 == null) {
        log.slog(
            log.LogImportance.err,
            @src(),
            "Missing ext-session-lock-v1",
            .{},
        );
        return 1;
    }

    if (g.args.steal_unlock) {
        g.ext_session_lock_v1 =
            wl.ext_session_lock_manager_v1_lock(
                g.ext_session_lock_manager_v1,
            );
        _ = wl.ext_session_lock_v1_add_listener(
            g.ext_session_lock_v1,
            &ext_session_lock_v1_listener,
            &g,
        );
        while (!g.locked and !g.lock_failed) {
            if (wl.wl_display_dispatch(g.display) < 0) {
                log.slog(
                    log.LogImportance.err,
                    @src(),
                    "wl_display_dispatch() failed",
                    .{},
                );
                return 1;
            }
        }
        if (!g.locked) {
            log.slog(
                log.LogImportance.err,
                @src(),
                "Compositor refused the lock; " ++
                    "another locker may still be connected.",
                .{},
            );
            return 1;
        }
        wl.ext_session_lock_v1_unlock_and_destroy(
            g.ext_session_lock_v1,
        );
        _ = wl.wl_display_roundtrip(g.display);
        return 0;
    }

    g.ext_session_lock_v1 =
        wl.ext_session_lock_manager_v1_lock(
            g.ext_session_lock_manager_v1,
        );
    _ = wl.ext_session_lock_v1_add_listener(
        g.ext_session_lock_v1,
        &ext_session_lock_v1_listener,
        &g,
    );

    if (wl.wl_display_roundtrip(g.display) == -1) {
        c.free(@ptrCast(g.args.font));
        return 1;
    }

    g.test_surface = types.c.cairo_image_surface_create(
        types.c.CAIRO_FORMAT_RGB24,
        1,
        1,
    );
    g.test_cairo = types.c.cairo_create(g.test_surface);

    for (g.surfaces.items) |surface| {
        createSurface(surface);
    }

    while (!g.locked) {
        if (wl.wl_display_dispatch(g.display) < 0) {
            log.slog(
                log.LogImportance.err,
                @src(),
                "wl_display_dispatch() failed",
                .{},
            );
            return 2;
        }
    }

    if (g.args.ready_fd >= 0) {
        if (c.write(g.args.ready_fd, "\n", 1) != 1) {
            log.slog(
                log.LogImportance.err,
                @src(),
                "Failed to send readiness notification",
                .{},
            );
            return 2;
        }
        _ = c.close(g.args.ready_fd);
        g.args.ready_fd = -1;
    }
    if (g.args.daemonize) daemonize();

    loop.loopAddFd(
        g.eventloop.?,
        wl.wl_display_get_fd(g.display),
        @as(i16, @intCast(wl.POLLIN)),
        displayIn,
        null,
    );
    loop.loopAddFd(
        g.eventloop.?,
        comm.getCommReplyFd(),
        @as(i16, @intCast(wl.POLLIN)),
        commIn,
        null,
    );
    loop.loopAddFd(
        g.eventloop.?,
        sigusr_fds[0],
        @as(i16, @intCast(wl.POLLIN)),
        termIn,
        null,
    );

    const sa = std.posix.Sigaction{
        .handler = .{ .handler = doSigusr },
        .mask = std.posix.empty_sigset,
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(std.posix.SIG.USR1, &sa, null);

    if (comptime opts.have_debug_unlock_on_crash) {
        const crash_sa = std.posix.Sigaction{
            .handler = .{ .handler = debugUnlockOnCrash },
            .mask = std.posix.empty_sigset,
            .flags = std.posix.SA.RESETHAND,
        };
        std.posix.sigaction(std.posix.SIG.SEGV, &crash_sa, null);
        std.posix.sigaction(std.posix.SIG.ABRT, &crash_sa, null);
        std.posix.sigaction(std.posix.SIG.BUS, &crash_sa, null);
        std.posix.sigaction(std.posix.SIG.ILL, &crash_sa, null);
        std.posix.sigaction(std.posix.SIG.FPE, &crash_sa, null);
    }

    g.run_display = true;
    while (g.run_display) {
        c.__errno_location().* = 0;
        if (wl.wl_display_flush(g.display) == -1 and
            c.__errno_location().* != c.EAGAIN)
        {
            break;
        }
        loop.loopPoll(g.eventloop.?);
    }

    wl.ext_session_lock_v1_unlock_and_destroy(g.ext_session_lock_v1);
    g.ext_session_lock_v1 = null;
    _ = wl.wl_display_roundtrip(g.display);

    c.free(@ptrCast(g.args.font));
    types.c.cairo_destroy(g.test_cairo);
    types.c.cairo_surface_destroy(g.test_surface);
    return 0;
}
