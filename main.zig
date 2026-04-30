//! main.zig – Zig port of main.c.
//! All JSON parsing uses std.json in place of cJSON.

const std = @import("std");
const opts = @import("main_options");

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    if (opts.have_debug_overlay) @cDefine("HAVE_DEBUG_OVERLAY", "1");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("getopt.h");
    @cInclude("signal.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
    @cInclude("wordexp.h");
});

const types = @import("types");
const wl = types.c;
const log_err: c_int = @intFromEnum(types.LogImportance.err);
const log_info: c_int = @intFromEnum(types.LogImportance.info);
const log_debug: c_int = @intFromEnum(types.LogImportance.debug);

// Log functions via C ABI (defined in log.zig).
extern fn _swaylock_log(verbosity: c_int, fmt: [*c]const u8, ...) void;
extern fn _swaylock_strip_path(
    filepath: [*c]const u8,
) [*c]const u8;
extern fn swaylock_log_init(verbosity: c_int) void;

// Loop functions.
extern fn loop_create() ?*types.Loop;
extern fn loop_destroy(loop: *types.Loop) void;
extern fn loop_poll(loop: *types.Loop) void;
extern fn loop_add_fd(
    loop: *types.Loop,
    fd: c_int,
    mask: c_short,
    callback: types.FdCallback,
    data: ?*anyopaque,
) void;
extern fn loop_remove_fd(loop: *types.Loop, fd: c_int) bool;
extern fn loop_add_timer(
    loop: *types.Loop,
    ms: c_int,
    callback: types.TimerCallback,
    data: ?*anyopaque,
) ?*types.LoopTimer;
extern fn loop_remove_timer(
    loop: *types.Loop,
    timer: *types.LoopTimer,
) bool;

// Pool-buffer functions.
extern fn get_next_buffer(
    shm: ?*wl.wl_shm,
    pool: [*]types.PoolBuffer,
    width: u32,
    height: u32,
) ?*types.PoolBuffer;
extern fn create_buffer(
    shm: ?*wl.wl_shm,
    buf: *types.PoolBuffer,
    width: i32,
    height: i32,
    format: u32,
) ?*types.PoolBuffer;
extern fn destroy_buffer(buffer: *types.PoolBuffer) void;

// Cairo helper functions.
extern fn cairo_set_source_u32(
    cairo: ?*types.c.cairo_t,
    color: u32,
) void;
extern fn to_cairo_subpixel_order(
    subpixel: wl.wl_output_subpixel,
) types.c.cairo_subpixel_order_t;

// Background image functions.
extern fn parse_background_mode(
    mode: [*c]const u8,
) types.BackgroundMode;
extern fn load_background_image(
    path: [*c]const u8,
) ?*types.c.cairo_surface_t;

// Comm functions.
extern fn spawn_comm_child() bool;
extern fn comm_main_read(payload: *[*c]u8, len: *usize) c_int;
extern fn comm_main_write(
    msg_type: u8,
    payload: [*c]const u8,
    len: usize,
) bool;
extern fn get_comm_reply_fd() c_int;
extern fn write_comm_password(pw: *types.SwaylockPassword) bool;

// Password functions.
extern fn swaylock_handle_key(
    state: *types.SwaylockState,
    keysym: wl.xkb_keysym_t,
    codepoint: u32,
) void;
extern fn schedule_auth_idle(state: *types.SwaylockState) void;
extern fn clear_password_buffer(pw: *types.SwaylockPassword) void;
extern fn password_buffer_create(size: usize) [*c]u8;

// Render function (defined in render.zig).
extern fn render(surface: *types.SwaylockSurface) void;

// Seat listener (exported from seat.zig).
extern var seat_listener: wl.wl_seat_listener;

// PAM/auth backend functions (from pam.zig or shadow.c).
extern fn initialize_pw_backend(argc: c_int, argv: [*c][*c]u8) void;

// Authd/PAM helpers (from pam.zig).
extern fn authd_ui_layout_clear(layout: *types.AuthdUiLayout) void;
extern fn authd_brokers_free(
    brokers: [*c]types.AuthdBroker,
    count: c_int,
) void;
extern fn authd_auth_modes_free(
    modes: [*c]types.AuthdAuthMode,
    count: c_int,
) void;

// getopt globals not always exposed by @cImport.
extern var optarg: [*c]u8;
extern var optind: c_int;

var sigusr_fds: [2]c_int = .{ -1, -1 };
var state: types.SwaylockState = std.mem.zeroes(types.SwaylockState);

const LineMode = enum { line, inside, ring };

/// Emit a log message with source location prepended.
fn slog(
    verbosity: c_int,
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

/// Return the struct enclosing a wl_list node pointer.
/// Accepts any pointer type to avoid cImport-namespace mismatches.
fn wlEntry(
    comptime T: type,
    comptime field: []const u8,
    node: anytype,
) *T {
    return @ptrFromInt(@intFromPtr(node) - @offsetOf(T, field));
}

/// Duplicate a Zig slice into a C malloc-owned null-terminated string.
fn dupStr(s: []const u8) [*c]u8 {
    const result = std.heap.c_allocator.dupeZ(u8, s) catch
        return null;
    return result.ptr;
}

fn parseColor(color_in: [*c]const u8) u32 {
    var color = color_in;
    if (color[0] == '#') color += 1;
    const len = c.strlen(color);
    if (len != 6 and len != 8) {
        slog(
            log_debug,
            @src(),
            "Invalid color {s}, defaulting to 0xFFFFFFFF",
            .{color},
        );
        return 0xFFFFFFFF;
    }
    var res: u32 = @truncate(c.strtoul(color, null, 16));
    if (len == 6) res = (res << 8) | 0xFF;
    return res;
}

fn lenientStrcmp(a: [*c]const u8, b: [*c]const u8) c_int {
    if (a == b) return 0;
    if (a == null) return -1;
    if (b == null) return 1;
    return c.strcmp(a, b);
}

fn daemonize() void {
    var fds: [2]c_int = undefined;
    if (c.pipe(&fds) != 0) {
        slog(log_err, @src(), "Failed to pipe", .{});
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
            slog(log_err, @src(), "Failed to daemonize", .{});
            c.exit(1);
        }
        _ = c.close(fds[0]);
        c.exit(0);
    }
}

fn destroySurface(surface: *types.SwaylockSurface) void {
    if (surface.frame != null)
        wl.wl_callback_destroy(surface.frame);
    wl.wl_list_remove(&surface.link);
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
    destroy_buffer(&surface.indicator_buffers[0]);
    destroy_buffer(&surface.indicator_buffers[1]);
    if (opts.have_debug_overlay) {
        if (surface.overlay_sub != null)
            wl.wl_subsurface_destroy(surface.overlay_sub);
        if (surface.overlay != null)
            wl.wl_surface_destroy(surface.overlay);
        destroy_buffer(&surface.overlay_buffers[0]);
        destroy_buffer(&surface.overlay_buffers[1]);
    }
    wl.wl_output_release(surface.output);
    std.heap.c_allocator.destroy(surface);
}

fn surfaceIsOpaque(surface: *types.SwaylockSurface) bool {
    if (surface.image != null) {
        return types.c.cairo_surface_get_content(surface.image) ==
            types.c.CAIRO_CONTENT_COLOR;
    }
    return (surface.state.?.args.colors.background & 0xff) == 0xff;
}

fn createSurface(surface: *types.SwaylockSurface) void {
    const st = surface.state.?;
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
    if (opts.have_debug_overlay) {
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
    render(surface);
}

const ext_session_lock_surface_v1_listener: wl.struct_ext_session_lock_surface_v1_listener = .{
    .configure = @ptrCast(&extSessionLockSurfaceV1HandleConfigure),
};

export fn damage_state(st: *types.SwaylockState) void {
    const head = &st.surfaces;
    var node = head.next;
    while (node != head) {
        const surface =
            wlEntry(types.SwaylockSurface, "link", node.?);
        node = surface.link.next;
        surface.dirty = true;
        render(surface);
    }
}

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
    if (surface.state.?.run_display) {
        surface.dirty = true;
        render(surface);
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
    if (!surface.created and surface.state.?.run_display)
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
    if (surface.state.?.run_display) {
        surface.dirty = true;
        render(surface);
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
    surface.output_name = c.strdup(name);
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
    slog(
        log_err,
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
        const seat: ?*wl.wl_seat = @ptrCast(wl.wl_registry_bind(
            registry,
            name,
            &wl.wl_seat_interface,
            4,
        ));
        const swaylock_seat = std.heap.c_allocator.create(
            types.SwaylockSeat,
        ) catch @panic("OOM");
        swaylock_seat.* = std.mem.zeroes(types.SwaylockSeat);
        swaylock_seat.state = st;
        _ = wl.wl_seat_add_listener(
            seat,
            &seat_listener,
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
        surface.state = st;
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
        wl.wl_list_insert(&st.surfaces, &surface.link);
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
    const head = &st.surfaces;
    var node = head.next;
    while (node != head) {
        const surface =
            wlEntry(types.SwaylockSurface, "link", node.?);
        node = surface.link.next;
        if (surface.output_global_name == name) {
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

fn debugUnlockOnExit() callconv(std.builtin.CallingConvention.c) void {
    if (state.ext_session_lock_v1 != null) {
        wl.ext_session_lock_v1_unlock_and_destroy(
            state.ext_session_lock_v1,
        );
        state.ext_session_lock_v1 = null;
        if (state.display != null)
            _ = wl.wl_display_flush(state.display);
    }
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
    const head = &st.images;
    var node = head.next;
    while (node != head) {
        const image = wlEntry(types.SwaylockImage, "link", node.?);
        node = image.link.next;
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

fn joinArgs(argv: [*c][*c]u8, argc: c_int) [*c]u8 {
    std.debug.assert(argc > 0);
    var len: usize = 0;
    var i: usize = 0;
    while (i < @as(usize, @intCast(argc))) : (i += 1)
        len += c.strlen(argv[i]) + 1;
    const res: [*c]u8 = @ptrCast(c.malloc(len));
    if (res == null) return null;
    var offset: usize = 0;
    i = 0;
    while (i < @as(usize, @intCast(argc))) : (i += 1) {
        const s = argv[i];
        const slen = c.strlen(s);
        _ = c.strcpy(res + offset, s);
        offset += slen;
        res[offset] = ' ';
        offset += 1;
    }
    res[offset - 1] = 0;
    return res;
}

fn loadImage(arg: [*c]u8, st: *types.SwaylockState) void {
    const image = std.heap.c_allocator.create(
        types.SwaylockImage,
    ) catch @panic("OOM");
    image.* = std.mem.zeroes(types.SwaylockImage);
    const separator: [*c]u8 = c.strchr(arg, ':');
    if (separator != null) {
        separator[0] = 0;
        image.output_name = if (separator == arg)
            null
        else
            c.strdup(arg);
        image.path = c.strdup(separator + 1);
    } else {
        image.output_name = null;
        image.path = c.strdup(arg);
    }
    // Replace any existing image for the same output.
    const head = &st.images;
    var node = head.next;
    while (node != head) {
        const iter_image =
            wlEntry(types.SwaylockImage, "link", node.?);
        node = iter_image.link.next;
        if (lenientStrcmp(
            iter_image.output_name,
            image.output_name,
        ) == 0) {
            if (image.output_name != null) {
                slog(
                    log_debug,
                    @src(),
                    "Replacing image defined for output {s} with {s}",
                    .{ image.output_name, image.path },
                );
            } else {
                slog(
                    log_debug,
                    @src(),
                    "Replacing default image with {s}",
                    .{image.path},
                );
            }
            wl.wl_list_remove(&iter_image.link);
            c.free(iter_image.cairo_surface);
            c.free(iter_image.output_name);
            c.free(iter_image.path);
            std.heap.c_allocator.destroy(iter_image);
            break;
        }
    }
    // Escape double spaces so wordexp handles the path correctly.
    while (c.strstr(image.path, "  ") != null) {
        const old_len = c.strlen(image.path);
        image.path = @ptrCast(c.realloc(image.path, old_len + 2));
        const ptr: [*c]u8 = c.strstr(image.path, "  ") + 1;
        _ = c.memmove(ptr + 1, ptr, c.strlen(ptr) + 1);
        ptr[0] = '\\';
    }
    var p: c.wordexp_t = undefined;
    if (c.wordexp(image.path, &p, 0) == 0) {
        c.free(image.path);
        image.path = joinArgs(p.we_wordv, @intCast(p.we_wordc));
        c.wordfree(&p);
    }
    image.cairo_surface = load_background_image(image.path);
    if (image.cairo_surface == null) {
        std.heap.c_allocator.destroy(image);
        return;
    }
    wl.wl_list_insert(&st.images, &image.link);
    slog(
        log_debug,
        @src(),
        "Loaded image {s} for output {s}",
        .{
            image.path,
            if (image.output_name != null)
                @as([*c]const u8, image.output_name)
            else
                @as([*c]const u8, "*"),
        },
    );
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

// Long option codes starting above the ASCII range.
const lo_bs_hl_color: c_int = 256;
const lo_caps_lock_bs_hl_color: c_int = 257;
const lo_caps_lock_key_hl_color: c_int = 258;
const lo_font: c_int = 259;
const lo_font_size: c_int = 260;
const lo_ind_idle_visible: c_int = 261;
const lo_ind_radius: c_int = 262;
const lo_ind_x_position: c_int = 263;
const lo_ind_y_position: c_int = 264;
const lo_ind_thickness: c_int = 265;
const lo_inside_color: c_int = 266;
const lo_inside_clear_color: c_int = 267;
const lo_inside_caps_lock_color: c_int = 268;
const lo_inside_ver_color: c_int = 269;
const lo_inside_wrong_color: c_int = 270;
const lo_key_hl_color: c_int = 271;
const lo_layout_txt_color: c_int = 272;
const lo_layout_bg_color: c_int = 273;
const lo_layout_border_color: c_int = 274;
const lo_line_color: c_int = 275;
const lo_line_clear_color: c_int = 276;
const lo_line_caps_lock_color: c_int = 277;
const lo_line_ver_color: c_int = 278;
const lo_line_wrong_color: c_int = 279;
const lo_ring_color: c_int = 280;
const lo_ring_clear_color: c_int = 281;
const lo_ring_caps_lock_color: c_int = 282;
const lo_ring_ver_color: c_int = 283;
const lo_ring_wrong_color: c_int = 284;
const lo_sep_color: c_int = 285;
const lo_text_color: c_int = 286;
const lo_text_clear_color: c_int = 287;
const lo_text_caps_lock_color: c_int = 288;
const lo_text_ver_color: c_int = 289;
const lo_text_wrong_color: c_int = 290;
const lo_steal_unlock: c_int = 291;

const usage =
    "Usage: swaylock [options...]\n" ++
    "\n" ++
    "  -C, --config <config_file>       " ++
    "Path to the config file.\n" ++
    "  -c, --color <color>              " ++
    "Turn the screen into the given color instead of light gray.\n" ++
    "  -d, --debug                      " ++
    "Enable debugging output.\n" ++
    "  -e, --ignore-empty-password      " ++
    "When an empty password is provided, do not validate it.\n" ++
    "  -F, --show-failed-attempts       " ++
    "Show current count of failed authentication attempts.\n" ++
    "  -f, --daemonize                  " ++
    "Detach from the controlling terminal after locking.\n" ++
    "  -R, --ready-fd <fd>              " ++
    "File descriptor to send readiness notifications to.\n" ++
    "  -h, --help                       " ++
    "Show help message and quit.\n" ++
    "  -i, --image [[<output>]:]<path>  " ++
    "Display the given image, optionally only on the given output.\n" ++
    "  -k, --show-keyboard-layout       " ++
    "Display the current xkb layout while typing.\n" ++
    "  -K, --hide-keyboard-layout       " ++
    "Hide the current xkb layout while typing.\n" ++
    "  -L, --disable-caps-lock-text     " ++
    "Disable the Caps Lock text.\n" ++
    "  -l, --indicator-caps-lock        " ++
    "Show the current Caps Lock state also on the indicator.\n" ++
    "  -s, --scaling <mode>             " ++
    "Image scaling mode: stretch, fill, fit, center, tile, solid_color.\n" ++
    "  -t, --tiling                     " ++
    "Same as --scaling=tile.\n" ++
    "  -u, --no-unlock-indicator        " ++
    "Disable the unlock indicator.\n" ++
    "  -v, --version                    " ++
    "Show the version number and quit.\n" ++
    "  --steal-unlock                   " ++
    "Attempt to unlock a session left locked by a crashed\n" ++
    "                               " ++
    "swaylock instance, then exit.\n" ++
    "  --bs-hl-color <color>            " ++
    "Sets the color of backspace highlight segments.\n" ++
    "  --caps-lock-bs-hl-color <color>  " ++
    "Sets the color of backspace highlight segments when Caps Lock " ++
    "is active.\n" ++
    "  --caps-lock-key-hl-color <color> " ++
    "Sets the color of the key press highlight segments when " ++
    "Caps Lock is active.\n" ++
    "  --font <font>                    " ++
    "Sets the font of the text.\n" ++
    "  --font-size <size>               " ++
    "Sets a fixed font size for the indicator text.\n" ++
    "  --indicator-idle-visible         " ++
    "Sets the indicator to show even if idle.\n" ++
    "  --indicator-radius <radius>      " ++
    "Sets the indicator radius.\n" ++
    "  --indicator-thickness <thick>    " ++
    "Sets the indicator thickness.\n" ++
    "  --indicator-x-position <x>       " ++
    "Sets the horizontal position of the indicator.\n" ++
    "  --indicator-y-position <y>       " ++
    "Sets the vertical position of the indicator.\n" ++
    "  --inside-color <color>           " ++
    "Sets the color of the inside of the indicator.\n" ++
    "  --inside-clear-color <color>     " ++
    "Sets the color of the inside of the indicator when cleared.\n" ++
    "  --inside-caps-lock-color <color> " ++
    "Sets the color of the inside of the indicator when Caps Lock " ++
    "is active.\n" ++
    "  --inside-ver-color <color>       " ++
    "Sets the color of the inside of the indicator when verifying.\n" ++
    "  --inside-wrong-color <color>     " ++
    "Sets the color of the inside of the indicator when invalid.\n" ++
    "  --key-hl-color <color>           " ++
    "Sets the color of the key press highlight segments.\n" ++
    "  --layout-bg-color <color>        " ++
    "Sets the background color of the box containing the layout text.\n" ++
    "  --layout-border-color <color>    " ++
    "Sets the color of the border of the box containing the layout text.\n" ++
    "  --layout-text-color <color>      " ++
    "Sets the color of the layout text.\n" ++
    "  --line-color <color>             " ++
    "Sets the color of the line between the inside and ring.\n" ++
    "  --line-clear-color <color>       " ++
    "Sets the color of the line between the inside and ring when " ++
    "cleared.\n" ++
    "  --line-caps-lock-color <color>   " ++
    "Sets the color of the line between the inside and ring when " ++
    "Caps Lock is active.\n" ++
    "  --line-ver-color <color>         " ++
    "Sets the color of the line between the inside and ring when " ++
    "verifying.\n" ++
    "  --line-wrong-color <color>       " ++
    "Sets the color of the line between the inside and ring when " ++
    "invalid.\n" ++
    "  -n, --line-uses-inside           " ++
    "Use the inside color for the line between the inside and ring.\n" ++
    "  -r, --line-uses-ring             " ++
    "Use the ring color for the line between the inside and ring.\n" ++
    "  --ring-color <color>             " ++
    "Sets the color of the ring of the indicator.\n" ++
    "  --ring-clear-color <color>       " ++
    "Sets the color of the ring of the indicator when cleared.\n" ++
    "  --ring-caps-lock-color <color>   " ++
    "Sets the color of the ring of the indicator when Caps Lock " ++
    "is active.\n" ++
    "  --ring-ver-color <color>         " ++
    "Sets the color of the ring of the indicator when verifying.\n" ++
    "  --ring-wrong-color <color>       " ++
    "Sets the color of the ring of the indicator when invalid.\n" ++
    "  --separator-color <color>        " ++
    "Sets the color of the lines that separate highlight segments.\n" ++
    "  --text-color <color>             " ++
    "Sets the color of the text.\n" ++
    "  --text-clear-color <color>       " ++
    "Sets the color of the text when cleared.\n" ++
    "  --text-caps-lock-color <color>   " ++
    "Sets the color of the text when Caps Lock is active.\n" ++
    "  --text-ver-color <color>         " ++
    "Sets the color of the text when verifying.\n" ++
    "  --text-wrong-color <color>       " ++
    "Sets the color of the text when invalid.\n" ++
    "\n" ++
    "All <color> options are of the form <rrggbb[aa]>.\n";

fn parseOptions(
    argc: c_int,
    argv: [*c][*c]u8,
    st: ?*types.SwaylockState,
    line_mode: ?*LineMode,
    config_path: ?*[*c]u8,
) c_int {
    const long_options = [_]c.struct_option{
        .{ .name = "config", .has_arg = c.required_argument, .flag = null, .val = 'C' },
        .{ .name = "color", .has_arg = c.required_argument, .flag = null, .val = 'c' },
        .{ .name = "debug", .has_arg = c.no_argument, .flag = null, .val = 'd' },
        .{ .name = "ignore-empty-password", .has_arg = c.no_argument, .flag = null, .val = 'e' },
        .{ .name = "daemonize", .has_arg = c.no_argument, .flag = null, .val = 'f' },
        .{ .name = "ready-fd", .has_arg = c.required_argument, .flag = null, .val = 'R' },
        .{ .name = "help", .has_arg = c.no_argument, .flag = null, .val = 'h' },
        .{ .name = "image", .has_arg = c.required_argument, .flag = null, .val = 'i' },
        .{ .name = "disable-caps-lock-text", .has_arg = c.no_argument, .flag = null, .val = 'L' },
        .{ .name = "indicator-caps-lock", .has_arg = c.no_argument, .flag = null, .val = 'l' },
        .{ .name = "line-uses-inside", .has_arg = c.no_argument, .flag = null, .val = 'n' },
        .{ .name = "line-uses-ring", .has_arg = c.no_argument, .flag = null, .val = 'r' },
        .{ .name = "scaling", .has_arg = c.required_argument, .flag = null, .val = 's' },
        .{ .name = "tiling", .has_arg = c.no_argument, .flag = null, .val = 't' },
        .{ .name = "no-unlock-indicator", .has_arg = c.no_argument, .flag = null, .val = 'u' },
        .{ .name = "show-keyboard-layout", .has_arg = c.no_argument, .flag = null, .val = 'k' },
        .{ .name = "hide-keyboard-layout", .has_arg = c.no_argument, .flag = null, .val = 'K' },
        .{ .name = "show-failed-attempts", .has_arg = c.no_argument, .flag = null, .val = 'F' },
        .{ .name = "version", .has_arg = c.no_argument, .flag = null, .val = 'v' },
        .{ .name = "bs-hl-color", .has_arg = c.required_argument, .flag = null, .val = lo_bs_hl_color },
        .{ .name = "caps-lock-bs-hl-color", .has_arg = c.required_argument, .flag = null, .val = lo_caps_lock_bs_hl_color },
        .{ .name = "caps-lock-key-hl-color", .has_arg = c.required_argument, .flag = null, .val = lo_caps_lock_key_hl_color },
        .{ .name = "font", .has_arg = c.required_argument, .flag = null, .val = lo_font },
        .{ .name = "font-size", .has_arg = c.required_argument, .flag = null, .val = lo_font_size },
        .{ .name = "indicator-idle-visible", .has_arg = c.no_argument, .flag = null, .val = lo_ind_idle_visible },
        .{ .name = "indicator-radius", .has_arg = c.required_argument, .flag = null, .val = lo_ind_radius },
        .{ .name = "indicator-thickness", .has_arg = c.required_argument, .flag = null, .val = lo_ind_thickness },
        .{ .name = "indicator-x-position", .has_arg = c.required_argument, .flag = null, .val = lo_ind_x_position },
        .{ .name = "indicator-y-position", .has_arg = c.required_argument, .flag = null, .val = lo_ind_y_position },
        .{ .name = "inside-color", .has_arg = c.required_argument, .flag = null, .val = lo_inside_color },
        .{ .name = "inside-clear-color", .has_arg = c.required_argument, .flag = null, .val = lo_inside_clear_color },
        .{ .name = "inside-caps-lock-color", .has_arg = c.required_argument, .flag = null, .val = lo_inside_caps_lock_color },
        .{ .name = "inside-ver-color", .has_arg = c.required_argument, .flag = null, .val = lo_inside_ver_color },
        .{ .name = "inside-wrong-color", .has_arg = c.required_argument, .flag = null, .val = lo_inside_wrong_color },
        .{ .name = "key-hl-color", .has_arg = c.required_argument, .flag = null, .val = lo_key_hl_color },
        .{ .name = "layout-bg-color", .has_arg = c.required_argument, .flag = null, .val = lo_layout_bg_color },
        .{ .name = "layout-border-color", .has_arg = c.required_argument, .flag = null, .val = lo_layout_border_color },
        .{ .name = "layout-text-color", .has_arg = c.required_argument, .flag = null, .val = lo_layout_txt_color },
        .{ .name = "line-color", .has_arg = c.required_argument, .flag = null, .val = lo_line_color },
        .{ .name = "line-clear-color", .has_arg = c.required_argument, .flag = null, .val = lo_line_clear_color },
        .{ .name = "line-caps-lock-color", .has_arg = c.required_argument, .flag = null, .val = lo_line_caps_lock_color },
        .{ .name = "line-ver-color", .has_arg = c.required_argument, .flag = null, .val = lo_line_ver_color },
        .{ .name = "line-wrong-color", .has_arg = c.required_argument, .flag = null, .val = lo_line_wrong_color },
        .{ .name = "ring-color", .has_arg = c.required_argument, .flag = null, .val = lo_ring_color },
        .{ .name = "ring-clear-color", .has_arg = c.required_argument, .flag = null, .val = lo_ring_clear_color },
        .{ .name = "ring-caps-lock-color", .has_arg = c.required_argument, .flag = null, .val = lo_ring_caps_lock_color },
        .{ .name = "ring-ver-color", .has_arg = c.required_argument, .flag = null, .val = lo_ring_ver_color },
        .{ .name = "ring-wrong-color", .has_arg = c.required_argument, .flag = null, .val = lo_ring_wrong_color },
        .{ .name = "separator-color", .has_arg = c.required_argument, .flag = null, .val = lo_sep_color },
        .{ .name = "text-color", .has_arg = c.required_argument, .flag = null, .val = lo_text_color },
        .{ .name = "text-clear-color", .has_arg = c.required_argument, .flag = null, .val = lo_text_clear_color },
        .{ .name = "text-caps-lock-color", .has_arg = c.required_argument, .flag = null, .val = lo_text_caps_lock_color },
        .{ .name = "text-ver-color", .has_arg = c.required_argument, .flag = null, .val = lo_text_ver_color },
        .{ .name = "text-wrong-color", .has_arg = c.required_argument, .flag = null, .val = lo_text_wrong_color },
        .{ .name = "steal-unlock", .has_arg = c.no_argument, .flag = null, .val = lo_steal_unlock },
        .{ .name = null, .has_arg = 0, .flag = null, .val = 0 },
    };
    optind = 1;
    while (true) {
        var opt_idx: c_int = 0;
        const ch = c.getopt_long(
            argc,
            argv,
            "c:deFfhi:kKLlnrs:tuvC:R:",
            &long_options,
            &opt_idx,
        );
        if (ch == -1) break;
        switch (ch) {
            'C' => {
                if (config_path) |cp|
                    cp.* = c.strdup(optarg);
            },
            'c' => {
                if (st) |s|
                    s.args.colors.background = parseColor(optarg);
            },
            'd' => swaylock_log_init(log_debug),
            'e' => {
                if (st) |s| s.args.ignore_empty = true;
            },
            'F' => {
                if (st) |s| s.args.show_failed_attempts = true;
            },
            'f' => {
                if (st) |s| s.args.daemonize = true;
            },
            'R' => {
                if (st) |s|
                    s.args.ready_fd = @intCast(
                        c.strtol(optarg, null, 10),
                    );
            },
            'h' => {
                _ = c.fprintf(c.stdout, "%s", usage.ptr);
                c.exit(c.EXIT_SUCCESS);
            },
            'i' => {
                if (st) |s| loadImage(optarg, s);
            },
            'k' => {
                if (st) |s| s.args.show_keyboard_layout = true;
            },
            'K' => {
                if (st) |s| s.args.hide_keyboard_layout = true;
            },
            'L' => {
                if (st) |s| s.args.show_caps_lock_text = false;
            },
            'l' => {
                if (st) |s| s.args.show_caps_lock_indicator = true;
            },
            'n' => {
                if (line_mode) |lm| lm.* = .inside;
            },
            'r' => {
                if (line_mode) |lm| lm.* = .ring;
            },
            's' => {
                if (st) |s| {
                    s.args.mode = parse_background_mode(optarg);
                    if (s.args.mode == .invalid)
                        return 1;
                }
            },
            't' => {
                if (st) |s|
                    s.args.mode = .tile;
            },
            'u' => {
                if (st) |s| s.args.show_indicator = false;
            },
            'v' => {
                _ = c.fprintf(
                    c.stdout,
                    "swaylock version %s\n",
                    opts.swaylock_version.ptr,
                );
                c.exit(c.EXIT_SUCCESS);
            },
            lo_bs_hl_color => {
                if (st) |s|
                    s.args.colors.bs_highlight =
                        parseColor(optarg);
            },
            lo_caps_lock_bs_hl_color => {
                if (st) |s|
                    s.args.colors.caps_lock_bs_highlight =
                        parseColor(optarg);
            },
            lo_caps_lock_key_hl_color => {
                if (st) |s|
                    s.args.colors.caps_lock_key_highlight =
                        parseColor(optarg);
            },
            lo_font => {
                if (st) |s| {
                    c.free(s.args.font);
                    s.args.font = c.strdup(optarg);
                }
            },
            lo_font_size => {
                if (st) |s|
                    s.args.font_size = @intCast(c.atoi(optarg));
            },
            lo_ind_idle_visible => {
                if (st) |s|
                    s.args.indicator_idle_visible = true;
            },
            lo_ind_radius => {
                if (st) |s|
                    s.args.radius = @intCast(
                        c.strtol(optarg, null, 0),
                    );
            },
            lo_ind_thickness => {
                if (st) |s|
                    s.args.thickness = @intCast(
                        c.strtol(optarg, null, 0),
                    );
            },
            lo_ind_x_position => {
                if (st) |s| {
                    s.args.override_indicator_x_position = true;
                    s.args.indicator_x_position =
                        @intCast(c.atoi(optarg));
                }
            },
            lo_ind_y_position => {
                if (st) |s| {
                    s.args.override_indicator_y_position = true;
                    s.args.indicator_y_position =
                        @intCast(c.atoi(optarg));
                }
            },
            lo_inside_color => {
                if (st) |s|
                    s.args.colors.inside.input = parseColor(optarg);
            },
            lo_inside_clear_color => {
                if (st) |s|
                    s.args.colors.inside.cleared =
                        parseColor(optarg);
            },
            lo_inside_caps_lock_color => {
                if (st) |s|
                    s.args.colors.inside.caps_lock =
                        parseColor(optarg);
            },
            lo_inside_ver_color => {
                if (st) |s|
                    s.args.colors.inside.verifying =
                        parseColor(optarg);
            },
            lo_inside_wrong_color => {
                if (st) |s|
                    s.args.colors.inside.wrong = parseColor(optarg);
            },
            lo_key_hl_color => {
                if (st) |s|
                    s.args.colors.key_highlight = parseColor(optarg);
            },
            lo_layout_bg_color => {
                if (st) |s|
                    s.args.colors.layout_background =
                        parseColor(optarg);
            },
            lo_layout_border_color => {
                if (st) |s|
                    s.args.colors.layout_border = parseColor(optarg);
            },
            lo_layout_txt_color => {
                if (st) |s|
                    s.args.colors.layout_text = parseColor(optarg);
            },
            lo_line_color => {
                if (st) |s|
                    s.args.colors.line.input = parseColor(optarg);
            },
            lo_line_clear_color => {
                if (st) |s|
                    s.args.colors.line.cleared = parseColor(optarg);
            },
            lo_line_caps_lock_color => {
                if (st) |s|
                    s.args.colors.line.caps_lock = parseColor(optarg);
            },
            lo_line_ver_color => {
                if (st) |s|
                    s.args.colors.line.verifying = parseColor(optarg);
            },
            lo_line_wrong_color => {
                if (st) |s|
                    s.args.colors.line.wrong = parseColor(optarg);
            },
            lo_ring_color => {
                if (st) |s|
                    s.args.colors.ring.input = parseColor(optarg);
            },
            lo_ring_clear_color => {
                if (st) |s|
                    s.args.colors.ring.cleared = parseColor(optarg);
            },
            lo_ring_caps_lock_color => {
                if (st) |s|
                    s.args.colors.ring.caps_lock = parseColor(optarg);
            },
            lo_ring_ver_color => {
                if (st) |s|
                    s.args.colors.ring.verifying = parseColor(optarg);
            },
            lo_ring_wrong_color => {
                if (st) |s|
                    s.args.colors.ring.wrong = parseColor(optarg);
            },
            lo_sep_color => {
                if (st) |s|
                    s.args.colors.separator = parseColor(optarg);
            },
            lo_text_color => {
                if (st) |s|
                    s.args.colors.text.input = parseColor(optarg);
            },
            lo_text_clear_color => {
                if (st) |s|
                    s.args.colors.text.cleared = parseColor(optarg);
            },
            lo_text_caps_lock_color => {
                if (st) |s|
                    s.args.colors.text.caps_lock = parseColor(optarg);
            },
            lo_text_ver_color => {
                if (st) |s|
                    s.args.colors.text.verifying = parseColor(optarg);
            },
            lo_text_wrong_color => {
                if (st) |s|
                    s.args.colors.text.wrong = parseColor(optarg);
            },
            lo_steal_unlock => {
                if (st) |s| s.args.steal_unlock = true;
            },
            else => {
                _ = c.fprintf(c.stderr, "%s", usage.ptr);
                return 1;
            },
        }
    }
    return 0;
}

fn fileExists(path: [*c]const u8) bool {
    return path != null and c.access(path, c.R_OK) != -1;
}

fn getConfigPath() ?[*c]u8 {
    const xdg_config_home = c.getenv("XDG_CONFIG_HOME");
    const path2: [*c]const u8 =
        if (xdg_config_home == null or xdg_config_home[0] == 0)
            "$HOME/.config/swaylock/config"
        else
            "$XDG_CONFIG_HOME/swaylock/config";
    // sysconfdir path is comptime-known from build options.
    const path3 = opts.sysconfdir ++ "/swaylock/config";
    const config_paths = [_][*c]const u8{
        "$HOME/.swaylock/config",
        path2,
        path3,
    };
    for (config_paths) |cp| {
        var p: c.wordexp_t = undefined;
        if (c.wordexp(cp, &p, 0) == 0) {
            const path = c.strdup(p.we_wordv[0]);
            c.wordfree(&p);
            if (fileExists(path)) return path;
            c.free(path);
        }
    }
    return null;
}

fn loadConfig(
    path: [*c]u8,
    st: *types.SwaylockState,
    line_mode: *LineMode,
) c_int {
    const config = c.fopen(path, "r");
    if (config == null) {
        slog(
            log_err,
            @src(),
            "Failed to read config. Running without it.",
            .{},
        );
        return 0;
    }
    defer _ = c.fclose(config);
    var line: [*c]u8 = null;
    defer c.free(line);
    var line_size: usize = 0;
    var line_number: c_int = 0;
    var result: c_int = 0;
    while (true) {
        const nread = c.getline(&line, &line_size, config);
        if (nread == -1) break;
        line_number += 1;
        var nread_u: usize = @intCast(nread);
        if (line[nread_u - 1] == '\n') {
            nread_u -= 1;
            line[nread_u] = 0;
        }
        if (line[0] == 0 or line[0] == '#') continue;
        slog(
            log_debug,
            @src(),
            "Config Line #{d}: {s}",
            .{ line_number, line },
        );
        const flag: [*c]u8 = @ptrCast(c.malloc(nread_u + 3));
        if (flag == null) {
            slog(log_err, @src(), "Failed to allocate memory", .{});
            return 0;
        }
        _ = c.sprintf(flag, "--%s", line);
        var fake_argv: [2][*c]u8 = .{
            @constCast("swaylock"),
            flag,
        };
        result = parseOptions(2, &fake_argv, st, line_mode, null);
        c.free(flag);
        if (result != 0) break;
    }
    return 0;
}

fn authStateStr(s: types.AuthState) [*c]const u8 {
    if (s == .idle) return "idle";
    if (s == .validating) return "validating";
    if (s == .invalid) return "invalid";
    return "unknown";
}

fn authdStageStr(s: types.AuthdStage) [*c]const u8 {
    if (s == .none) return "none";
    if (s == .broker) return "broker";
    if (s == .auth_mode) return "auth_mode";
    if (s == .challenge) return "challenge";
    return "unknown";
}

fn displayIn(
    fd: c_int,
    mask: c_short,
    data: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = fd;
    _ = mask;
    _ = data;
    if (wl.wl_display_dispatch(state.display) == -1)
        state.run_display = false;
}

fn commIn(
    fd: c_int,
    mask: c_short,
    data: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = fd;
    _ = data;
    if ((mask & wl.POLLERR) != 0) {
        slog(
            log_err,
            @src(),
            "Password checking subprocess crashed; exiting.",
            .{},
        );
        c.exit(c.EXIT_FAILURE);
    }
    if ((mask & wl.POLLIN) == 0) {
        if ((mask & wl.POLLHUP) != 0) {
            slog(
                log_err,
                @src(),
                "Password checking subprocess exited unexpectedly; exiting.",
                .{},
            );
            c.exit(c.EXIT_FAILURE);
        }
        return;
    }
    var payload: [*c]u8 = null;
    var len: usize = 0;
    const msg_type = comm_main_read(&payload, &len);
    defer c.free(payload);
    if (msg_type <= 0) {
        if (msg_type == 0) c.exit(c.EXIT_FAILURE);
        slog(
            log_err,
            @src(),
            "comm_main_read failed; exiting.",
            .{},
        );
        c.exit(c.EXIT_FAILURE);
    }
    slog(
        log_debug,
        @src(),
        "comm_in: msg=0x{x:0>2} len={d} auth={s} stage={s}",
        .{
            msg_type,
            len,
            authStateStr(state.auth_state),
            authdStageStr(state.authd_stage),
        },
    );
    const payload_slice: []const u8 =
        if (payload) |p| p[0..len] else &.{};
    switch (msg_type) {
        types.CommMsg.auth_result => {
            if (len >= 1 and payload != null and payload[0] == 0x01) {
                slog(
                    log_debug,
                    @src(),
                    "comm_in: AUTH_RESULT granted -> unlocking",
                    .{},
                );
                state.run_display = false;
            } else {
                slog(
                    log_debug,
                    @src(),
                    "comm_in: AUTH_RESULT denied auth={s} -> invalid",
                    .{authStateStr(state.auth_state)},
                );
                state.auth_state = .invalid;
                schedule_auth_idle(&state);
                state.failed_attempts += 1;
                damage_state(&state);
            }
        },
        types.CommMsg.brokers => {
            // Parse JSON array [{id, name}, ...]
            authd_brokers_free(
                @ptrCast(state.authd_brokers),
                state.authd_num_brokers,
            );
            state.authd_brokers = null;
            state.authd_num_brokers = 0;
            state.authd_sel_broker = 0;
            parseBrokers(payload_slice);
            state.authd_active = true;
            state.authd_stage = .broker;
            slog(
                log_debug,
                @src(),
                "comm_in: BROKERS n={d} -> stage=broker",
                .{state.authd_num_brokers},
            );
            damage_state(&state);
        },
        types.CommMsg.auth_modes => {
            // Parse JSON array [{id, label}, ...]
            authd_auth_modes_free(
                @ptrCast(state.authd_auth_modes),
                state.authd_num_auth_modes,
            );
            state.authd_auth_modes = null;
            state.authd_num_auth_modes = 0;
            state.authd_sel_auth_mode = 0;
            parseAuthModes(payload_slice);
            state.authd_active = true;
            state.authd_stage = .auth_mode;
            slog(
                log_debug,
                @src(),
                "comm_in: AUTH_MODES n={d} -> stage=auth_mode",
                .{state.authd_num_auth_modes},
            );
            damage_state(&state);
        },
        types.CommMsg.ui_layout => {
            // Parse UILayout JSON object.
            authd_ui_layout_clear(&state.authd_layout);
            c.free(state.authd_error);
            state.authd_error = null;
            parseUiLayout(payload_slice);
            slog(
                log_debug,
                @src(),
                "comm_in: UI_LAYOUT type={s} label={s} entry={s} " ++
                    "wait={d} auth={s} -> idle/challenge",
                .{
                    if (state.authd_layout.type != null)
                        @as([*c]const u8, state.authd_layout.type)
                    else
                        @as([*c]const u8, "(null)"),
                    if (state.authd_layout.label != null)
                        state.authd_layout.label
                    else
                        @as([*c]const u8, "(null)"),
                    if (state.authd_layout.entry != null)
                        state.authd_layout.entry
                    else
                        @as([*c]const u8, "(null)"),
                    @intFromBool(state.authd_layout.wait),
                    authStateStr(state.auth_state),
                },
            );
            state.auth_state = .idle;
            state.authd_stage = .challenge;
            damage_state(&state);
        },
        types.CommMsg.stage => {
            if (len >= 1) {
                const new_stage: types.AuthdStage =
                    @enumFromInt(@as(c_int, payload[0]));
                if (state.auth_state == .validating) {
                    slog(
                        log_debug,
                        @src(),
                        "comm_in: STAGE {s} -> {s} while validating:" ++
                            " auth.Retry assumed, auth=validating -> invalid",
                        .{
                            authdStageStr(state.authd_stage),
                            authdStageStr(new_stage),
                        },
                    );
                    state.auth_state = .invalid;
                    schedule_auth_idle(&state);
                    state.failed_attempts += 1;
                } else {
                    slog(
                        log_debug,
                        @src(),
                        "comm_in: STAGE {s} -> {s} auth={s}",
                        .{
                            authdStageStr(state.authd_stage),
                            authdStageStr(new_stage),
                            authStateStr(state.auth_state),
                        },
                    );
                }
                state.authd_stage = new_stage;
                damage_state(&state);
            }
        },
        types.CommMsg.auth_event => {
            // Intermediate result — show as error/info.
            c.free(state.authd_error);
            state.authd_error = null;
            parseAuthEvent(payload_slice);
            slog(
                log_debug,
                @src(),
                "comm_in: AUTH_EVENT msg={s} auth={s} -> idle",
                .{
                    if (state.authd_error != null)
                        state.authd_error
                    else
                        @as([*c]const u8, "(null)"),
                    authStateStr(state.auth_state),
                },
            );
            state.auth_state = .idle;
            damage_state(&state);
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
    state.authd_brokers = brokers;
    state.authd_num_brokers = @intCast(n);
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
    state.authd_auth_modes = modes;
    state.authd_num_auth_modes = @intCast(n);
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
    state.authd_layout.type =
        if (layout.type) |s| dupStr(s) else null;
    state.authd_layout.label =
        if (layout.label) |s| dupStr(s) else null;
    state.authd_layout.button =
        if (layout.button) |s| dupStr(s) else null;
    state.authd_layout.entry =
        if (layout.entry) |s| dupStr(s) else null;
    state.authd_layout.wait =
        if (layout.wait) |w| std.mem.eql(u8, w, "true") else false;
    state.authd_layout.qr_content =
        if (layout.content) |s| dupStr(s) else null;
    state.authd_layout.qr_code =
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
    state.authd_error =
        if (parsed.value.msg) |s| dupStr(s) else null;
}

fn termIn(
    fd: c_int,
    mask: c_short,
    data: ?*anyopaque,
) callconv(std.builtin.CallingConvention.c) void {
    _ = fd;
    _ = mask;
    _ = data;
    state.run_display = false;
}

// Check for --debug early so the child process also gets the right
// log level before full option parsing runs.
fn logInit(argc: c_int, argv: [*c][*c]u8) void {
    const long_options = [_]c.struct_option{
        .{
            .name = "debug",
            .has_arg = c.no_argument,
            .flag = null,
            .val = 'd',
        },
        .{ .name = null, .has_arg = 0, .flag = null, .val = 0 },
    };
    optind = 1;
    while (true) {
        var opt_idx: c_int = 0;
        const ch = c.getopt_long(
            argc,
            argv,
            "-:d",
            &long_options,
            &opt_idx,
        );
        if (ch == -1) break;
        if (ch == 'd') {
            swaylock_log_init(log_debug);
            return;
        }
    }
    swaylock_log_init(log_err);
}

export fn main(argc: c_int, argv: [*c][*c]u8) c_int {
    logInit(argc, argv);
    initialize_pw_backend(argc, argv);
    _ = c.srand(@intCast(wl.time(null)));

    var line_mode: LineMode = .line;
    state.failed_attempts = 0;
    state.authd_active = false;
    state.authd_stage = .none;
    state.authd_brokers = null;
    state.authd_num_brokers = 0;
    state.authd_sel_broker = -1;
    state.authd_auth_modes = null;
    state.authd_num_auth_modes = 0;
    state.authd_sel_auth_mode = -1;
    state.authd_layout = std.mem.zeroes(types.AuthdUiLayout);
    state.authd_error = null;
    state.args = std.mem.zeroes(types.SwaylockArgs);
    state.args.mode = .fill;
    state.args.font = c.strdup("sans-serif");
    state.args.font_size = 0;
    state.args.radius = 50;
    state.args.thickness = 10;
    state.args.indicator_x_position = 0;
    state.args.indicator_y_position = 0;
    state.args.override_indicator_x_position = false;
    state.args.override_indicator_y_position = false;
    state.args.ignore_empty = false;
    state.args.show_indicator = true;
    state.args.show_caps_lock_indicator = false;
    state.args.show_caps_lock_text = true;
    state.args.show_keyboard_layout = false;
    state.args.hide_keyboard_layout = false;
    state.args.show_failed_attempts = false;
    state.args.indicator_idle_visible = false;
    state.args.ready_fd = -1;
    wl.wl_list_init(&state.images);
    setDefaultColors(&state.args.colors);

    var config_path: [*c]u8 = null;
    var result = parseOptions(argc, argv, null, null, &config_path);
    if (result != 0) {
        c.free(config_path);
        return result;
    }
    if (config_path == null)
        config_path = getConfigPath() orelse null;
    if (config_path != null) {
        slog(
            log_debug,
            @src(),
            "Found config at {s}",
            .{config_path},
        );
        const config_status =
            loadConfig(config_path, &state, &line_mode);
        c.free(config_path);
        if (config_status != 0) {
            c.free(state.args.font);
            return config_status;
        }
    }
    if (argc > 1) {
        slog(log_debug, @src(), "Parsing CLI Args", .{});
        result = parseOptions(argc, argv, &state, &line_mode, null);
        if (result != 0) {
            c.free(state.args.font);
            return result;
        }
    }
    if (line_mode == .inside) {
        state.args.colors.line = state.args.colors.inside;
    } else if (line_mode == .ring) {
        state.args.colors.line = state.args.colors.ring;
    }

    state.password.len = 0;
    state.password.buffer_len = 1024;
    state.password.buffer =
        password_buffer_create(state.password.buffer_len);
    if (state.password.buffer == null) return c.EXIT_FAILURE;
    state.password.buffer[0] = 0;

    if (c.pipe(&sigusr_fds) != 0) {
        slog(log_err, @src(), "Failed to pipe", .{});
        return c.EXIT_FAILURE;
    }
    if (c.fcntl(sigusr_fds[1], c.F_SETFL, c.O_NONBLOCK) == -1) {
        slog(
            log_err,
            @src(),
            "Failed to make pipe end nonblocking",
            .{},
        );
        return c.EXIT_FAILURE;
    }

    wl.wl_list_init(&state.surfaces);
    state.xkb.context =
        types.c.xkb_context_new(types.c.XKB_CONTEXT_NO_FLAGS);
    state.display = wl.wl_display_connect(null);
    if (state.display == null) {
        c.free(state.args.font);
        slog(
            log_err,
            @src(),
            "Unable to connect to the compositor. " ++
                "If your compositor is running, check or set the " ++
                "WAYLAND_DISPLAY environment variable.",
            .{},
        );
        return c.EXIT_FAILURE;
    }
    state.eventloop = loop_create();

    const registry =
        wl.wl_display_get_registry(state.display);
    _ = wl.wl_registry_add_listener(
        registry,
        &registry_listener,
        &state,
    );
    if (wl.wl_display_roundtrip(state.display) == -1) {
        slog(
            log_err,
            @src(),
            "wl_display_roundtrip() failed",
            .{},
        );
        return c.EXIT_FAILURE;
    }

    if (state.compositor == null) {
        slog(log_err, @src(), "Missing wl_compositor", .{});
        return 1;
    }
    if (state.subcompositor == null) {
        slog(log_err, @src(), "Missing wl_subcompositor", .{});
        return 1;
    }
    if (state.shm == null) {
        slog(log_err, @src(), "Missing wl_shm", .{});
        return 1;
    }
    if (state.ext_session_lock_manager_v1 == null) {
        slog(
            log_err,
            @src(),
            "Missing ext-session-lock-v1",
            .{},
        );
        return 1;
    }

    if (state.args.steal_unlock) {
        state.ext_session_lock_v1 =
            wl.ext_session_lock_manager_v1_lock(
                state.ext_session_lock_manager_v1,
            );
        _ = wl.ext_session_lock_v1_add_listener(
            state.ext_session_lock_v1,
            &ext_session_lock_v1_listener,
            &state,
        );
        while (!state.locked and !state.lock_failed) {
            if (wl.wl_display_dispatch(state.display) < 0) {
                slog(
                    log_err,
                    @src(),
                    "wl_display_dispatch() failed",
                    .{},
                );
                return 1;
            }
        }
        if (!state.locked) {
            slog(
                log_err,
                @src(),
                "Compositor refused the lock; " ++
                    "another locker may still be connected.",
                .{},
            );
            return 1;
        }
        wl.ext_session_lock_v1_unlock_and_destroy(
            state.ext_session_lock_v1,
        );
        _ = wl.wl_display_roundtrip(state.display);
        return 0;
    }

    state.ext_session_lock_v1 =
        wl.ext_session_lock_manager_v1_lock(
            state.ext_session_lock_manager_v1,
        );
    _ = wl.ext_session_lock_v1_add_listener(
        state.ext_session_lock_v1,
        &ext_session_lock_v1_listener,
        &state,
    );

    if (wl.wl_display_roundtrip(state.display) == -1) {
        c.free(state.args.font);
        return 1;
    }

    state.test_surface = types.c.cairo_image_surface_create(
        types.c.CAIRO_FORMAT_RGB24,
        1,
        1,
    );
    state.test_cairo = types.c.cairo_create(state.test_surface);

    const head = &state.surfaces;
    var node = head.next;
    while (node != head) {
        const surface =
            wlEntry(types.SwaylockSurface, "link", node.?);
        node = surface.link.next;
        createSurface(surface);
    }

    while (!state.locked) {
        if (wl.wl_display_dispatch(state.display) < 0) {
            slog(
                log_err,
                @src(),
                "wl_display_dispatch() failed",
                .{},
            );
            return 2;
        }
    }

    if (state.args.ready_fd >= 0) {
        if (c.write(state.args.ready_fd, "\n", 1) != 1) {
            slog(
                log_err,
                @src(),
                "Failed to send readiness notification",
                .{},
            );
            return 2;
        }
        _ = c.close(state.args.ready_fd);
        state.args.ready_fd = -1;
    }
    if (state.args.daemonize) daemonize();

    loop_add_fd(
        state.eventloop.?,
        wl.wl_display_get_fd(state.display),
        @as(c_short, @intCast(wl.POLLIN)),
        displayIn,
        null,
    );
    loop_add_fd(
        state.eventloop.?,
        get_comm_reply_fd(),
        @as(c_short, @intCast(wl.POLLIN)),
        commIn,
        null,
    );
    loop_add_fd(
        state.eventloop.?,
        sigusr_fds[0],
        @as(c_short, @intCast(wl.POLLIN)),
        termIn,
        null,
    );

    var sa: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
    sa.__sigaction_handler.sa_handler = doSigusr;
    _ = c.sigemptyset(&sa.sa_mask);
    sa.sa_flags = c.SA_RESTART;
    _ = c.sigaction(c.SIGUSR1, &sa, null);

    if (opts.have_debug_unlock_on_crash) {
        var crash_sa: c.struct_sigaction =
            std.mem.zeroes(c.struct_sigaction);
        crash_sa.__sigaction_handler.sa_handler = debugUnlockOnCrash;
        _ = c.sigemptyset(&crash_sa.sa_mask);
        crash_sa.sa_flags = c.SA_RESETHAND;
        _ = c.sigaction(c.SIGSEGV, &crash_sa, null);
        _ = c.sigaction(c.SIGABRT, &crash_sa, null);
        _ = c.sigaction(c.SIGBUS, &crash_sa, null);
        _ = c.sigaction(c.SIGILL, &crash_sa, null);
        _ = c.sigaction(c.SIGFPE, &crash_sa, null);
        _ = c.atexit(debugUnlockOnExit);
    }

    state.run_display = true;
    while (state.run_display) {
        c.__errno_location().* = 0;
        if (wl.wl_display_flush(state.display) == -1 and
            c.__errno_location().* != c.EAGAIN)
        {
            break;
        }
        loop_poll(state.eventloop.?);
    }

    wl.ext_session_lock_v1_unlock_and_destroy(state.ext_session_lock_v1);
    state.ext_session_lock_v1 = null;
    _ = wl.wl_display_roundtrip(state.display);

    c.free(state.args.font);
    types.c.cairo_destroy(state.test_cairo);
    types.c.cairo_surface_destroy(state.test_surface);
    return 0;
}
