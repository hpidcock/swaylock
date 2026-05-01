//! seat.zig – Zig port of seat.c.
//! Handles Wayland seat events: keyboard input and pointer cursor.

const std = @import("std");
const types = @import("types.zig");
const state = @import("state.zig");

/// Local C imports: only sys/mman.h for mmap/munmap.
/// All Wayland and xkbcommon types are accessed via types.c to
/// ensure struct layout compatibility with types.SwaylockXkb and
/// types.SwaylockSeat.
// Only sys/mman.h needed locally — all xkb/wayland types come from types.c.
const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cInclude("sys/mman.h");
});

const wl = types.c;

const log = @import("log.zig");
const loop = @import("loop.zig");
const password_mod = @import("password.zig");

fn keyboardKeymap(
    data: ?*anyopaque,
    wl_keyboard: ?*types.c.wl_keyboard,
    format: u32,
    fd: i32,
    size: u32,
) callconv(.c) void {
    _ = wl_keyboard;
    const seat: *types.SwaylockSeat = @ptrCast(@alignCast(data.?));
    const g = seat.g.?;
    var keymap: ?*types.c.xkb_keymap = null;
    var xkb_state: ?*types.c.xkb_state = null;
    switch (format) {
        @as(u32, @intCast(
            types.c.WL_KEYBOARD_KEYMAP_FORMAT_NO_KEYMAP,
        )) => {},
        @as(u32, @intCast(
            types.c.WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1,
        )) => {
            const shm_size: usize = @as(usize, size) - 1;
            const raw = c.mmap(
                null,
                shm_size,
                c.PROT_READ,
                c.MAP_PRIVATE,
                fd,
                0,
            );
            // MAP_FAILED is (void*)-1, i.e. all bits set.
            if (raw == null or
                @intFromPtr(raw.?) == std.math.maxInt(usize))
            {
                _ = std.c.close(fd);
                log.slog(
                    log.LogImportance.err,
                    @src(),
                    "Unable to initialise keymap shm, aborting",
                    .{},
                );
                std.process.exit(1);
            }
            const map_shm: [*]const u8 = @ptrCast(raw.?);
            keymap = types.c.xkb_keymap_new_from_buffer(
                g.xkb.context,
                map_shm,
                shm_size,
                types.c.XKB_KEYMAP_FORMAT_TEXT_V1,
                types.c.XKB_KEYMAP_COMPILE_NO_FLAGS,
            );
            std.debug.assert(keymap != null);
            _ = c.munmap(@ptrCast(@constCast(map_shm)), shm_size);
            xkb_state = types.c.xkb_state_new(keymap);
            std.debug.assert(xkb_state != null);
        },
        else => {},
    }
    _ = std.c.close(fd);
    types.c.xkb_keymap_unref(g.xkb.keymap);
    types.c.xkb_state_unref(g.xkb.state);
    g.xkb.keymap = keymap;
    g.xkb.state = xkb_state;
}

fn keyboardEnter(
    data: ?*anyopaque,
    wl_keyboard: ?*types.c.wl_keyboard,
    serial: u32,
    surface: ?*types.c.wl_surface,
    keys: ?*types.c.wl_array,
) callconv(.c) void {
    _ = data;
    _ = wl_keyboard;
    _ = serial;
    _ = surface;
    _ = keys;
}

fn keyboardLeave(
    data: ?*anyopaque,
    wl_keyboard: ?*types.c.wl_keyboard,
    serial: u32,
    surface: ?*types.c.wl_surface,
) callconv(.c) void {
    _ = data;
    _ = wl_keyboard;
    _ = serial;
    _ = surface;
}

fn keyboardRepeat(data: ?*anyopaque) callconv(.c) void {
    const seat: *types.SwaylockSeat = @ptrCast(@alignCast(data.?));
    const g = seat.g.?;
    seat.repeat_timer = loop.loopAddTimer(
        g.eventloop.?,
        seat.repeat_period_ms,
        keyboardRepeat,
        seat,
    );
    password_mod.swaylockHandleKey(g, seat.repeat_sym, seat.repeat_codepoint);
}

fn keyboardKey(
    data: ?*anyopaque,
    wl_keyboard: ?*types.c.wl_keyboard,
    serial: u32,
    time: u32,
    key: u32,
    key_state_raw: u32,
) callconv(.c) void {
    _ = wl_keyboard;
    _ = serial;
    _ = time;
    const seat: *types.SwaylockSeat = @ptrCast(@alignCast(data.?));
    const g = seat.g.?;
    if (g.xkb.state == null) return;
    const pressed = @as(
        u32,
        @intCast(types.c.WL_KEYBOARD_KEY_STATE_PRESSED),
    );
    const sym = types.c.xkb_state_key_get_one_sym(
        g.xkb.state,
        key + 8,
    );
    const keycode: u32 = if (key_state_raw == pressed) key + 8 else 0;
    const codepoint = types.c.xkb_state_key_get_utf32(
        g.xkb.state,
        keycode,
    );
    if (key_state_raw == pressed)
        password_mod.swaylockHandleKey(g, sym, codepoint);
    if (seat.repeat_timer != null) {
        _ = loop.loopRemoveTimer(
            g.eventloop.?,
            seat.repeat_timer.?,
        );
        seat.repeat_timer = null;
    }
    if (key_state_raw == pressed and seat.repeat_period_ms > 0) {
        seat.repeat_sym = sym;
        seat.repeat_codepoint = codepoint;
        seat.repeat_timer = loop.loopAddTimer(
            g.eventloop.?,
            seat.repeat_delay_ms,
            keyboardRepeat,
            seat,
        );
    }
}

fn keyboardModifiers(
    data: ?*anyopaque,
    wl_keyboard: ?*types.c.wl_keyboard,
    serial: u32,
    mods_depressed: u32,
    mods_latched: u32,
    mods_locked: u32,
    group: u32,
) callconv(.c) void {
    _ = wl_keyboard;
    _ = serial;
    const seat: *types.SwaylockSeat = @ptrCast(@alignCast(data.?));
    const g = seat.g.?;
    if (g.xkb.state == null) return;
    const layout_same = types.c.xkb_state_layout_index_is_active(
        g.xkb.state,
        group,
        types.c.XKB_STATE_LAYOUT_EFFECTIVE,
    );
    _ = types.c.xkb_state_update_mask(
        g.xkb.state,
        mods_depressed,
        mods_latched,
        mods_locked,
        0,
        0,
        group,
    );
    const caps_lock_int = types.c.xkb_state_mod_name_is_active(
        g.xkb.state,
        types.c.XKB_MOD_NAME_CAPS,
        types.c.XKB_STATE_MODS_LOCKED,
    );
    const caps_lock = caps_lock_int != 0;
    if (caps_lock != g.xkb.caps_lock or layout_same == 0) {
        g.xkb.caps_lock = caps_lock;
        state.damageState(g);
    }
    g.xkb.control = types.c.xkb_state_mod_name_is_active(
        g.xkb.state,
        types.c.XKB_MOD_NAME_CTRL,
        types.c.XKB_STATE_MODS_DEPRESSED |
            types.c.XKB_STATE_MODS_LATCHED,
    ) != 0;
}

fn keyboardRepeatInfo(
    data: ?*anyopaque,
    wl_keyboard: ?*types.c.wl_keyboard,
    rate: i32,
    delay: i32,
) callconv(.c) void {
    _ = wl_keyboard;
    const seat: *types.SwaylockSeat = @ptrCast(@alignCast(data.?));
    if (rate <= 0) {
        seat.repeat_period_ms = -1;
    } else {
        // Keys per second -> milliseconds between keys.
        seat.repeat_period_ms = @divTrunc(1000, rate);
    }
    seat.repeat_delay_ms = delay;
}

const keyboard_listener: types.c.wl_keyboard_listener = .{
    .keymap = keyboardKeymap,
    .enter = keyboardEnter,
    .leave = keyboardLeave,
    .key = keyboardKey,
    .modifiers = keyboardModifiers,
    .repeat_info = keyboardRepeatInfo,
};

fn pointerEnter(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    serial: u32,
    surface: ?*types.c.wl_surface,
    surface_x: types.c.wl_fixed_t,
    surface_y: types.c.wl_fixed_t,
) callconv(.c) void {
    _ = data;
    _ = surface;
    _ = surface_x;
    _ = surface_y;
    types.c.wl_pointer_set_cursor(wl_pointer, serial, null, 0, 0);
}

fn pointerLeave(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    serial: u32,
    surface: ?*types.c.wl_surface,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = serial;
    _ = surface;
}

fn pointerMotion(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    time: u32,
    surface_x: types.c.wl_fixed_t,
    surface_y: types.c.wl_fixed_t,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = time;
    _ = surface_x;
    _ = surface_y;
}

fn pointerButton(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    serial: u32,
    time: u32,
    button: u32,
    button_state: u32,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = serial;
    _ = time;
    _ = button;
    _ = button_state;
}

fn pointerAxis(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    time: u32,
    axis: u32,
    value: types.c.wl_fixed_t,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = time;
    _ = axis;
    _ = value;
}

fn pointerFrame(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
}

fn pointerAxisSource(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    axis_source: u32,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = axis_source;
}

fn pointerAxisStop(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    time: u32,
    axis: u32,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = time;
    _ = axis;
}

fn pointerAxisDiscrete(
    data: ?*anyopaque,
    wl_pointer: ?*types.c.wl_pointer,
    axis: u32,
    discrete: i32,
) callconv(.c) void {
    _ = data;
    _ = wl_pointer;
    _ = axis;
    _ = discrete;
}

const pointer_listener: types.c.wl_pointer_listener = .{
    .enter = pointerEnter,
    .leave = pointerLeave,
    .motion = pointerMotion,
    .button = pointerButton,
    .axis = pointerAxis,
    .frame = pointerFrame,
    .axis_source = pointerAxisSource,
    .axis_stop = pointerAxisStop,
    .axis_discrete = pointerAxisDiscrete,
};

fn seatHandleCapabilities(
    data: ?*anyopaque,
    wl_seat: ?*types.c.wl_seat,
    caps: u32,
) callconv(.c) void {
    const seat: *types.SwaylockSeat = @ptrCast(@alignCast(data.?));
    if (seat.pointer != null) {
        types.c.wl_pointer_release(seat.pointer);
        seat.pointer = null;
    }
    if (seat.keyboard != null) {
        types.c.wl_keyboard_release(seat.keyboard);
        seat.keyboard = null;
    }
    if (caps & @as(
        u32,
        @intCast(types.c.WL_SEAT_CAPABILITY_POINTER),
    ) != 0) {
        seat.pointer = types.c.wl_seat_get_pointer(wl_seat);
        _ = types.c.wl_pointer_add_listener(
            seat.pointer,
            &pointer_listener,
            null,
        );
    }
    if (caps & @as(
        u32,
        @intCast(types.c.WL_SEAT_CAPABILITY_KEYBOARD),
    ) != 0) {
        seat.keyboard = types.c.wl_seat_get_keyboard(wl_seat);
        _ = types.c.wl_keyboard_add_listener(
            seat.keyboard,
            &keyboard_listener,
            seat,
        );
    }
}

fn seatHandleName(
    data: ?*anyopaque,
    wl_seat: ?*types.c.wl_seat,
    name: [*c]const u8,
) callconv(.c) void {
    _ = data;
    _ = wl_seat;
    _ = name;
}

/// Public seat listener; referenced from main.zig.
pub var seatListener: types.c.wl_seat_listener = .{
    .capabilities = seatHandleCapabilities,
    .name = seatHandleName,
};
