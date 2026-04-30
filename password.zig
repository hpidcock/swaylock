//! password.zig – Zig port of password.c and password-buffer.c.
//! Manages the locked password buffer and keyboard input handling.

const std = @import("std");
const types = @import("types");

// Only stdlib/mmap/unistd needed locally — xkb constants come from types.c.
const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    @cInclude("stdlib.h");
    @cInclude("sys/mman.h");
    @cInclude("unistd.h");
});

const wl = types.c;

const log_err: i32 = @intFromEnum(types.LogImportance.err);
const log_debug: i32 = @intFromEnum(types.LogImportance.debug);

extern fn _swaylock_log(verbosity: i32, fmt: [*c]const u8, ...) void;
extern fn _swaylock_strip_path(
    filepath: [*c]const u8,
) [*c]const u8;
extern fn comm_main_write(
    msg_type: u8,
    payload: ?[*]const u8,
    len: usize,
) bool;
extern fn write_comm_password(pw: *types.SwaylockPassword) bool;
extern fn loop_add_timer(
    loop: *types.Loop,
    ms: i32,
    callback: types.TimerCallback,
    data: ?*anyopaque,
) ?*types.LoopTimer;
extern fn loop_remove_timer(
    loop: *types.Loop,
    timer: *types.LoopTimer,
) bool;
extern fn damage_state(state: *types.SwaylockState) void;
extern fn utf8_last_size(str: [*c]const u8) i32;
extern fn utf8_chsize(ch: u32) usize;
extern fn utf8_encode(str: [*c]u8, ch: u32) usize;

// ── logging helpers ──────────────────────────────────────────────────

fn slog(
    verbosity: i32,
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
    verbosity: i32,
    src: std.builtin.SourceLocation,
    comptime fmt: []const u8,
) void {
    const err_num = std.c._errno().*;
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(
        &buf,
        fmt ++ ": errno {d}",
        .{err_num},
    ) catch return;
    _swaylock_log(
        verbosity,
        "[%s:%d] %s",
        _swaylock_strip_path(src.file.ptr),
        @as(c_int, @intCast(src.line)),
        msg.ptr,
    );
}

// ── password-buffer ──────────────────────────────────────────────────

var mlock_supported: bool = true;

/// Expects addr to be page-aligned.
fn passwordBufferLock(addr: [*]u8, size: usize) bool {
    var retries: i32 = 5;
    while (c.mlock(@ptrCast(addr), size) != 0 and retries > 0) {
        const err = std.c._errno().*;
        if (err == @intFromEnum(std.posix.E.AGAIN)) {
            retries -= 1;
            if (retries == 0) {
                slog(
                    log_err,
                    @src(),
                    "mlock() supported but failed too often.",
                    .{},
                );
                return false;
            }
        } else if (err == @intFromEnum(std.posix.E.PERM)) {
            slogErrno(
                log_err,
                @src(),
                "Unable to mlock() password memory: Unsupported!",
            );
            mlock_supported = false;
            return true;
        } else {
            slogErrno(
                log_err,
                @src(),
                "Unable to mlock() password memory.",
            );
            return false;
        }
    }
    return true;
}

/// Expects addr to be page-aligned.
fn passwordBufferUnlock(addr: [*]u8, size: usize) bool {
    if (mlock_supported) {
        if (c.munlock(@ptrCast(addr), size) != 0) {
            slogErrno(
                log_err,
                @src(),
                "Unable to munlock() password memory.",
            );
            return false;
        }
    }
    return true;
}

export fn password_buffer_create(size: usize) ?[*]u8 {
    var buffer: ?*anyopaque = null;
    // posix_memalign requires page-size alignment; use sysconf to
    // retrieve the runtime page size portably.
    const page_size: usize = @intCast(c.sysconf(c._SC_PAGESIZE));
    const result = c.posix_memalign(
        &buffer,
        page_size,
        size,
    );
    if (result != 0) {
        // posix_memalign does not set errno per the man page.
        std.c._errno().* = result;
        slogErrno(
            log_err,
            @src(),
            "failed to alloc password buffer",
        );
        return null;
    }
    const buf: [*]u8 = @ptrCast(buffer.?);
    if (!passwordBufferLock(buf, size)) {
        c.free(buffer);
        return null;
    }
    return buf;
}

export fn password_buffer_destroy(buffer: ?[*]u8, size: usize) void {
    clear_buffer(buffer, size);
    _ = passwordBufferUnlock(buffer.?, size);
    c.free(@ptrCast(buffer));
}

// ── buffer helpers ───────────────────────────────────────────────────

/// Clears a buffer using volatile writes so the compiler cannot
/// optimise the zeroing away.
export fn clear_buffer(buf: ?[*]u8, size: usize) void {
    const vbuf: [*]volatile u8 = @ptrCast(buf.?);
    for (0..size) |i|
        vbuf[i] = 0;
}

export fn clear_password_buffer(pw: *types.SwaylockPassword) void {
    clear_buffer(pw.buffer, pw.buffer_len);
    pw.len = 0;
}

fn backspace(pw: *types.SwaylockPassword) bool {
    if (pw.len != 0) {
        const last: i32 = utf8_last_size(@ptrCast(pw.buffer));
        pw.len -= @intCast(last);
        pw.buffer.?[@intCast(pw.len)] = 0;
        return true;
    }
    return false;
}

fn appendCh(pw: *types.SwaylockPassword, codepoint: u32) void {
    const utf8_size: usize = utf8_chsize(codepoint);
    const len: usize = @intCast(pw.len);
    if (len + utf8_size + 1 >= pw.buffer_len)
        return;
    _ = utf8_encode(@ptrCast(&pw.buffer.?[len]), codepoint);
    pw.buffer.?[len + utf8_size] = 0;
    pw.len += @intCast(utf8_size);
}

// ── timer callbacks ──────────────────────────────────────────────────

fn setInputIdle(data: ?*anyopaque) callconv(.c) void {
    const state: *types.SwaylockState = @ptrCast(@alignCast(data));
    state.input_idle_timer = null;
    state.input_state = types.InputState.idle;
    damage_state(state);
}

fn setAuthIdle(data: ?*anyopaque) callconv(.c) void {
    const state: *types.SwaylockState = @ptrCast(@alignCast(data));
    state.auth_idle_timer = null;
    state.auth_state = types.AuthState.idle;
    damage_state(state);
}

fn scheduleInputIdle(state: *types.SwaylockState) void {
    if (state.input_idle_timer != null)
        _ = loop_remove_timer(
            state.eventloop.?,
            state.input_idle_timer.?,
        );
    state.input_idle_timer = loop_add_timer(
        state.eventloop.?,
        1500,
        setInputIdle,
        state,
    );
}

fn cancelInputIdle(state: *types.SwaylockState) void {
    if (state.input_idle_timer != null) {
        _ = loop_remove_timer(
            state.eventloop.?,
            state.input_idle_timer.?,
        );
        state.input_idle_timer = null;
    }
}

export fn schedule_auth_idle(state: *types.SwaylockState) void {
    if (state.auth_idle_timer != null)
        _ = loop_remove_timer(
            state.eventloop.?,
            state.auth_idle_timer.?,
        );
    state.auth_idle_timer = loop_add_timer(
        state.eventloop.?,
        3000,
        setAuthIdle,
        state,
    );
}

fn clearPassword(data: ?*anyopaque) callconv(.c) void {
    const state: *types.SwaylockState = @ptrCast(@alignCast(data));
    state.clear_password_timer = null;
    state.input_state = types.InputState.clear;
    scheduleInputIdle(state);
    clear_password_buffer(&state.password);
    damage_state(state);
}

fn schedulePasswordClear(state: *types.SwaylockState) void {
    if (state.clear_password_timer != null)
        _ = loop_remove_timer(
            state.eventloop.?,
            state.clear_password_timer.?,
        );
    state.clear_password_timer = loop_add_timer(
        state.eventloop.?,
        10000,
        clearPassword,
        state,
    );
}

fn cancelPasswordClear(state: *types.SwaylockState) void {
    if (state.clear_password_timer != null) {
        _ = loop_remove_timer(
            state.eventloop.?,
            state.clear_password_timer.?,
        );
        state.clear_password_timer = null;
    }
}

// ── submit / highlight ───────────────────────────────────────────────

fn submitPassword(state: *types.SwaylockState) void {
    if (state.args.ignore_empty and state.password.len == 0) {
        slog(
            log_debug,
            @src(),
            "submit_password: skipped (ignore_empty)",
            .{},
        );
        return;
    }
    if (state.auth_state == types.AuthState.validating) {
        slog(
            log_debug,
            @src(),
            "submit_password: skipped (already validating)",
            .{},
        );
        return;
    }
    slog(
        log_debug,
        @src(),
        "submit_password: sending (len={d}) auth=idle -> validating",
        .{state.password.len},
    );
    state.input_state = types.InputState.idle;
    state.auth_state = types.AuthState.validating;
    cancelPasswordClear(state);
    cancelInputIdle(state);
    if (!write_comm_password(&state.password)) {
        slog(
            log_debug,
            @src(),
            "submit_password: write failed auth=validating -> invalid",
            .{},
        );
        state.auth_state = types.AuthState.invalid;
        schedule_auth_idle(state);
    }
    damage_state(state);
}

fn updateHighlight(state: *types.SwaylockState) void {
    // Advance a random amount between 1/4 and 3/4 of a full turn.
    state.highlight_start =
        (state.highlight_start +
            @as(u32, @intCast(@rem(c.rand(), 1024))) + 512) % 2048;
}

// ── key handler ──────────────────────────────────────────────────────

export fn swaylock_handle_key(
    state: *types.SwaylockState,
    keysym: wl.xkb_keysym_t,
    codepoint: u32,
) void {
    // In broker or auth-mode selection, Up/Down navigate the list
    // and Enter confirms. Tab presses the optional button.
    if (state.authd_active) {
        if (state.authd_stage == types.AuthdStage.broker or
            state.authd_stage == types.AuthdStage.auth_mode)
        {
            const is_broker =
                state.authd_stage == types.AuthdStage.broker;
            if (keysym == wl.XKB_KEY_Up) {
                if (is_broker) {
                    if (state.authd_sel_broker > 0)
                        state.authd_sel_broker -= 1;
                } else {
                    if (state.authd_sel_auth_mode > 0)
                        state.authd_sel_auth_mode -= 1;
                }
                damage_state(state);
                return;
            } else if (keysym == wl.XKB_KEY_Down) {
                if (is_broker) {
                    if (state.authd_sel_broker <
                        state.authd_num_brokers - 1)
                        state.authd_sel_broker += 1;
                } else {
                    if (state.authd_sel_auth_mode <
                        state.authd_num_auth_modes - 1)
                        state.authd_sel_auth_mode += 1;
                }
                damage_state(state);
                return;
            } else if (keysym == wl.XKB_KEY_Return or
                keysym == wl.XKB_KEY_KP_Enter)
            {
                if (is_broker) {
                    const sel = state.authd_sel_broker;
                    if (sel >= 0 and sel < state.authd_num_brokers) {
                        const id =
                            state.authd_brokers.?[@intCast(sel)].id;
                        if (id != null)
                            _ = comm_main_write(
                                types.CommMsg.broker_sel,
                                id,
                                std.mem.len(id.?) + 1,
                            );
                    }
                } else {
                    const sel = state.authd_sel_auth_mode;
                    if (sel >= 0 and
                        sel < state.authd_num_auth_modes)
                    {
                        const id =
                            state.authd_auth_modes.?[
                                @intCast(sel)
                            ].id;
                        if (id != null)
                            _ = comm_main_write(
                                types.CommMsg.auth_mode_sel,
                                id,
                                std.mem.len(id.?) + 1,
                            );
                    }
                }
                return;
            } else if (keysym == wl.XKB_KEY_Escape) {
                _ = comm_main_write(types.CommMsg.cancel, null, 0);
                return;
            }
        }
        if (state.authd_stage == types.AuthdStage.challenge) {
            if (keysym == wl.XKB_KEY_Tab and
                state.authd_layout.button != null)
            {
                _ = comm_main_write(types.CommMsg.button, null, 0);
                damage_state(state);
                return;
            }
        }
    }

    if (keysym == wl.XKB_KEY_KP_Enter or keysym == wl.XKB_KEY_Return) {
        submitPassword(state);
    } else if (keysym == wl.XKB_KEY_Delete or
        keysym == wl.XKB_KEY_BackSpace)
    {
        if (state.xkb.control) {
            clear_password_buffer(&state.password);
            state.input_state = types.InputState.clear;
            cancelPasswordClear(state);
        } else if (backspace(&state.password) and
            state.password.len != 0)
        {
            state.input_state = types.InputState.backspace;
            schedulePasswordClear(state);
            updateHighlight(state);
        } else {
            state.input_state = types.InputState.clear;
            cancelPasswordClear(state);
        }
        scheduleInputIdle(state);
        damage_state(state);
    } else if (keysym == wl.XKB_KEY_Escape) {
        clear_password_buffer(&state.password);
        state.input_state = types.InputState.clear;
        cancelPasswordClear(state);
        scheduleInputIdle(state);
        damage_state(state);
    } else if (keysym == wl.XKB_KEY_Caps_Lock or
        keysym == wl.XKB_KEY_Shift_L or
        keysym == wl.XKB_KEY_Shift_R or
        keysym == wl.XKB_KEY_Control_L or
        keysym == wl.XKB_KEY_Control_R or
        keysym == wl.XKB_KEY_Meta_L or
        keysym == wl.XKB_KEY_Meta_R or
        keysym == wl.XKB_KEY_Alt_L or
        keysym == wl.XKB_KEY_Alt_R or
        keysym == wl.XKB_KEY_Super_L or
        keysym == wl.XKB_KEY_Super_R)
    {
        state.input_state = types.InputState.neutral;
        schedulePasswordClear(state);
        scheduleInputIdle(state);
        damage_state(state);
    } else if ((keysym == wl.XKB_KEY_m or
        keysym == wl.XKB_KEY_d or
        keysym == wl.XKB_KEY_j) and state.xkb.control)
    {
        submitPassword(state);
    } else if ((keysym == wl.XKB_KEY_c or
        keysym == wl.XKB_KEY_u) and state.xkb.control)
    {
        clear_password_buffer(&state.password);
        state.input_state = types.InputState.clear;
        cancelPasswordClear(state);
        scheduleInputIdle(state);
        damage_state(state);
    } else {
        if (codepoint != 0) {
            appendCh(&state.password, codepoint);
            state.input_state = types.InputState.letter;
            schedulePasswordClear(state);
            scheduleInputIdle(state);
            updateHighlight(state);
            damage_state(state);
        }
    }
}
