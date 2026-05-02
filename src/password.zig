//! Password buffer management and keyboard input handling.

const std = @import("std");
const types = @import("types.zig");
const state = @import("state.zig");

const wl = types.c;

const log = @import("log.zig");
const loop = @import("loop.zig");
const comm = @import("comm.zig");
const password_buffer = @import("password_buffer.zig");
const unicode_mod = @import("unicode.zig");

const zero: []const u8 = ""[0..0];

fn backspace(pw: *types.SwaylockPassword) bool {
    if (pw.len != 0) {
        const last: i32 = unicode_mod.utf8LastSize(
            @ptrCast(pw.buffer.?),
        );
        pw.len -= @intCast(last);
        pw.buffer.?[@intCast(pw.len)] = 0;
        return true;
    }
    return false;
}

fn appendCh(pw: *types.SwaylockPassword, codepoint: u32) void {
    const utf8_size: usize = unicode_mod.utf8Chsize(codepoint);
    const len: usize = @intCast(pw.len);
    if (len + utf8_size + 1 >= pw.buffer.?.len)
        return;
    _ = unicode_mod.utf8Encode(
        pw.buffer.?[len..],
        codepoint,
    );
    pw.buffer.?[len + utf8_size] = 0;
    pw.len += @intCast(utf8_size);
}

fn setInputIdle(data: ?*anyopaque) callconv(.c) void {
    const g: *types.State = @ptrCast(@alignCast(data));
    g.input_idle_timer = null;
    g.input_state = types.InputState.idle;
    state.damageState(g);
}

fn setAuthIdle(data: ?*anyopaque) callconv(.c) void {
    const g: *types.State = @ptrCast(@alignCast(data));
    g.auth_idle_timer = null;
    g.auth_state = types.AuthState.idle;
    state.damageState(g);
}

fn scheduleInputIdle(g: *types.State) void {
    if (g.input_idle_timer != null)
        _ = loop.loopRemoveTimer(
            g.eventloop.?,
            g.input_idle_timer.?,
        );
    g.input_idle_timer = loop.loopAddTimer(
        g.eventloop.?,
        1500,
        setInputIdle,
        g,
    );
}

fn cancelInputIdle(g: *types.State) void {
    if (g.input_idle_timer != null) {
        _ = loop.loopRemoveTimer(
            g.eventloop.?,
            g.input_idle_timer.?,
        );
        g.input_idle_timer = null;
    }
}

pub fn scheduleAuthIdle(g: *types.State) void {
    if (g.auth_idle_timer != null)
        _ = loop.loopRemoveTimer(
            g.eventloop.?,
            g.auth_idle_timer.?,
        );
    g.auth_idle_timer = loop.loopAddTimer(
        g.eventloop.?,
        3000,
        setAuthIdle,
        g,
    );
}

fn clearPassword(data: ?*anyopaque) callconv(.c) void {
    const g: *types.State = @ptrCast(@alignCast(data));
    g.clear_password_timer = null;
    g.input_state = types.InputState.clear;
    scheduleInputIdle(g);
    password_buffer.clear(&g.password);
    state.damageState(g);
}

fn schedulePasswordClear(g: *types.State) void {
    if (g.clear_password_timer != null)
        _ = loop.loopRemoveTimer(
            g.eventloop.?,
            g.clear_password_timer.?,
        );
    g.clear_password_timer = loop.loopAddTimer(
        g.eventloop.?,
        10000,
        clearPassword,
        g,
    );
}

fn cancelPasswordClear(g: *types.State) void {
    if (g.clear_password_timer != null) {
        _ = loop.loopRemoveTimer(
            g.eventloop.?,
            g.clear_password_timer.?,
        );
        g.clear_password_timer = null;
    }
}

fn submitPassword(g: *types.State) void {
    if (g.args.ignore_empty and g.password.len == 0) {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "submit_password: skipped (ignore_empty)",
            .{},
        );
        return;
    }
    if (g.auth_state == types.AuthState.validating) {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "submit_password: skipped (already validating)",
            .{},
        );
        return;
    }
    log.slog(
        log.LogImportance.debug,
        @src(),
        "submit_password: sending (len={d}) auth=idle -> validating",
        .{g.password.len},
    );
    g.input_state = types.InputState.idle;
    g.auth_state = types.AuthState.validating;
    cancelPasswordClear(g);
    cancelInputIdle(g);
    if (!comm.writeCommPassword(&g.password)) {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "submit_password: write failed auth=validating -> invalid",
            .{},
        );
        g.auth_state = types.AuthState.invalid;
        scheduleAuthIdle(g);
    }
    state.damageState(g);
}

fn updateHighlight(g: *types.State) void {
    const r = std.crypto.random.int(u32) % 1024;
    g.highlight_start =
        (g.highlight_start + r + 512) % 2048;
}

pub fn swaylockHandleKey(
    g: *types.State,
    keysym: wl.xkb_keysym_t,
    codepoint: u32,
) void {
    // Broker/auth-mode selection: Up/Down navigate, Enter
    // confirms, Tab presses the optional button.
    if (g.authd_active) {
        if (g.authd_stage == types.AuthdStage.broker or
            g.authd_stage == types.AuthdStage.auth_mode)
        {
            const is_broker =
                g.authd_stage == types.AuthdStage.broker;
            if (keysym == wl.XKB_KEY_Up) {
                if (is_broker) {
                    if (g.authd_sel_broker > 0)
                        g.authd_sel_broker -= 1;
                } else {
                    if (g.authd_sel_auth_mode > 0)
                        g.authd_sel_auth_mode -= 1;
                }
                state.damageState(g);
                return;
            } else if (keysym == wl.XKB_KEY_Down) {
                if (is_broker) {
                    if (g.authd_sel_broker + 1 <
                        @as(i32, @intCast(g.authd_brokers.len)))
                        g.authd_sel_broker += 1;
                } else {
                    if (g.authd_sel_auth_mode + 1 <
                        @as(i32, @intCast(g.authd_auth_modes.len)))
                        g.authd_sel_auth_mode += 1;
                }
                state.damageState(g);
                return;
            } else if (keysym == wl.XKB_KEY_Return or
                keysym == wl.XKB_KEY_KP_Enter)
            {
                if (is_broker) {
                    const sel = g.authd_sel_broker;
                    if (sel >= 0 and
                        @as(usize, @intCast(sel)) < g.authd_brokers.len)
                    {
                        const id =
                            g.authd_brokers[@intCast(sel)].id;
                        if (id != null)
                            _ = comm.commMainWrite(
                                types.CommMsg.broker_sel,
                                id.?[0 .. std.mem.len(id.?) + 1],
                            );
                    }
                } else {
                    const sel = g.authd_sel_auth_mode;
                    if (sel >= 0 and
                        @as(usize, @intCast(sel)) < g.authd_auth_modes.len)
                    {
                        const id =
                            g.authd_auth_modes[@intCast(sel)].id;
                        if (id != null)
                            _ = comm.commMainWrite(
                                types.CommMsg.auth_mode_sel,
                                id.?[0 .. std.mem.len(id.?) + 1],
                            );
                    }
                }
                return;
            } else if (keysym == wl.XKB_KEY_Escape) {
                _ = comm.commMainWrite(
                    types.CommMsg.cancel,
                    zero,
                );
                return;
            }
        }
        if (g.authd_stage == types.AuthdStage.challenge) {
            if (keysym == wl.XKB_KEY_Tab and
                g.authd_layout.button != null)
            {
                _ = comm.commMainWrite(types.CommMsg.button, zero);
                state.damageState(g);
                return;
            }
        }
    }

    if (keysym == wl.XKB_KEY_KP_Enter or keysym == wl.XKB_KEY_Return) {
        submitPassword(g);
    } else if (keysym == wl.XKB_KEY_Delete or
        keysym == wl.XKB_KEY_BackSpace)
    {
        if (g.xkb.control) {
            password_buffer.clear(&g.password);
            g.input_state = types.InputState.clear;
            cancelPasswordClear(g);
        } else if (backspace(&g.password) and
            g.password.len != 0)
        {
            g.input_state = types.InputState.backspace;
            schedulePasswordClear(g);
            updateHighlight(g);
        } else {
            g.input_state = types.InputState.clear;
            cancelPasswordClear(g);
        }
        scheduleInputIdle(g);
        state.damageState(g);
    } else if (keysym == wl.XKB_KEY_Escape) {
        password_buffer.clear(&g.password);
        g.input_state = types.InputState.clear;
        cancelPasswordClear(g);
        scheduleInputIdle(g);
        state.damageState(g);
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
        g.input_state = types.InputState.neutral;
        schedulePasswordClear(g);
        scheduleInputIdle(g);
        state.damageState(g);
    } else if ((keysym == wl.XKB_KEY_m or
        keysym == wl.XKB_KEY_d or
        keysym == wl.XKB_KEY_j) and g.xkb.control)
    {
        submitPassword(g);
    } else if ((keysym == wl.XKB_KEY_c or
        keysym == wl.XKB_KEY_u) and g.xkb.control)
    {
        password_buffer.clear(&g.password);
        g.input_state = types.InputState.clear;
        cancelPasswordClear(g);
        scheduleInputIdle(g);
        state.damageState(g);
    } else {
        if (codepoint != 0) {
            appendCh(&g.password, codepoint);
            g.input_state = types.InputState.letter;
            schedulePasswordClear(g);
            scheduleInputIdle(g);
            updateHighlight(g);
            state.damageState(g);
        }
    }
}
