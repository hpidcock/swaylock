//! Main rendering module for the swaylock lock indicator.
//! Manages background compositing, indicator ring drawing,
//! text overlays, QR codes, and authd UI elements via Cairo.

const std = @import("std");
const math = std.math;
const opts = @import("render_options");
const allocator_mod = @import("allocator");
const types = @import("types.zig");

const wl = types.c;
const qrencode = if (opts.have_qrencode) @cImport({
    @cInclude("qrencode.h");
}) else struct {};

const log = @import("log.zig");
const background_image = @import("background-image.zig");
const cairo_mod = @import("cairo.zig");
const pool_buffer = @import("pool-buffer.zig");

const pi: f64 = math.pi;
/// Arc span of the typing highlight (60 degrees).
const type_indicator_range: f64 = pi / 3.0;
/// Colour used for authd error text (red, fully opaque).
const error_text_color: u32 = 0xFF4444FF;

/// Shorthand: cast any integer to f64 for Cairo coordinates.
inline fn fd(x: anytype) f64 {
    return @floatFromInt(x);
}

fn set_color_for_state(
    cairo: ?*wl.cairo_t,
    state: *types.State,
    colorset: *types.SwaylockColorSet,
) void {
    if (state.input_state == types.InputState.clear) {
        cairo_mod.cairoSetSourceU32(cairo, colorset.cleared);
    } else if (state.auth_state == types.AuthState.validating) {
        cairo_mod.cairoSetSourceU32(cairo, colorset.verifying);
    } else if (state.auth_state == types.AuthState.invalid) {
        cairo_mod.cairoSetSourceU32(cairo, colorset.wrong);
    } else if (state.xkb.caps_lock and
        state.args.show_caps_lock_indicator)
    {
        cairo_mod.cairoSetSourceU32(cairo, colorset.caps_lock);
    } else if (state.xkb.caps_lock and
        !state.args.show_caps_lock_indicator and
        state.args.show_caps_lock_text)
    {
        const saved = state.args.colors.text.input;
        state.args.colors.text.input =
            state.args.colors.text.caps_lock;
        cairo_mod.cairoSetSourceU32(cairo, colorset.input);
        state.args.colors.text.input = saved;
    } else {
        cairo_mod.cairoSetSourceU32(cairo, colorset.input);
    }
}

fn surface_frame_handle_done(
    data: ?*anyopaque,
    callback: ?*wl.wl_callback,
    time: u32,
) callconv(std.builtin.CallingConvention.c) void {
    _ = time;
    const surface: *types.Surface =
        @ptrCast(@alignCast(data));
    wl.wl_callback_destroy(callback);
    surface.frame = null;
    render(surface);
}

const surface_frame_listener: wl.wl_callback_listener = .{
    .done = surface_frame_handle_done,
};

fn render_debug_overlay(surface: *types.Surface) void {
    // Body is comptime-gated; overlay-only Surface fields are
    // safe because Zig skips unreachable comptime branches.
    if (comptime opts.have_debug_overlay) {
        const state: *types.State = surface.g.?;
        if (surface.width == 0 or surface.height == 0) return;

        var count: i32 = 0;
        const lines = log.getOverlay(&count);
        if (count == 0) return;

        const font_size: f64 = fd(surface.scale) * 12.0;
        wl.cairo_select_font_face(
            state.test_cairo,
            @ptrCast(state.args.font),
            wl.CAIRO_FONT_SLANT_NORMAL,
            wl.CAIRO_FONT_WEIGHT_NORMAL,
        );
        wl.cairo_set_font_size(state.test_cairo, font_size);
        var fe: wl.cairo_font_extents_t = undefined;
        wl.cairo_font_extents(state.test_cairo, &fe);

        const pad: f64 = fd(surface.scale) * 4.0;
        const line_h: i32 = @intFromFloat(@ceil(fe.height + pad));
        const buf_w: i32 = @intCast(
            surface.width * @as(u32, @intCast(surface.scale)),
        );
        const buf_h: i32 = @intCast(
            surface.height * @as(u32, @intCast(surface.scale)),
        );

        const buf_ptr = pool_buffer.getNextBuffer(
            state.shm,
            @as([*]types.PoolBuffer, @ptrCast(&surface.overlay_buffers)),
            @intCast(buf_w),
            @intCast(buf_h),
        );
        if (buf_ptr == null) return;
        const buf: *types.PoolBuffer = buf_ptr.?;

        const max_lines: i32 =
            if (line_h > 0) @divTrunc(buf_h, line_h) else 0;
        if (max_lines <= 0) return;
        const show: i32 = @min(count, max_lines);
        const start: i32 = count - show;

        const cr = buf.cairo;
        wl.cairo_identity_matrix(cr);
        wl.cairo_set_antialias(cr, wl.CAIRO_ANTIALIAS_BEST);

        wl.cairo_set_source_rgba(cr, 0, 0, 0, 0);
        wl.cairo_set_operator(cr, wl.CAIRO_OPERATOR_SOURCE);
        wl.cairo_paint(cr);
        wl.cairo_set_operator(cr, wl.CAIRO_OPERATOR_OVER);

        const text_h: i32 = show * line_h;
        const text_top: i32 = buf_h - text_h;
        wl.cairo_set_source_rgba(cr, 0, 0, 0, 0.75);
        wl.cairo_rectangle(cr, 0, fd(text_top), fd(buf_w), fd(text_h));
        wl.cairo_fill(cr);

        wl.cairo_select_font_face(
            cr,
            @ptrCast(state.args.font),
            wl.CAIRO_FONT_SLANT_NORMAL,
            wl.CAIRO_FONT_WEIGHT_NORMAL,
        );
        wl.cairo_set_font_size(cr, font_size);
        wl.cairo_font_extents(cr, &fe);
        wl.cairo_set_source_rgba(cr, 1, 1, 1, 1);

        var y: f64 = fd(text_top) + fe.ascent + pad;
        var i: i32 = start;
        while (i < count) : (i += 1) {
            wl.cairo_move_to(cr, pad, y);
            wl.cairo_show_text(cr, @ptrCast(&lines[@intCast(i)]));
            y += fd(line_h);
        }

        wl.wl_subsurface_set_position(surface.overlay_sub, 0, 0);
        wl.wl_surface_set_buffer_scale(surface.overlay, surface.scale);
        wl.wl_surface_attach(surface.overlay, buf.buffer, 0, 0);
        wl.wl_surface_damage_buffer(
            surface.overlay,
            0,
            0,
            math.maxInt(i32),
            math.maxInt(i32),
        );
        wl.wl_surface_commit(surface.overlay);
    }
}

pub fn render(surface: *types.Surface) void {
    const state: *types.State = surface.g.?;
    const bw: i32 =
        @as(i32, @intCast(surface.width)) * surface.scale;
    const bh: i32 =
        @as(i32, @intCast(surface.height)) * surface.scale;
    if (bw == 0 or bh == 0) return;
    if (!surface.dirty or surface.frame != null) return;

    var need_destroy = false;
    var buffer: types.PoolBuffer = undefined;

    if (bw != surface.last_buffer_width or
        bh != surface.last_buffer_height)
    {
        need_destroy = true;
        if (pool_buffer.createBuffer(
            state.shm,
            &buffer,
            bw,
            bh,
            wl.WL_SHM_FORMAT_ARGB8888,
        ) == null) {
            log.slog(
                log.LogImportance.err,
                @src(),
                "Failed to create new buffer for frame background.",
                .{},
            );
            return;
        }

        const cr = buffer.cairo;
        wl.cairo_set_antialias(cr, wl.CAIRO_ANTIALIAS_BEST);
        wl.cairo_save(cr);
        wl.cairo_set_operator(cr, wl.CAIRO_OPERATOR_SOURCE);
        cairo_mod.cairoSetSourceU32(cr, state.args.colors.background);
        wl.cairo_paint(cr);
        if (surface.image != null and
            state.args.mode != types.BackgroundMode.solid_color)
        {
            wl.cairo_set_operator(cr, wl.CAIRO_OPERATOR_OVER);
            background_image.renderBackgroundImage(
                cr,
                surface.image,
                state.args.mode,
                bw,
                bh,
            );
        }
        wl.cairo_restore(cr);
        wl.cairo_identity_matrix(cr);

        wl.wl_surface_attach(surface.surface, buffer.buffer, 0, 0);
        wl.wl_surface_damage_buffer(
            surface.surface,
            0,
            0,
            math.maxInt(i32),
            math.maxInt(i32),
        );

        surface.last_buffer_width = bw;
        surface.last_buffer_height = bh;
    }

    // Buffer scale may change without affecting buffer size.
    wl.wl_surface_set_buffer_scale(surface.surface, surface.scale);
    _ = render_frame(surface);
    if (comptime opts.have_debug_overlay) {
        render_debug_overlay(surface);
    }
    surface.dirty = false;
    surface.frame = wl.wl_surface_frame(surface.surface);
    _ = wl.wl_callback_add_listener(
        surface.frame,
        &surface_frame_listener,
        surface,
    );
    wl.wl_surface_commit(surface.surface);

    if (need_destroy) pool_buffer.destroyBuffer(&buffer);
    allocator_mod.resetRender();
}

fn configure_font_drawing(
    cairo: ?*wl.cairo_t,
    state: *types.State,
    subpixel: wl.wl_output_subpixel,
    arc_radius: i32,
) void {
    const fo = wl.cairo_font_options_create() orelse return;
    defer wl.cairo_font_options_destroy(fo);
    wl.cairo_font_options_set_hint_style(fo, wl.CAIRO_HINT_STYLE_FULL);
    wl.cairo_font_options_set_antialias(fo, wl.CAIRO_ANTIALIAS_SUBPIXEL);
    wl.cairo_font_options_set_subpixel_order(
        fo,
        cairo_mod.toCairoSubpixelOrder(subpixel),
    );
    wl.cairo_set_font_options(cairo, fo);
    wl.cairo_select_font_face(
        cairo,
        @ptrCast(state.args.font),
        wl.CAIRO_FONT_SLANT_NORMAL,
        wl.CAIRO_FONT_WEIGHT_NORMAL,
    );
    if (state.args.font_size > 0) {
        wl.cairo_set_font_size(cairo, fd(state.args.font_size));
    } else {
        wl.cairo_set_font_size(cairo, fd(arc_radius) / 3.0);
    }
}

fn render_frame(surface: *types.Surface) bool {
    const state: *types.State = surface.g.?;
    const scale: i32 = surface.scale;
    const arc_radius: i32 =
        @as(i32, @intCast(state.args.radius)) * scale;
    const arc_thickness: i32 =
        @as(i32, @intCast(state.args.thickness)) * scale;
    const buffer_diameter: i32 =
        (arc_radius + arc_thickness) * 2;

    // Broker or auth-mode selection: render a list and return
    // early without drawing the indicator ring.
    if (state.authd_active and
        (state.authd_stage == types.AuthdStage.broker or
            state.authd_stage == types.AuthdStage.auth_mode))
    {
        const is_broker =
            state.authd_stage == types.AuthdStage.broker;
        const count: i32 = if (is_broker)
            @intCast(state.authd_brokers.len)
        else
            @intCast(state.authd_auth_modes.len);
        const sel: i32 = if (is_broker)
            state.authd_sel_broker
        else
            state.authd_sel_auth_mode;

        configure_font_drawing(
            state.test_cairo,
            state,
            surface.subpixel,
            arc_radius,
        );
        var fe: wl.cairo_font_extents_t = undefined;
        wl.cairo_font_extents(state.test_cairo, &fe);

        const max_vis: i32 = 8;
        const vis_count: i32 = @min(count, max_vis);
        var start: i32 = 0;
        if (count > max_vis and sel >= 0) {
            start = sel - @divTrunc(max_vis, 2);
            if (start < 0) {
                start = 0;
            } else if (start + max_vis > count) {
                start = count - max_vis;
            }
        }

        const box_padding: f64 = 4.0 * fd(scale);
        const item_height: f64 = fe.height * 1.5;
        var max_text_w: f64 = 0;

        var mi: i32 = start;
        while (mi < start + vis_count) : (mi += 1) {
            const name: [*c]const u8 = if (is_broker)
                state.authd_brokers[@intCast(mi)].name
            else
                state.authd_auth_modes[@intCast(mi)].label;
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(
                state.test_cairo,
                if (name != null) name else "",
                &ext,
            );
            if (ext.width > max_text_w) max_text_w = ext.width;
        }

        var buf_w: i32 = @intFromFloat(max_text_w + 4.0 * box_padding);
        var buf_h: i32 = @intFromFloat(
            fd(vis_count) * item_height + 2.0 * box_padding,
        );
        buf_w += scale - @mod(buf_w, scale);
        buf_h += scale - @mod(buf_h, scale);

        const subsurf_xpos: i32 =
            if (state.args.override_indicator_x_position)
                @as(i32, @intCast(state.args.indicator_x_position)) -
                    @divTrunc(buf_w, 2 * scale)
            else
                @divTrunc(@as(i32, @intCast(surface.width)), 2) -
                    @divTrunc(buf_w, 2 * scale);
        const subsurf_ypos: i32 =
            if (state.args.override_indicator_y_position)
                @as(i32, @intCast(state.args.indicator_y_position)) -
                    @divTrunc(buf_h, 2 * scale)
            else
                @divTrunc(@as(i32, @intCast(surface.height)), 2) -
                    @divTrunc(buf_h, 2 * scale);

        const buf_ptr = pool_buffer.getNextBuffer(
            state.shm,
            @as([*]types.PoolBuffer, @ptrCast(&surface.indicator_buffers)),
            @intCast(buf_w),
            @intCast(buf_h),
        );
        if (buf_ptr == null) {
            log.slog(log.LogImportance.err, @src(), "No buffer", .{});
            return false;
        }
        const buf: *types.PoolBuffer = buf_ptr.?;

        const cr = buf.cairo;
        wl.cairo_set_antialias(cr, wl.CAIRO_ANTIALIAS_BEST);
        wl.cairo_identity_matrix(cr);

        wl.cairo_save(cr);
        wl.cairo_set_source_rgba(cr, 0, 0, 0, 0);
        wl.cairo_set_operator(cr, wl.CAIRO_OPERATOR_SOURCE);
        wl.cairo_paint(cr);
        wl.cairo_restore(cr);

        configure_font_drawing(cr, state, surface.subpixel, arc_radius);

        var vi: i32 = 0;
        while (vi < vis_count) : (vi += 1) {
            const idx = start + vi;
            const name: [*c]const u8 = if (is_broker)
                state.authd_brokers[@intCast(idx)].name
            else
                state.authd_auth_modes[@intCast(idx)].label;
            const safe_name: [*c]const u8 =
                if (name != null) name else "";
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(cr, safe_name, &ext);

            const iy: f64 =
                box_padding + fd(vi) * item_height;

            wl.cairo_rectangle(cr, 0, iy, fd(buf_w), item_height);
            if (idx == sel) {
                cairo_mod.cairoSetSourceU32(
                    cr,
                    state.args.colors.layout_background,
                );
            } else {
                cairo_mod.cairoSetSourceU32(
                    cr,
                    state.args.colors.background,
                );
            }
            wl.cairo_fill(cr);

            const tx: f64 =
                (fd(buf_w) - ext.width) / 2.0 -
                ext.x_bearing;
            const ty: f64 = iy +
                (item_height + fe.height) / 2.0 -
                fe.descent;
            wl.cairo_move_to(cr, tx, ty);
            if (idx == sel) {
                cairo_mod.cairoSetSourceU32(
                    cr,
                    state.args.colors.layout_text,
                );
            } else {
                cairo_mod.cairoSetSourceU32(
                    cr,
                    state.args.colors.text.input,
                );
            }
            wl.cairo_show_text(cr, safe_name);
        }

        wl.wl_subsurface_set_position(
            surface.subsurface,
            subsurf_xpos,
            subsurf_ypos,
        );
        wl.wl_surface_set_buffer_scale(surface.child, scale);
        wl.wl_surface_attach(surface.child, buf.buffer, 0, 0);
        wl.wl_surface_damage_buffer(
            surface.child,
            0,
            0,
            math.maxInt(i32),
            math.maxInt(i32),
        );
        wl.wl_surface_commit(surface.child);
        return true;
    }

    // Determine indicator text; affects buffer sizing.
    var attempts_buf: [5]u8 = std.mem.zeroes([5]u8);
    var text: [*c]const u8 = null;
    var layout_text: [*c]const u8 = null;

    const draw_indicator = state.args.show_indicator and
        (state.auth_state != types.AuthState.idle or
            state.input_state != types.InputState.idle or
            state.args.indicator_idle_visible);

    if (draw_indicator) {
        if (state.input_state == types.InputState.clear) {
            text = "Cleared";
        } else if (state.auth_state == types.AuthState.validating) {
            text = "Verifying";
        } else if (state.auth_state == types.AuthState.invalid) {
            text = "Wrong";
        } else {
            // Caps Lock takes display priority over attempts.
            if (state.xkb.caps_lock and
                state.args.show_caps_lock_text)
            {
                text = "Caps Lock";
            } else if (state.args.show_failed_attempts and
                state.failed_attempts > 0)
            {
                if (state.failed_attempts > 999) {
                    text = "999+";
                } else {
                    _ = std.fmt.bufPrint(
                        attempts_buf[0..4],
                        "{d}",
                        .{state.failed_attempts},
                    ) catch {};
                    text = @as([*c]const u8, @ptrCast(&attempts_buf));
                }
            }

            if (state.xkb.keymap != null) {
                const num_layout =
                    wl.xkb_keymap_num_layouts(state.xkb.keymap);
                if (!state.args.hide_keyboard_layout and
                    (state.args.show_keyboard_layout or
                        num_layout > 1))
                {
                    var curr: wl.xkb_layout_index_t = 0;
                    while (curr < num_layout and
                        wl.xkb_state_layout_index_is_active(
                            state.xkb.state,
                            curr,
                            wl.XKB_STATE_LAYOUT_EFFECTIVE,
                        ) != 1)
                    {
                        curr += 1;
                    }
                    layout_text =
                        wl.xkb_keymap_layout_get_name(
                            state.xkb.keymap,
                            curr,
                        );
                }
            }
        }
    }

    // QR code layout replaces the indicator ring.
    const is_qrcode = state.authd_active and
        state.authd_stage == types.AuthdStage.challenge and
        state.authd_layout.type != null and
        std.mem.eql(
            u8,
            std.mem.sliceTo(state.authd_layout.type.?, 0),
            "qrcode",
        );

    // Opaque pointer so the variable exists regardless of
    // opts.have_qrencode; only dereferenced in comptime blocks.
    var qrcode_opaque: ?*anyopaque = null;
    defer if (comptime opts.have_qrencode) {
        if (qrcode_opaque) |p| {
            const qr: *qrencode.QRcode = @ptrCast(p);
            qrencode.QRcode_free(qr);
        }
    };
    if (comptime opts.have_qrencode) {
        if (is_qrcode and
            state.authd_layout.qr_content != null)
        {
            const qr = qrencode.QRcode_encodeString(
                @ptrCast(state.authd_layout.qr_content),
                0,
                qrencode.QR_ECLEVEL_L,
                qrencode.QR_MODE_8,
                1,
            );
            if (qr != null) qrcode_opaque = @ptrCast(qr);
        }
    }

    // Calculate required buffer dimensions.
    var buffer_width: i32 = buffer_diameter;
    var buffer_height: i32 = buffer_diameter;

    if (is_qrcode) {
        var have_qr_image = false;
        if (comptime opts.have_qrencode) {
            if (qrcode_opaque) |qr_opaque| {
                const qr: *qrencode.QRcode = @ptrCast(qr_opaque);
                const qr_px = qr.width * 4 * scale;
                buffer_width = qr_px;
                buffer_height = qr_px;
                have_qr_image = true;
            }
        }
        // Reserve height for the human-readable code text.
        if (state.authd_layout.qr_code != null and
            state.authd_layout.qr_code.?[0] != 0)
        {
            wl.cairo_set_antialias(
                state.test_cairo,
                wl.CAIRO_ANTIALIAS_BEST,
            );
            configure_font_drawing(
                state.test_cairo,
                state,
                surface.subpixel,
                arc_radius,
            );
            var ext: wl.cairo_text_extents_t = undefined;
            var fe: wl.cairo_font_extents_t = undefined;
            wl.cairo_text_extents(
                state.test_cairo,
                @ptrCast(state.authd_layout.qr_code),
                &ext,
            );
            wl.cairo_font_extents(state.test_cairo, &fe);
            const box_padding: f64 = 4.0 * fd(scale);
            buffer_height += @intFromFloat(fe.height + 2.0 * box_padding);
            if (!have_qr_image and
                buffer_width < @as(
                    i32,
                    @intFromFloat(ext.width + 2.0 * box_padding),
                ))
            {
                buffer_width =
                    @intFromFloat(ext.width + 2.0 * box_padding);
            }
        }
        // No layout badge when showing a QR code.
        layout_text = null;
    } else {
        if (text != null or layout_text != null) {
            wl.cairo_set_antialias(
                state.test_cairo,
                wl.CAIRO_ANTIALIAS_BEST,
            );
            configure_font_drawing(
                state.test_cairo,
                state,
                surface.subpixel,
                arc_radius,
            );
            if (text != null) {
                var ext: wl.cairo_text_extents_t = undefined;
                wl.cairo_text_extents(state.test_cairo, text, &ext);
                if (buffer_width < @as(i32, @intFromFloat(ext.width))) {
                    buffer_width = @intFromFloat(ext.width);
                }
            }
            if (layout_text != null) {
                var ext: wl.cairo_text_extents_t = undefined;
                var fe: wl.cairo_font_extents_t = undefined;
                const box_padding: f64 =
                    4.0 * fd(surface.scale);
                wl.cairo_text_extents(state.test_cairo, layout_text, &ext);
                wl.cairo_font_extents(state.test_cairo, &fe);
                buffer_height +=
                    @intFromFloat(fe.height + 2.0 * box_padding);
                if (buffer_width < @as(
                    i32,
                    @intFromFloat(ext.width + 2.0 * box_padding),
                )) {
                    buffer_width =
                        @intFromFloat(ext.width + 2.0 * box_padding);
                }
            }
        }
    }

    // Extra space for challenge-stage label, button, and error.
    var label_box_h: f64 = 0;
    var button_box_h: f64 = 0;
    var error_h: f64 = 0;
    if (state.authd_active and
        state.authd_stage == types.AuthdStage.challenge)
    {
        wl.cairo_set_antialias(
            state.test_cairo,
            wl.CAIRO_ANTIALIAS_BEST,
        );
        configure_font_drawing(
            state.test_cairo,
            state,
            surface.subpixel,
            arc_radius,
        );
        var fe: wl.cairo_font_extents_t = undefined;
        wl.cairo_font_extents(state.test_cairo, &fe);
        const box_padding: f64 = 4.0 * fd(scale);

        if (!is_qrcode and
            state.authd_layout.label != null and
            state.authd_layout.label.?[0] != 0)
        {
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(
                state.test_cairo,
                @ptrCast(state.authd_layout.label),
                &ext,
            );
            label_box_h = fe.height + 2.0 * box_padding;
            buffer_height += @intFromFloat(label_box_h);
            if (buffer_width < @as(
                i32,
                @intFromFloat(ext.width + 2.0 * box_padding),
            )) {
                buffer_width =
                    @intFromFloat(ext.width + 2.0 * box_padding);
            }
        }
        if (!is_qrcode and
            state.authd_layout.button != null and
            state.authd_layout.button.?[0] != 0)
        {
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(
                state.test_cairo,
                @ptrCast(state.authd_layout.button),
                &ext,
            );
            button_box_h = fe.height + 2.0 * box_padding;
            buffer_height += @intFromFloat(button_box_h);
            if (buffer_width < @as(
                i32,
                @intFromFloat(ext.width + 2.0 * box_padding),
            )) {
                buffer_width =
                    @intFromFloat(ext.width + 2.0 * box_padding);
            }
        }
        if (state.authd_error != null and
            state.authd_error.?[0] != 0)
        {
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(
                state.test_cairo,
                @ptrCast(state.authd_error),
                &ext,
            );
            error_h = fe.height + box_padding;
            buffer_height += @intFromFloat(error_h);
            if (buffer_width < @as(i32, @intFromFloat(ext.width))) {
                buffer_width = @intFromFloat(ext.width);
            }
        }
    }

    // Wayland requires buffer dimensions be multiples of scale.
    buffer_height += scale - @mod(buffer_height, scale);
    buffer_width += scale - @mod(buffer_width, scale);

    var subsurf_xpos: i32 = undefined;
    var subsurf_ypos: i32 = undefined;
    if (is_qrcode) {
        subsurf_xpos =
            if (state.args.override_indicator_x_position)
                @as(i32, @intCast(state.args.indicator_x_position)) -
                    @divTrunc(buffer_width, 2 * scale)
            else
                @divTrunc(@as(i32, @intCast(surface.width)), 2) -
                    @divTrunc(buffer_width, 2 * scale);
        subsurf_ypos =
            if (state.args.override_indicator_y_position)
                @as(i32, @intCast(state.args.indicator_y_position)) -
                    @divTrunc(buffer_height, 2 * scale)
            else
                @divTrunc(@as(i32, @intCast(surface.height)), 2) -
                    @divTrunc(buffer_height, 2 * scale);
    } else {
        subsurf_xpos =
            if (state.args.override_indicator_x_position)
                @as(i32, @intCast(state.args.indicator_x_position)) -
                    @divTrunc(buffer_width, 2 * scale) +
                    @divTrunc(2, scale)
            else
                @divTrunc(@as(i32, @intCast(surface.width)), 2) -
                    @divTrunc(buffer_width, 2 * scale) +
                    @divTrunc(2, scale);
        subsurf_ypos =
            if (state.args.override_indicator_y_position)
                @as(i32, @intCast(state.args.indicator_y_position)) -
                    @as(i32, @intCast(
                        state.args.radius + state.args.thickness,
                    ))
            else
                @divTrunc(@as(i32, @intCast(surface.height)), 2) -
                    @as(i32, @intCast(
                        state.args.radius + state.args.thickness,
                    ));
        // Offset upward to keep the ring centred on screen
        // when a label box sits above it.
        subsurf_ypos -=
            @as(i32, @intFromFloat(label_box_h / fd(scale)));
    }

    const buf_ptr = pool_buffer.getNextBuffer(
        state.shm,
        @as([*]types.PoolBuffer, @ptrCast(&surface.indicator_buffers)),
        @intCast(buffer_width),
        @intCast(buffer_height),
    );
    if (buf_ptr == null) {
        log.slog(log.LogImportance.err, @src(), "No buffer", .{});
        return false;
    }
    const buf: *types.PoolBuffer = buf_ptr.?;

    const cairo = buf.cairo;
    wl.cairo_set_antialias(cairo, wl.CAIRO_ANTIALIAS_BEST);
    wl.cairo_identity_matrix(cairo);

    // Clear buffer to fully transparent.
    wl.cairo_save(cairo);
    wl.cairo_set_source_rgba(cairo, 0, 0, 0, 0);
    wl.cairo_set_operator(cairo, wl.CAIRO_OPERATOR_SOURCE);
    wl.cairo_paint(cairo);
    wl.cairo_restore(cairo);

    if (is_qrcode) {
        configure_font_drawing(cairo, state, surface.subpixel, arc_radius);
        var fe: wl.cairo_font_extents_t = undefined;
        wl.cairo_font_extents(cairo, &fe);
        const box_padding: f64 = 4.0 * fd(scale);

        var qr_y: f64 = 0;
        var drew_qr = false;

        if (comptime opts.have_qrencode) {
            if (qrcode_opaque) |qr_opaque| {
                const qr: *qrencode.QRcode = @ptrCast(qr_opaque);
                const mod_size: i32 = 4 * scale;
                const qr_px: i32 = qr.width * mod_size;
                const qr_x: i32 =
                    @divTrunc(buffer_width - qr_px, 2);

                // White backdrop for QR modules.
                wl.cairo_rectangle(
                    cairo,
                    fd(qr_x),
                    0,
                    fd(qr_px),
                    fd(qr_px),
                );
                wl.cairo_set_source_rgb(cairo, 1, 1, 1);
                wl.cairo_fill(cairo);

                // Batch all dark modules into one fill pass.
                wl.cairo_set_source_rgb(cairo, 0, 0, 0);
                var row: i32 = 0;
                while (row < qr.width) : (row += 1) {
                    var col: i32 = 0;
                    while (col < qr.width) : (col += 1) {
                        const px = qr.data[
                            @intCast(row * qr.width + col)
                        ];
                        if (px & 1 == 0) continue;
                        wl.cairo_rectangle(
                            cairo,
                            fd(qr_x + col * mod_size),
                            fd(row * mod_size),
                            fd(mod_size),
                            fd(mod_size),
                        );
                    }
                }
                wl.cairo_fill(cairo);

                qr_y = fd(qr_px);
                drew_qr = true;
            }
        }

        if (state.authd_layout.qr_code != null and
            state.authd_layout.qr_code.?[0] != 0)
        {
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(
                cairo,
                @ptrCast(state.authd_layout.qr_code),
                &ext,
            );
            const tx: f64 =
                (fd(buffer_width) - ext.width) / 2.0 -
                ext.x_bearing;
            var ty: f64 = undefined;
            if (drew_qr) {
                ty = qr_y + (fe.height - fe.descent) +
                    box_padding;
                qr_y += fe.height + 2.0 * box_padding;
            } else {
                // No QR image; centre the fallback text.
                ty = (fd(buffer_height) - error_h) / 2.0 +
                    (fe.height / 2.0 - fe.descent);
                qr_y = fd(buffer_height) - error_h;
            }
            wl.cairo_move_to(cairo, tx, ty);
            cairo_mod.cairoSetSourceU32(
                cairo,
                state.args.colors.layout_text,
            );
            wl.cairo_show_text(cairo, @ptrCast(state.authd_layout.qr_code));
        }

        // Error message below QR content.
        if (error_h > 0) {
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_text_extents(cairo, @ptrCast(state.authd_error), &ext);
            const tx: f64 =
                (fd(buffer_width) - ext.width) / 2.0 -
                ext.x_bearing;
            const ty: f64 = qr_y +
                (fe.height - fe.descent) +
                box_padding / 2.0;
            wl.cairo_move_to(cairo, tx, ty);
            cairo_mod.cairoSetSourceU32(cairo, error_text_color);
            wl.cairo_show_text(cairo, @ptrCast(state.authd_error));
        }
    } else if (draw_indicator) {
        configure_font_drawing(cairo, state, surface.subpixel, arc_radius);

        // Label box above the ring (challenge stage).
        if (label_box_h > 0) {
            var fe: wl.cairo_font_extents_t = undefined;
            var ext: wl.cairo_text_extents_t = undefined;
            wl.cairo_font_extents(cairo, &fe);
            wl.cairo_text_extents(
                cairo,
                @ptrCast(state.authd_layout.label),
                &ext,
            );
            const box_padding: f64 = 4.0 * fd(scale);
            const bx: f64 = fd(buffer_width) / 2.0 -
                ext.width / 2.0 - box_padding;
            wl.cairo_rectangle(
                cairo,
                bx,
                0,
                ext.width + 2.0 * box_padding,
                fe.height + 2.0 * box_padding,
            );
            cairo_mod.cairoSetSourceU32(
                cairo,
                state.args.colors.layout_background,
            );
            wl.cairo_fill_preserve(cairo);
            cairo_mod.cairoSetSourceU32(
                cairo,
                state.args.colors.layout_border,
            );
            wl.cairo_stroke(cairo);
            wl.cairo_move_to(
                cairo,
                bx - ext.x_bearing + box_padding,
                (fe.height - fe.descent) + box_padding,
            );
            cairo_mod.cairoSetSourceU32(cairo, state.args.colors.layout_text);
            wl.cairo_show_text(cairo, @ptrCast(state.authd_layout.label));
            wl.cairo_new_sub_path(cairo);
        }

        // Shift ring centre down by label height to keep
        // it visually centred.
        const ring_cy: i32 =
            @as(i32, @intFromFloat(label_box_h)) +
            @divTrunc(buffer_diameter, 2);
        const cx: f64 = fd(@divTrunc(buffer_width, 2));

        // Inner circle fill.
        wl.cairo_set_line_width(cairo, 0);
        wl.cairo_arc(
            cairo,
            cx,
            fd(ring_cy),
            fd(arc_radius) -
                fd(@divTrunc(arc_thickness, 2)),
            0,
            2.0 * pi,
        );
        set_color_for_state(cairo, state, &state.args.colors.inside);
        wl.cairo_fill_preserve(cairo);
        wl.cairo_stroke(cairo);

        // Outer ring stroke.
        wl.cairo_set_line_width(cairo, fd(arc_thickness));
        wl.cairo_arc(
            cairo,
            cx,
            fd(ring_cy),
            fd(arc_radius),
            0,
            2.0 * pi,
        );
        set_color_for_state(cairo, state, &state.args.colors.ring);
        wl.cairo_stroke(cairo);

        // Status text inside the ring.
        configure_font_drawing(cairo, state, surface.subpixel, arc_radius);
        set_color_for_state(cairo, state, &state.args.colors.text);

        if (text != null) {
            var ext: wl.cairo_text_extents_t = undefined;
            var fe: wl.cairo_font_extents_t = undefined;
            wl.cairo_text_extents(cairo, text, &ext);
            wl.cairo_font_extents(cairo, &fe);
            const x: f64 = cx -
                (ext.width / 2.0 + ext.x_bearing);
            const y: f64 = fd(ring_cy) +
                (fe.height / 2.0 - fe.descent);
            wl.cairo_move_to(cairo, x, y);
            wl.cairo_show_text(cairo, text);
            wl.cairo_close_path(cairo);
            wl.cairo_new_sub_path(cairo);
        }

        // Typing highlight: random arc segment on keypress.
        if (state.input_state == types.InputState.letter or
            state.input_state == types.InputState.backspace)
        {
            const hs: f64 =
                fd(state.highlight_start) * (pi / 1024.0);
            wl.cairo_arc(
                cairo,
                cx,
                fd(ring_cy),
                fd(arc_radius),
                hs,
                hs + type_indicator_range,
            );
            if (state.input_state == types.InputState.letter) {
                if (state.xkb.caps_lock and
                    state.args.show_caps_lock_indicator)
                {
                    cairo_mod.cairoSetSourceU32(
                        cairo,
                        state.args.colors.caps_lock_key_highlight,
                    );
                } else {
                    cairo_mod.cairoSetSourceU32(
                        cairo,
                        state.args.colors.key_highlight,
                    );
                }
            } else {
                if (state.xkb.caps_lock and
                    state.args.show_caps_lock_indicator)
                {
                    cairo_mod.cairoSetSourceU32(
                        cairo,
                        state.args.colors.caps_lock_bs_highlight,
                    );
                } else {
                    cairo_mod.cairoSetSourceU32(
                        cairo,
                        state.args.colors.bs_highlight,
                    );
                }
            }
            wl.cairo_stroke(cairo);

            // Separator lines at segment edges.
            const inner_radius: f64 =
                fd(buffer_diameter) / 2.0 -
                fd(arc_thickness) * 1.5;
            const outer_radius: f64 =
                fd(buffer_diameter) / 2.0 -
                fd(arc_thickness) / 2.0;
            const hs_end: f64 = hs + type_indicator_range;

            wl.cairo_set_line_width(cairo, 2.0 * fd(scale));
            cairo_mod.cairoSetSourceU32(cairo, state.args.colors.separator);
            wl.cairo_move_to(
                cairo,
                cx + math.cos(hs) * inner_radius,
                fd(ring_cy) + math.sin(hs) * inner_radius,
            );
            wl.cairo_line_to(
                cairo,
                cx + math.cos(hs) * outer_radius,
                fd(ring_cy) + math.sin(hs) * outer_radius,
            );
            wl.cairo_stroke(cairo);

            wl.cairo_move_to(
                cairo,
                cx + math.cos(hs_end) * inner_radius,
                fd(ring_cy) + math.sin(hs_end) * inner_radius,
            );
            wl.cairo_line_to(
                cairo,
                cx + math.cos(hs_end) * outer_radius,
                fd(ring_cy) + math.sin(hs_end) * outer_radius,
            );
            wl.cairo_stroke(cairo);
        }

        // Inner and outer ring border lines.
        set_color_for_state(cairo, state, &state.args.colors.line);
        wl.cairo_set_line_width(cairo, 2.0 * fd(scale));
        wl.cairo_arc(
            cairo,
            cx,
            fd(ring_cy),
            fd(arc_radius) -
                fd(@divTrunc(arc_thickness, 2)),
            0,
            2.0 * pi,
        );
        wl.cairo_stroke(cairo);
        wl.cairo_arc(
            cairo,
            cx,
            fd(ring_cy),
            fd(arc_radius) +
                fd(@divTrunc(arc_thickness, 2)),
            0,
            2.0 * pi,
        );
        wl.cairo_stroke(cairo);

        // Keyboard layout badge below the ring.
        if (layout_text != null) {
            var ext: wl.cairo_text_extents_t = undefined;
            var fe: wl.cairo_font_extents_t = undefined;
            const box_padding: f64 = 4.0 * fd(scale);
            wl.cairo_text_extents(cairo, layout_text, &ext);
            wl.cairo_font_extents(cairo, &fe);
            const lbx: f64 = cx -
                ext.width / 2.0 - box_padding;
            const lby: f64 = fd(
                @as(i32, @intFromFloat(label_box_h)) + buffer_diameter,
            );

            wl.cairo_rectangle(
                cairo,
                lbx,
                lby,
                ext.width + 2.0 * box_padding,
                fe.height + 2.0 * box_padding,
            );
            cairo_mod.cairoSetSourceU32(
                cairo,
                state.args.colors.layout_background,
            );
            wl.cairo_fill_preserve(cairo);
            cairo_mod.cairoSetSourceU32(cairo, state.args.colors.layout_border);
            wl.cairo_stroke(cairo);
            wl.cairo_move_to(
                cairo,
                lbx - ext.x_bearing + box_padding,
                lby + (fe.height - fe.descent) +
                    box_padding,
            );
            cairo_mod.cairoSetSourceU32(cairo, state.args.colors.layout_text);
            wl.cairo_show_text(cairo, layout_text);
            wl.cairo_new_sub_path(cairo);
        }

        // Challenge-stage button and error below ring.
        if (button_box_h > 0 or error_h > 0) {
            var fe: wl.cairo_font_extents_t = undefined;
            wl.cairo_font_extents(cairo, &fe);
            const box_padding: f64 = 4.0 * fd(scale);

            // Position below ring and optional layout badge.
            var y: f64 = fd(
                @as(i32, @intFromFloat(label_box_h)) + buffer_diameter,
            );
            if (layout_text != null) {
                y += fe.height + 2.0 * box_padding;
            }

            if (button_box_h > 0) {
                var ext: wl.cairo_text_extents_t = undefined;
                wl.cairo_text_extents(
                    cairo,
                    @ptrCast(state.authd_layout.button),
                    &ext,
                );
                const bw: f64 =
                    ext.width + 2.0 * box_padding;
                const bh: f64 =
                    fe.height + 2.0 * box_padding;
                const bx: f64 =
                    (fd(buffer_width) - bw) / 2.0;
                const corner: f64 = bh / 4.0;

                // Rounded rectangle button shape.
                wl.cairo_new_sub_path(cairo);
                wl.cairo_arc(
                    cairo,
                    bx + bw - corner,
                    y + corner,
                    corner,
                    -pi / 2.0,
                    0,
                );
                wl.cairo_arc(
                    cairo,
                    bx + bw - corner,
                    y + bh - corner,
                    corner,
                    0,
                    pi / 2.0,
                );
                wl.cairo_arc(
                    cairo,
                    bx + corner,
                    y + bh - corner,
                    corner,
                    pi / 2.0,
                    pi,
                );
                wl.cairo_arc(
                    cairo,
                    bx + corner,
                    y + corner,
                    corner,
                    pi,
                    3.0 * pi / 2.0,
                );
                wl.cairo_close_path(cairo);

                cairo_mod.cairoSetSourceU32(
                    cairo,
                    state.args.colors.layout_background,
                );
                wl.cairo_fill_preserve(cairo);
                wl.cairo_set_line_width(cairo, 2.0 * fd(scale));
                cairo_mod.cairoSetSourceU32(
                    cairo,
                    state.args.colors.layout_border,
                );
                wl.cairo_stroke(cairo);

                wl.cairo_move_to(
                    cairo,
                    bx - ext.x_bearing + box_padding,
                    y + (fe.height - fe.descent) +
                        box_padding,
                );
                cairo_mod.cairoSetSourceU32(
                    cairo,
                    state.args.colors.layout_text,
                );
                wl.cairo_show_text(cairo, @ptrCast(state.authd_layout.button));
                wl.cairo_new_sub_path(cairo);

                y += button_box_h;
            }

            if (error_h > 0) {
                var ext: wl.cairo_text_extents_t = undefined;
                wl.cairo_text_extents(cairo, @ptrCast(state.authd_error), &ext);
                const tx: f64 =
                    (fd(buffer_width) - ext.width) / 2.0 -
                    ext.x_bearing;
                const ty: f64 = y +
                    (fe.height - fe.descent) +
                    box_padding / 2.0;
                wl.cairo_move_to(cairo, tx, ty);
                cairo_mod.cairoSetSourceU32(cairo, error_text_color);
                wl.cairo_show_text(cairo, @ptrCast(state.authd_error));
                wl.cairo_new_sub_path(cairo);
            }
        }
    }

    // Submit the indicator subsurface to the compositor.
    wl.wl_subsurface_set_position(
        surface.subsurface,
        subsurf_xpos,
        subsurf_ypos,
    );
    wl.wl_surface_set_buffer_scale(surface.child, surface.scale);
    wl.wl_surface_attach(surface.child, buf.buffer, 0, 0);
    wl.wl_surface_damage_buffer(
        surface.child,
        0,
        0,
        math.maxInt(i32),
        math.maxInt(i32),
    );
    wl.wl_surface_commit(surface.child);

    return true;
}
