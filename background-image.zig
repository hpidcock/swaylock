//! background-image.zig – Zig port of background-image.c.
//! Parses background mode strings, loads background images,
//! and renders them onto Cairo surfaces.

const std = @import("std");
const opts = @import("background_image_options");
const types = @import("types");

// No local C imports needed — cairo types come from types.c.
const c = types.c;

const log_err: i32 = @intFromEnum(types.LogImportance.err);
extern fn _swaylock_log(verbosity: i32, fmt: [*c]const u8, ...) void;
extern fn _swaylock_strip_path(filepath: [*c]const u8) [*c]const u8;

// Minimal hand-rolled declarations for the gdk-pixbuf/glib symbols
// needed by load_background_image. Zig 0.16's aro C-frontend cannot
// parse the glib pragma-heavy headers, so we avoid @cImporting them
// and instead declare just what we need here.
const GdkPixbuf = opaque {};
/// Matches struct _GError { GQuark domain; gint code; gchar *message; }
const GError = extern struct {
    domain: u32,
    code: i32,
    message: [*c]u8,
};
extern fn gdk_pixbuf_new_from_file(
    filename: [*c]const u8,
    err: *?*GError,
) ?*GdkPixbuf;
extern fn gdk_pixbuf_apply_embedded_orientation(
    src: ?*GdkPixbuf,
) ?*GdkPixbuf;
extern fn gdk_cairo_image_surface_create_from_pixbuf(
    pixbuf: ?*const GdkPixbuf,
) ?*c.cairo_surface_t;
extern fn g_object_unref(object: ?*anyopaque) void;

/// Formats a message and passes it to the swaylock logger,
/// attaching the source location captured at the call site.
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

/// Parses a background mode string and returns the corresponding
/// enum value, or .invalid on an unknown string.
pub export fn parse_background_mode(
    mode: [*c]const u8,
) types.BackgroundMode {
    const s = std.mem.span(mode);
    if (std.mem.eql(u8, s, "stretch")) {
        return types.BackgroundMode.stretch;
    } else if (std.mem.eql(u8, s, "fill")) {
        return types.BackgroundMode.fill;
    } else if (std.mem.eql(u8, s, "fit")) {
        return types.BackgroundMode.fit;
    } else if (std.mem.eql(u8, s, "center")) {
        return types.BackgroundMode.center;
    } else if (std.mem.eql(u8, s, "tile")) {
        return types.BackgroundMode.tile;
    } else if (std.mem.eql(u8, s, "solid_color")) {
        return types.BackgroundMode.solid_color;
    }
    slog(
        log_err,
        @src(),
        "Unsupported background mode: {s}",
        .{s},
    );
    return types.BackgroundMode.invalid;
}

/// Loads a background image from path. When compiled with
/// gdk_pixbuf support, any format supported by gdk-pixbuf is
/// accepted and embedded orientation is applied; otherwise only
/// PNG images are supported via Cairo directly.
/// Returns a cairo surface on success, or null on failure.
pub export fn load_background_image(
    path: [*c]const u8,
) ?*c.cairo_surface_t {
    var image: ?*c.cairo_surface_t = null;
    if (comptime opts.have_gdk_pixbuf) {
        var err: ?*GError = null;
        const pixbuf = gdk_pixbuf_new_from_file(path, &err);
        if (pixbuf == null) {
            const msg = if (err) |e|
                std.mem.sliceTo(e.message, 0)
            else
                "unknown error";
            slog(
                log_err,
                @src(),
                "Failed to load background image ({s}).",
                .{msg},
            );
            return null;
        }
        // Correct for embedded image orientation; typical images
        // are not rotated and will be handled efficiently.
        const oriented = gdk_pixbuf_apply_embedded_orientation(pixbuf);
        g_object_unref(pixbuf);
        image = gdk_cairo_image_surface_create_from_pixbuf(oriented);
        g_object_unref(oriented);
    } else {
        image = c.cairo_image_surface_create_from_png(path);
    }
    if (image == null) {
        slog(
            log_err,
            @src(),
            "Failed to read background image.",
            .{},
        );
        return null;
    }
    if (c.cairo_surface_status(image) != c.CAIRO_STATUS_SUCCESS) {
        const status_str = std.mem.sliceTo(
            c.cairo_status_to_string(c.cairo_surface_status(image)),
            0,
        );
        if (comptime opts.have_gdk_pixbuf) {
            slog(
                log_err,
                @src(),
                "Failed to read background image: {s}.",
                .{status_str},
            );
        } else {
            slog(
                log_err,
                @src(),
                "Failed to read background image: {s}.\n" ++
                    "Swaylock was compiled without gdk_pixbuf " ++
                    "support, so only\nPNG images can be loaded." ++
                    " This is the likely cause.",
                .{status_str},
            );
        }
        return null;
    }
    return image;
}

/// Renders image onto cairo using the given mode, scaling it to
/// fit within buffer_width x buffer_height.
/// .solid_color and .invalid are not valid here and will trigger
/// unreachable.
pub export fn render_background_image(
    cairo: ?*c.cairo_t,
    image: ?*c.cairo_surface_t,
    mode: types.BackgroundMode,
    buffer_width: i32,
    buffer_height: i32,
) void {
    const width: f64 = @floatFromInt(
        c.cairo_image_surface_get_width(image),
    );
    const height: f64 = @floatFromInt(
        c.cairo_image_surface_get_height(image),
    );
    const bw: f64 = @floatFromInt(buffer_width);
    const bh: f64 = @floatFromInt(buffer_height);

    c.cairo_save(cairo);
    switch (mode) {
        .stretch => {
            c.cairo_scale(cairo, bw / width, bh / height);
            c.cairo_set_source_surface(cairo, image, 0, 0);
        },
        .fill => {
            const window_ratio = bw / bh;
            const bg_ratio = width / height;
            if (window_ratio > bg_ratio) {
                const scale = bw / width;
                c.cairo_scale(cairo, scale, scale);
                c.cairo_set_source_surface(
                    cairo,
                    image,
                    0,
                    bh / 2.0 / scale - height / 2.0,
                );
            } else {
                const scale = bh / height;
                c.cairo_scale(cairo, scale, scale);
                c.cairo_set_source_surface(
                    cairo,
                    image,
                    bw / 2.0 / scale - width / 2.0,
                    0,
                );
            }
        },
        .fit => {
            const window_ratio = bw / bh;
            const bg_ratio = width / height;
            if (window_ratio > bg_ratio) {
                const scale = bh / height;
                c.cairo_scale(cairo, scale, scale);
                c.cairo_set_source_surface(
                    cairo,
                    image,
                    bw / 2.0 / scale - width / 2.0,
                    0,
                );
            } else {
                const scale = bw / width;
                c.cairo_scale(cairo, scale, scale);
                c.cairo_set_source_surface(
                    cairo,
                    image,
                    0,
                    bh / 2.0 / scale - height / 2.0,
                );
            }
        },
        .center => {
            // Align to integer pixel boundaries to prevent clarity
            // loss on odd-sized images.
            c.cairo_set_source_surface(
                cairo,
                image,
                std.math.trunc(bw / 2.0 - width / 2.0),
                std.math.trunc(bh / 2.0 - height / 2.0),
            );
        },
        .tile => {
            const pattern =
                c.cairo_pattern_create_for_surface(image);
            c.cairo_pattern_set_extend(
                pattern,
                c.CAIRO_EXTEND_REPEAT,
            );
            c.cairo_set_source(cairo, pattern);
        },
        else => unreachable,
    }
    c.cairo_paint(cairo);
    c.cairo_restore(cairo);
}
