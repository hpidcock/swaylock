//! cairo.zig – Zig port of cairo.c.
//! Helper wrappers around the Cairo drawing library.

const builtin = @import("builtin");
const opts = @import("cairo_options");

const types = @import("types");

// No local C imports needed — cairo/wayland types come from types.c.
const c = types.c;

// Minimal hand-rolled declarations for the gdk-pixbuf symbols needed
// by gdk_cairo_image_surface_create_from_pixbuf. Zig 0.16's aro
// C-frontend cannot parse the glib pragma-heavy headers, so we avoid
// @cImporting them and instead declare just what we need here.
const GdkPixbuf = opaque {};
extern fn gdk_pixbuf_get_n_channels(
    pixbuf: ?*const GdkPixbuf,
) c_int;
extern fn gdk_pixbuf_read_pixels(
    pixbuf: ?*const GdkPixbuf,
) ?[*]const u8;
extern fn gdk_pixbuf_get_width(pixbuf: ?*const GdkPixbuf) c_int;
extern fn gdk_pixbuf_get_height(pixbuf: ?*const GdkPixbuf) c_int;
extern fn gdk_pixbuf_get_rowstride(pixbuf: ?*const GdkPixbuf) c_int;

/// Sets the Cairo source colour from a packed ARGB u32.
/// Byte order: RRGGBBAA (most-significant byte = red).
pub export fn cairo_set_source_u32(
    cairo: ?*c.cairo_t,
    color: u32,
) void {
    c.cairo_set_source_rgba(
        cairo,
        @as(f64, @floatFromInt((color >> 24) & 0xFF)) / 255.0,
        @as(f64, @floatFromInt((color >> 16) & 0xFF)) / 255.0,
        @as(f64, @floatFromInt((color >> 8) & 0xFF)) / 255.0,
        @as(f64, @floatFromInt(color & 0xFF)) / 255.0,
    );
}

/// Converts a Wayland subpixel hint to the Cairo equivalent.
pub export fn to_cairo_subpixel_order(
    subpixel: c.wl_output_subpixel,
) c.cairo_subpixel_order_t {
    return switch (subpixel) {
        c.WL_OUTPUT_SUBPIXEL_HORIZONTAL_RGB => c.CAIRO_SUBPIXEL_ORDER_RGB,
        c.WL_OUTPUT_SUBPIXEL_HORIZONTAL_BGR => c.CAIRO_SUBPIXEL_ORDER_BGR,
        c.WL_OUTPUT_SUBPIXEL_VERTICAL_RGB => c.CAIRO_SUBPIXEL_ORDER_VRGB,
        c.WL_OUTPUT_SUBPIXEL_VERTICAL_BGR => c.CAIRO_SUBPIXEL_ORDER_VBGR,
        else => c.CAIRO_SUBPIXEL_ORDER_DEFAULT,
    };
}

const GdkExports = if (opts.have_gdk_pixbuf) struct {
    /// Premultiplies a colour channel by an alpha value, using the
    /// integer rounding approximation from the original C source.
    /// Equivalent to lround(channel * alpha / 255.0) for all values
    /// in [0..0xfe02].
    inline fn premulAlpha(channel: u8, alpha: u8) u8 {
        const z: u32 = @as(u32, channel) * @as(u32, alpha) + 0x80;
        return @truncate((z + (z >> 8)) >> 8);
    }

    /// Creates a Cairo ARGB32 image surface from a GdkPixbuf,
    /// premultiplying alpha as required by Cairo.
    /// Returns null on failure.
    pub export fn gdk_cairo_image_surface_create_from_pixbuf(
        gdkbuf: ?*const GdkPixbuf,
    ) ?*c.cairo_surface_t {
        const buf = gdkbuf orelse return null;
        const chan = gdk_pixbuf_get_n_channels(buf);
        if (chan < 3) return null;
        const gdkpix = gdk_pixbuf_read_pixels(buf) orelse
            return null;
        const w = gdk_pixbuf_get_width(buf);
        const h = gdk_pixbuf_get_height(buf);
        const stride = gdk_pixbuf_get_rowstride(buf);
        const fmt: c.cairo_format_t = if (chan == 3)
            c.CAIRO_FORMAT_RGB24
        else
            c.CAIRO_FORMAT_ARGB32;
        const cs = c.cairo_image_surface_create(fmt, w, h);
        c.cairo_surface_flush(cs);
        if (cs == null or
            c.cairo_surface_status(cs) != c.CAIRO_STATUS_SUCCESS)
        {
            return null;
        }
        const cstride = c.cairo_image_surface_get_stride(cs);
        const cpix_base = c.cairo_image_surface_get_data(cs) orelse
            return null;
        var row_gdk: [*]const u8 = gdkpix;
        var row_cairo: [*]u8 = cpix_base;
        const row_stride: usize = @intCast(stride);
        const cairo_row_stride: usize = @intCast(cstride);
        if (chan == 3) {
            var i: c_int = h;
            while (i > 0) : (i -= 1) {
                var gp: [*]const u8 = row_gdk;
                var cp: [*]u8 = row_cairo;
                var col: c_int = w;
                while (col > 0) : (col -= 1) {
                    if (comptime builtin.cpu.arch.endian() == .little) {
                        cp[0] = gp[2];
                        cp[1] = gp[1];
                        cp[2] = gp[0];
                    } else {
                        cp[1] = gp[0];
                        cp[2] = gp[1];
                        cp[3] = gp[2];
                    }
                    gp += 3;
                    cp += 4;
                }
                row_gdk += row_stride;
                row_cairo += cairo_row_stride;
            }
        } else {
            var i: c_int = h;
            while (i > 0) : (i -= 1) {
                var gp: [*]const u8 = row_gdk;
                var cp: [*]u8 = row_cairo;
                var col: c_int = w;
                while (col > 0) : (col -= 1) {
                    if (comptime builtin.cpu.arch.endian() == .little) {
                        cp[0] = premulAlpha(gp[2], gp[3]);
                        cp[1] = premulAlpha(gp[1], gp[3]);
                        cp[2] = premulAlpha(gp[0], gp[3]);
                        cp[3] = gp[3];
                    } else {
                        cp[1] = premulAlpha(gp[0], gp[3]);
                        cp[2] = premulAlpha(gp[1], gp[3]);
                        cp[3] = premulAlpha(gp[2], gp[3]);
                        cp[0] = gp[3];
                    }
                    gp += 4;
                    cp += 4;
                }
                row_gdk += row_stride;
                row_cairo += cairo_row_stride;
            }
        }
        c.cairo_surface_mark_dirty(cs);
        return cs;
    }
} else struct {};

// Force-reference GdkExports so the exported symbol is emitted.
comptime {
    _ = GdkExports;
}
