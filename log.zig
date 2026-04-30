//! log.zig – Zig port of log.c.
//! Provides structured log output with timestamps, ANSI
//! colouring, and an optional in-memory ring-buffer overlay.

const std = @import("std");
const opts = @import("log_options");
const types = @import("types");

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cInclude("stdio.h");
    @cInclude("time.h");
    @cInclude("unistd.h");
});

// Declare these ourselves so the va_list parameter is *anyopaque,
// sidestepping the Zig VaListX86_64 / glibc __va_list_tag mismatch.
extern fn vfprintf(
    stream: ?*c.FILE,
    format: [*c]const u8,
    arg: *anyopaque,
) c_int;
extern fn vsnprintf(
    s: [*c]u8,
    n: usize,
    format: [*c]const u8,
    arg: *anyopaque,
) c_int;

// Importance levels – derived from the shared types enum.
const log_silent: c_int = @intFromEnum(types.LogImportance.silent);
const log_error: c_int = @intFromEnum(types.LogImportance.err);
const log_info: c_int = @intFromEnum(types.LogImportance.info);
const log_debug: c_int = @intFromEnum(types.LogImportance.debug);
const log_importance_last: c_int = @intFromEnum(types.LogImportance.last);

const verbosity_colors = [_][*:0]const u8{
    "", // LOG_SILENT
    "\x1B[1;31m", // LOG_ERROR
    "\x1B[1;34m", // LOG_INFO
    "\x1B[1;90m", // LOG_DEBUG
};

var log_importance: c_int = log_error;

/// Line count and length for the debug overlay ring buffer.
/// These must match LOG_OVERLAY_LINES / LOG_OVERLAY_LINE_LEN in log.h.
pub const overlay_lines = 24;
pub const overlay_line_len = 220;

const OverlayState = struct {
    ring: [overlay_lines][overlay_line_len]u8,
    snap: [overlay_lines][overlay_line_len]u8,
    head: usize,
    count: usize,
};

var overlay: if (opts.have_debug_overlay) OverlayState else void =
    if (opts.have_debug_overlay) std.mem.zeroes(OverlayState) else {};

/// Sets the global log verbosity threshold.
pub export fn swaylock_log_init(verbosity: c_int) callconv(.c) void {
    if (verbosity < log_importance_last) {
        log_importance = verbosity;
    }
}

/// Emits a formatted log line to stderr with a timestamp and
/// optional ANSI colour. The swaylock_log() macro in log.h calls
/// this directly.
pub export fn _swaylock_log(
    verbosity: c_int,
    fmt: [*c]const u8,
    ...,
) callconv(.c) void {
    if (verbosity > log_importance) return;

    var result: c.struct_tm = undefined;
    const t = c.time(null);
    _ = c.localtime_r(&t, &result);
    var tbuf: [26:0]u8 = undefined;
    _ = c.strftime(&tbuf, tbuf.len, "%F %T - ", &result);
    _ = c.fputs(&tbuf, c.stderr);

    const vi: usize = @min(
        @as(usize, @intCast(verbosity)),
        verbosity_colors.len - 1,
    );
    if (c.isatty(c.STDERR_FILENO) != 0) {
        _ = c.fputs(verbosity_colors[vi], c.stderr);
    }

    var ap = @cVaStart();
    // Copy the va_list before vfprintf consumes it so we can
    // still write the raw message into the overlay ring buffer.
    if (comptime opts.have_debug_overlay) {
        var ap2 = @cVaCopy(ap);
        _ = vsnprintf(
            @ptrCast(&overlay.ring[overlay.head]),
            overlay_line_len,
            fmt,
            @ptrCast(&ap2),
        );
        @cVaEnd(&ap2);
        overlay.head = (overlay.head + 1) % overlay_lines;
        if (overlay.count < overlay_lines) overlay.count += 1;
    }
    _ = vfprintf(c.stderr, fmt, @ptrCast(&ap));
    @cVaEnd(&ap);

    if (c.isatty(c.STDERR_FILENO) != 0) {
        _ = c.fputs("\x1B[0m", c.stderr);
    }
    _ = c.fputc('\n', c.stderr);
}

/// Returns a snapshot of the debug log overlay sorted oldest-first.
/// count_out is set to the number of valid lines (0..overlay_lines).
/// The returned pointer is to an internal static buffer; callers
/// must not free or write to it.
pub export fn swaylock_log_get_overlay(
    count_out: *c_int,
) callconv(.c) [*c][overlay_line_len]u8 {
    if (comptime !opts.have_debug_overlay) {
        count_out.* = 0;
        return undefined;
    }
    count_out.* = @intCast(overlay.count);
    const start =
        (overlay.head + overlay_lines - overlay.count) % overlay_lines;
    for (0..overlay.count) |i| {
        const idx = (start + i) % overlay_lines;
        @memcpy(&overlay.snap[i], &overlay.ring[idx]);
    }
    return @as([*c][overlay_line_len]u8, @ptrCast(&overlay.snap));
}

/// Strips leading "./" path components from a source file literal.
/// Used by the swaylock_log() macro to shorten __FILE__ strings.
pub export fn _swaylock_strip_path(
    filepath: [*c]const u8,
) callconv(.c) [*c]const u8 {
    var p = filepath;
    if (p[0] == '.') {
        while (p[0] == '.' or p[0] == '/') p += 1;
    }
    return p;
}
