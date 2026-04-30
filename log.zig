//! log.zig – structured log output with timestamps, ANSI
//! colouring, and an optional in-memory ring-buffer overlay.

const std = @import("std");
const opts = @import("log_options");
const types = @import("types");

// Importance levels – derived from the shared types enum.
const log_silent: i32 = @intFromEnum(types.LogImportance.silent);
const log_error: i32 = @intFromEnum(types.LogImportance.err);
const log_info: i32 = @intFromEnum(types.LogImportance.info);
const log_debug: i32 = @intFromEnum(types.LogImportance.debug);
const log_importance_last: i32 = @intFromEnum(types.LogImportance.last);

const verbosity_colors = [_][]const u8{
    "", // LOG_SILENT
    "\x1B[1;31m", // LOG_ERROR
    "\x1B[1;34m", // LOG_INFO
    "\x1B[1;90m", // LOG_DEBUG
};

var log_importance: i32 = log_error;

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
pub fn logInit(verbosity: i32) void {
    if (verbosity < log_importance_last) {
        log_importance = verbosity;
    }
}

/// Emits a log line to stderr with a UTC timestamp and optional
/// ANSI colour.
pub fn swayLog(verbosity: i32, msg: []const u8) void {
    if (verbosity > log_importance) return;

    if (comptime opts.have_debug_overlay) {
        const line = &overlay.ring[overlay.head];
        const n = @min(msg.len, overlay_line_len - 1);
        @memcpy(line[0..n], msg[0..n]);
        line[n] = 0;
        overlay.head = (overlay.head + 1) % overlay_lines;
        if (overlay.count < overlay_lines) overlay.count += 1;
    }

    const stderr = std.io.getStdErr();
    const use_color = std.posix.isatty(stderr.handle);

    // Format UTC timestamp. localtime is unavailable without C;
    // timestamps are displayed in UTC.
    const ep = std.time.epoch;
    const secs: u64 = @intCast(std.time.timestamp());
    const epoch_secs = ep.EpochSeconds{ .secs = secs };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();

    var tbuf: [32]u8 = undefined;
    const ts = std.fmt.bufPrint(
        &tbuf,
        "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} - ",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        },
    ) catch "???? - ";

    var bw = std.io.bufferedWriter(stderr.writer());
    const w = bw.writer();
    w.writeAll(ts) catch {};
    if (use_color) {
        const vi: usize = @min(
            @as(usize, @intCast(verbosity)),
            verbosity_colors.len - 1,
        );
        w.writeAll(verbosity_colors[vi]) catch {};
    }
    w.writeAll(msg) catch {};
    if (use_color) w.writeAll("\x1B[0m") catch {};
    w.writeByte('\n') catch {};
    bw.flush() catch {};
}

/// Emits a formatted log line with source location prepended.
pub fn slog(
    verbosity: i32,
    src: std.builtin.SourceLocation,
    comptime fmt: []const u8,
    args: anytype,
) void {
    var msg_buf: [500]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &msg_buf,
        fmt,
        args,
    ) catch return;
    var full_buf: [600]u8 = undefined;
    const full = std.fmt.bufPrint(
        &full_buf,
        "[{s}:{d}] {s}",
        .{ stripPath(src.file), src.line, msg },
    ) catch return;
    swayLog(verbosity, full);
}

/// Returns a snapshot of the debug log overlay sorted oldest-first.
/// count_out is set to the number of valid lines (0..overlay_lines).
/// The returned pointer is to an internal static buffer; callers
/// must not free or write to it.
pub fn getOverlay(count_out: *i32) ?[*][overlay_line_len]u8 {
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
    return @as(?[*][overlay_line_len]u8, @ptrCast(&overlay.snap));
}

/// Strips leading "./" path components from a file path literal.
pub fn stripPath(filepath: []const u8) []const u8 {
    if (filepath.len == 0 or filepath[0] != '.') return filepath;
    var i: usize = 0;
    while (i < filepath.len and
        (filepath[i] == '.' or filepath[i] == '/')) : (i += 1)
    {}
    return filepath[i..];
}
