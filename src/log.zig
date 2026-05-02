//! Structured logging with UTC timestamps, ANSI colour output,
//! and an optional in-memory ring buffer for a debug overlay.

const std = @import("std");
const opts = @import("log_options");
const types = @import("types.zig");

/// Log verbosity levels used for filtering output.
pub const LogImportance = enum(u32) {
    silent = 0,
    err = 1,
    info = 2,
    debug = 3,
    last = 4,
};

const verbosity_colors = [LogImportance][]const u8{};

var log_importance = LogImportance.err;

/// Ring buffer dimensions for the debug overlay.
/// Must match LOG_OVERLAY_LINES / LOG_OVERLAY_LINE_LEN in log.h.
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
pub fn logInit(verbosity: LogImportance) void {
    if (@intFromEnum(verbosity) < @intFromEnum(LogImportance.last)) {
        log_importance = verbosity;
    } else {
        log_importance = LogImportance.debug;
    }
}

/// Writes a log line to stderr with a UTC timestamp and
/// optional ANSI colour based on verbosity.
fn swayLog(verbosity: LogImportance, msg: []const u8) void {
    if (@intFromEnum(verbosity) > @intFromEnum(log_importance)) return;

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

    // Format a UTC timestamp. We use UTC because localtime
    // is unavailable without libc.
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
        w.writeAll(switch (verbosity) {
            LogImportance.silent => "",
            LogImportance.err => "\x1B[1;31m",
            LogImportance.info => "\x1B[1;34m",
            LogImportance.debug => "\x1B[1;90m",
            else => "",
        }) catch {};
    }
    w.writeAll(msg) catch {};
    if (use_color) w.writeAll("\x1B[0m") catch {};
    w.writeByte('\n') catch {};
    bw.flush() catch {};
}

/// Primary logging function. Formats a message with source
/// location prepended, then delegates to swayLog.
pub fn slog(
    verbosity: LogImportance,
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

/// Returns a snapshot of the overlay ring buffer sorted
/// oldest-first. Sets count_out to the number of valid lines.
/// The returned pointer refers to an internal static buffer;
/// callers must not free or write to it.
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

/// Strips leading "./" components from a file path.
fn stripPath(filepath: []const u8) []const u8 {
    if (filepath.len == 0 or filepath[0] != '.') return filepath;
    var i: usize = 0;
    while (i < filepath.len and
        (filepath[i] == '.' or filepath[i] == '/')) : (i += 1)
    {}
    return filepath[i..];
}
