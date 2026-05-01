//! CLI parameter definitions for swaylock.

const std = @import("std");
const clap = @import("clap");
const opts = @import("main_options");

const types = @import("types.zig");
const log = @import("log.zig");
const background_image = @import("background-image.zig");

const c = types.c;

/// Typed IDs for all CLI options. Short options use their ASCII
/// value; long-only options are assigned values starting at 256.
pub const OptId = enum(u16) {
    config = 'C',
    color = 'c',
    debug = 'd',
    ignore_empty = 'e',
    show_failed_attempts = 'F',
    daemonize = 'f',
    ready_fd = 'R',
    help = 'h',
    image = 'i',
    show_keyboard_layout = 'k',
    hide_keyboard_layout = 'K',
    disable_caps_lock_text = 'L',
    indicator_caps_lock = 'l',
    line_uses_inside = 'n',
    line_uses_ring = 'r',
    scaling = 's',
    tiling = 't',
    no_unlock_indicator = 'u',
    version = 'v',
    bs_hl_color = 256,
    caps_lock_bs_hl_color,
    caps_lock_key_hl_color,
    font,
    font_size,
    ind_idle_visible,
    ind_radius,
    ind_x_position,
    ind_y_position,
    ind_thickness,
    inside_color,
    inside_clear_color,
    inside_caps_lock_color,
    inside_ver_color,
    inside_wrong_color,
    key_hl_color,
    layout_txt_color,
    layout_bg_color,
    layout_border_color,
    line_color,
    line_clear_color,
    line_caps_lock_color,
    line_ver_color,
    line_wrong_color,
    ring_color,
    ring_clear_color,
    ring_caps_lock_color,
    ring_ver_color,
    ring_wrong_color,
    sep_color,
    text_color,
    text_clear_color,
    text_caps_lock_color,
    text_ver_color,
    text_wrong_color,
    steal_unlock,
};

/// All recognised CLI parameters, keyed by OptId.
pub const params = [_]clap.Param(OptId){
    .{ .id = .config, .names = .{ .short = 'C', .long = "config" }, .takes_value = .one },
    .{ .id = .color, .names = .{ .short = 'c', .long = "color" }, .takes_value = .one },
    .{ .id = .debug, .names = .{ .short = 'd', .long = "debug" } },
    .{ .id = .ignore_empty, .names = .{ .short = 'e', .long = "ignore-empty-password" } },
    .{ .id = .show_failed_attempts, .names = .{ .short = 'F', .long = "show-failed-attempts" } },
    .{ .id = .daemonize, .names = .{ .short = 'f', .long = "daemonize" } },
    .{ .id = .ready_fd, .names = .{ .short = 'R', .long = "ready-fd" }, .takes_value = .one },
    .{ .id = .help, .names = .{ .short = 'h', .long = "help" } },
    .{ .id = .image, .names = .{ .short = 'i', .long = "image" }, .takes_value = .one },
    .{ .id = .show_keyboard_layout, .names = .{ .short = 'k', .long = "show-keyboard-layout" } },
    .{ .id = .hide_keyboard_layout, .names = .{ .short = 'K', .long = "hide-keyboard-layout" } },
    .{ .id = .disable_caps_lock_text, .names = .{ .short = 'L', .long = "disable-caps-lock-text" } },
    .{ .id = .indicator_caps_lock, .names = .{ .short = 'l', .long = "indicator-caps-lock" } },
    .{ .id = .line_uses_inside, .names = .{ .short = 'n', .long = "line-uses-inside" } },
    .{ .id = .line_uses_ring, .names = .{ .short = 'r', .long = "line-uses-ring" } },
    .{ .id = .scaling, .names = .{ .short = 's', .long = "scaling" }, .takes_value = .one },
    .{ .id = .tiling, .names = .{ .short = 't', .long = "tiling" } },
    .{ .id = .no_unlock_indicator, .names = .{ .short = 'u', .long = "no-unlock-indicator" } },
    .{ .id = .version, .names = .{ .short = 'v', .long = "version" } },
    .{ .id = .bs_hl_color, .names = .{ .long = "bs-hl-color" }, .takes_value = .one },
    .{ .id = .caps_lock_bs_hl_color, .names = .{ .long = "caps-lock-bs-hl-color" }, .takes_value = .one },
    .{ .id = .caps_lock_key_hl_color, .names = .{ .long = "caps-lock-key-hl-color" }, .takes_value = .one },
    .{ .id = .font, .names = .{ .long = "font" }, .takes_value = .one },
    .{ .id = .font_size, .names = .{ .long = "font-size" }, .takes_value = .one },
    .{ .id = .ind_idle_visible, .names = .{ .long = "indicator-idle-visible" } },
    .{ .id = .ind_radius, .names = .{ .long = "indicator-radius" }, .takes_value = .one },
    .{ .id = .ind_thickness, .names = .{ .long = "indicator-thickness" }, .takes_value = .one },
    .{ .id = .ind_x_position, .names = .{ .long = "indicator-x-position" }, .takes_value = .one },
    .{ .id = .ind_y_position, .names = .{ .long = "indicator-y-position" }, .takes_value = .one },
    .{ .id = .inside_color, .names = .{ .long = "inside-color" }, .takes_value = .one },
    .{ .id = .inside_clear_color, .names = .{ .long = "inside-clear-color" }, .takes_value = .one },
    .{ .id = .inside_caps_lock_color, .names = .{ .long = "inside-caps-lock-color" }, .takes_value = .one },
    .{ .id = .inside_ver_color, .names = .{ .long = "inside-ver-color" }, .takes_value = .one },
    .{ .id = .inside_wrong_color, .names = .{ .long = "inside-wrong-color" }, .takes_value = .one },
    .{ .id = .key_hl_color, .names = .{ .long = "key-hl-color" }, .takes_value = .one },
    .{ .id = .layout_bg_color, .names = .{ .long = "layout-bg-color" }, .takes_value = .one },
    .{ .id = .layout_border_color, .names = .{ .long = "layout-border-color" }, .takes_value = .one },
    .{ .id = .layout_txt_color, .names = .{ .long = "layout-text-color" }, .takes_value = .one },
    .{ .id = .line_color, .names = .{ .long = "line-color" }, .takes_value = .one },
    .{ .id = .line_clear_color, .names = .{ .long = "line-clear-color" }, .takes_value = .one },
    .{ .id = .line_caps_lock_color, .names = .{ .long = "line-caps-lock-color" }, .takes_value = .one },
    .{ .id = .line_ver_color, .names = .{ .long = "line-ver-color" }, .takes_value = .one },
    .{ .id = .line_wrong_color, .names = .{ .long = "line-wrong-color" }, .takes_value = .one },
    .{ .id = .ring_color, .names = .{ .long = "ring-color" }, .takes_value = .one },
    .{ .id = .ring_clear_color, .names = .{ .long = "ring-clear-color" }, .takes_value = .one },
    .{ .id = .ring_caps_lock_color, .names = .{ .long = "ring-caps-lock-color" }, .takes_value = .one },
    .{ .id = .ring_ver_color, .names = .{ .long = "ring-ver-color" }, .takes_value = .one },
    .{ .id = .ring_wrong_color, .names = .{ .long = "ring-wrong-color" }, .takes_value = .one },
    .{ .id = .sep_color, .names = .{ .long = "separator-color" }, .takes_value = .one },
    .{ .id = .text_color, .names = .{ .long = "text-color" }, .takes_value = .one },
    .{ .id = .text_clear_color, .names = .{ .long = "text-clear-color" }, .takes_value = .one },
    .{ .id = .text_caps_lock_color, .names = .{ .long = "text-caps-lock-color" }, .takes_value = .one },
    .{ .id = .text_ver_color, .names = .{ .long = "text-ver-color" }, .takes_value = .one },
    .{ .id = .text_wrong_color, .names = .{ .long = "text-wrong-color" }, .takes_value = .one },
    .{ .id = .steal_unlock, .names = .{ .long = "steal-unlock" } },
};

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

pub fn parseOptions(
    argc: c_int,
    argv: [*c][*c]u8,
    st: ?*types.SwaylockState,
    line_mode: ?*types.LineMode,
    config_path: ?*[*c]u8,
) c_int {
    const allocator = std.heap.c_allocator;
    var args_list = std.ArrayList([]const u8).init(allocator);
    defer args_list.deinit();
    for (1..@as(usize, @intCast(argc))) |i| {
        args_list.append(
            std.mem.sliceTo(argv[i], 0),
        ) catch {
            log.slog(log.LogImportance.err, @src(), "OOM", .{});
            return 1;
        };
    }
    var iter = clap.args.SliceIterator{
        .args = args_list.items,
    };
    var diag = clap.Diagnostic{};
    var parser = clap.streaming.Clap(
        OptId,
        clap.args.SliceIterator,
    ){
        .params = &params,
        .iter = &iter,
        .diagnostic = &diag,
    };
    while (parser.next() catch {
        std.debug.print("{s}", .{usage});
        return 1;
    }) |arg| {
        const val: ?[]const u8 = arg.value;
        switch (arg.param.id) {
            .help => {
                std.io.getStdOut().writeAll(usage) catch {};
                std.process.exit(0);
            },
            .version => {
                std.io.getStdOut().writer().print(
                    "swaylock version {s}\n",
                    .{opts.swaylock_version},
                ) catch {};
                std.process.exit(0);
            },
            .debug => log.logInit(log.LogImportance.debug),
            .config => {
                if (config_path) |cp|
                    cp.* = c.strdup(val.?.ptr);
            },
            .color => {
                if (st) |s|
                    s.args.colors.background =
                        parseColor(val.?.ptr);
            },
            .ignore_empty => {
                if (st) |s| s.args.ignore_empty = true;
            },
            .show_failed_attempts => {
                if (st) |s| s.args.show_failed_attempts = true;
            },
            .daemonize => {
                if (st) |s| s.args.daemonize = true;
            },
            .ready_fd => {
                if (st) |s|
                    s.args.ready_fd = std.fmt.parseInt(
                        i32,
                        val.?,
                        10,
                    ) catch {
                        log.slog(
                            log.LogImportance.err,
                            @src(),
                            "Invalid ready-fd value",
                            .{},
                        );
                        return 1;
                    };
            },
            .image => {
                if (st) |s|
                    loadImage(@constCast(val.?.ptr), s);
            },
            .show_keyboard_layout => {
                if (st) |s| s.args.show_keyboard_layout = true;
            },
            .hide_keyboard_layout => {
                if (st) |s| s.args.hide_keyboard_layout = true;
            },
            .disable_caps_lock_text => {
                if (st) |s| s.args.show_caps_lock_text = false;
            },
            .indicator_caps_lock => {
                if (st) |s| s.args.show_caps_lock_indicator = true;
            },
            .line_uses_inside => {
                if (line_mode) |lm| lm.* = .inside;
            },
            .line_uses_ring => {
                if (line_mode) |lm| lm.* = .ring;
            },
            .scaling => {
                if (st) |s| {
                    s.args.mode =
                        background_image.parseBackgroundMode(
                            val.?,
                        );
                    if (s.args.mode == .invalid) return 1;
                }
            },
            .tiling => {
                if (st) |s| s.args.mode = .tile;
            },
            .no_unlock_indicator => {
                if (st) |s| s.args.show_indicator = false;
            },
            .bs_hl_color => {
                if (st) |s|
                    s.args.colors.bs_highlight =
                        parseColor(val.?.ptr);
            },
            .caps_lock_bs_hl_color => {
                if (st) |s|
                    s.args.colors.caps_lock_bs_highlight =
                        parseColor(val.?.ptr);
            },
            .caps_lock_key_hl_color => {
                if (st) |s|
                    s.args.colors.caps_lock_key_highlight =
                        parseColor(val.?.ptr);
            },
            .font => {
                if (st) |s| {
                    c.free(@ptrCast(s.args.font));
                    s.args.font = @ptrCast(c.strdup(val.?.ptr));
                }
            },
            .font_size => {
                if (st) |s|
                    s.args.font_size =
                        std.fmt.parseInt(u32, val.?, 10) catch 0;
            },
            .ind_idle_visible => {
                if (st) |s| s.args.indicator_idle_visible = true;
            },
            .ind_radius => {
                if (st) |s|
                    s.args.radius =
                        std.fmt.parseInt(u32, val.?, 0) catch 50;
            },
            .ind_thickness => {
                if (st) |s|
                    s.args.thickness =
                        std.fmt.parseInt(u32, val.?, 0) catch 10;
            },
            .ind_x_position => {
                if (st) |s| {
                    s.args.override_indicator_x_position = true;
                    s.args.indicator_x_position =
                        std.fmt.parseInt(u32, val.?, 10) catch 0;
                }
            },
            .ind_y_position => {
                if (st) |s| {
                    s.args.override_indicator_y_position = true;
                    s.args.indicator_y_position =
                        std.fmt.parseInt(u32, val.?, 10) catch 0;
                }
            },
            .inside_color => {
                if (st) |s|
                    s.args.colors.inside.input =
                        parseColor(val.?.ptr);
            },
            .inside_clear_color => {
                if (st) |s|
                    s.args.colors.inside.cleared =
                        parseColor(val.?.ptr);
            },
            .inside_caps_lock_color => {
                if (st) |s|
                    s.args.colors.inside.caps_lock =
                        parseColor(val.?.ptr);
            },
            .inside_ver_color => {
                if (st) |s|
                    s.args.colors.inside.verifying =
                        parseColor(val.?.ptr);
            },
            .inside_wrong_color => {
                if (st) |s|
                    s.args.colors.inside.wrong =
                        parseColor(val.?.ptr);
            },
            .key_hl_color => {
                if (st) |s|
                    s.args.colors.key_highlight =
                        parseColor(val.?.ptr);
            },
            .layout_bg_color => {
                if (st) |s|
                    s.args.colors.layout_background =
                        parseColor(val.?.ptr);
            },
            .layout_border_color => {
                if (st) |s|
                    s.args.colors.layout_border =
                        parseColor(val.?.ptr);
            },
            .layout_txt_color => {
                if (st) |s|
                    s.args.colors.layout_text =
                        parseColor(val.?.ptr);
            },
            .line_color => {
                if (st) |s|
                    s.args.colors.line.input =
                        parseColor(val.?.ptr);
            },
            .line_clear_color => {
                if (st) |s|
                    s.args.colors.line.cleared =
                        parseColor(val.?.ptr);
            },
            .line_caps_lock_color => {
                if (st) |s|
                    s.args.colors.line.caps_lock =
                        parseColor(val.?.ptr);
            },
            .line_ver_color => {
                if (st) |s|
                    s.args.colors.line.verifying =
                        parseColor(val.?.ptr);
            },
            .line_wrong_color => {
                if (st) |s|
                    s.args.colors.line.wrong =
                        parseColor(val.?.ptr);
            },
            .ring_color => {
                if (st) |s|
                    s.args.colors.ring.input =
                        parseColor(val.?.ptr);
            },
            .ring_clear_color => {
                if (st) |s|
                    s.args.colors.ring.cleared =
                        parseColor(val.?.ptr);
            },
            .ring_caps_lock_color => {
                if (st) |s|
                    s.args.colors.ring.caps_lock =
                        parseColor(val.?.ptr);
            },
            .ring_ver_color => {
                if (st) |s|
                    s.args.colors.ring.verifying =
                        parseColor(val.?.ptr);
            },
            .ring_wrong_color => {
                if (st) |s|
                    s.args.colors.ring.wrong =
                        parseColor(val.?.ptr);
            },
            .sep_color => {
                if (st) |s|
                    s.args.colors.separator =
                        parseColor(val.?.ptr);
            },
            .text_color => {
                if (st) |s|
                    s.args.colors.text.input =
                        parseColor(val.?.ptr);
            },
            .text_clear_color => {
                if (st) |s|
                    s.args.colors.text.cleared =
                        parseColor(val.?.ptr);
            },
            .text_caps_lock_color => {
                if (st) |s|
                    s.args.colors.text.caps_lock =
                        parseColor(val.?.ptr);
            },
            .text_ver_color => {
                if (st) |s|
                    s.args.colors.text.verifying =
                        parseColor(val.?.ptr);
            },
            .text_wrong_color => {
                if (st) |s|
                    s.args.colors.text.wrong =
                        parseColor(val.?.ptr);
            },
            .steal_unlock => {
                if (st) |s| s.args.steal_unlock = true;
            },
        }
    }
    return 0;
}

fn parseColor(color_in: [*c]const u8) u32 {
    var color = color_in;
    if (color[0] == '#') color += 1;
    const len = c.strlen(color);
    if (len != 6 and len != 8) {
        log.slog(
            log.LogImportance.debug,
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

fn lenientStrcmp(
    a: ?[*:0]const u8,
    b: ?[*:0]const u8,
) i32 {
    if (a == b) return 0;
    if (a == null) return -1;
    if (b == null) return 1;
    return c.strcmp(@ptrCast(a), @ptrCast(b));
}

fn joinArgs(argv: [*c][*c]u8, argc: i32) [*c]u8 {
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
    const allocator = std.heap.c_allocator;
    const image = allocator.create(
        types.SwaylockImage,
    ) catch @panic("OOM");
    image.* = .{
        .path = null,
        .output_name = null,
        .cairo_surface = null,
    };
    const separator: [*c]u8 = c.strchr(arg, ':');
    if (separator != null) {
        separator[0] = 0;
        image.output_name = if (separator == arg)
            null
        else
            @ptrCast(c.strdup(arg));
        image.path = @ptrCast(c.strdup(separator + 1));
    } else {
        image.output_name = null;
        image.path = @ptrCast(c.strdup(arg));
    }
    // Replace any existing image for the same output.
    for (st.images.items, 0..) |iter_image, idx| {
        if (lenientStrcmp(
            iter_image.output_name,
            image.output_name,
        ) != 0) continue;
        if (image.output_name != null) {
            log.slog(
                log.LogImportance.debug,
                @src(),
                "Replacing image defined for output {s} with {s}",
                .{
                    if (image.output_name) |n| @as([*:0]const u8, n) else "(null)",
                    if (image.path) |p| @as([*:0]const u8, p) else "(null)",
                },
            );
        } else {
            log.slog(
                log.LogImportance.debug,
                @src(),
                "Replacing default image with {s}",
                .{if (image.path) |p| @as([*:0]const u8, p) else "(null)"},
            );
        }
        _ = st.images.swapRemove(idx);
        c.free(iter_image.cairo_surface);
        c.free(@ptrCast(iter_image.output_name));
        c.free(@ptrCast(iter_image.path));
        allocator.destroy(iter_image);
        break;
    }
    // Escape double spaces so wordexp handles the path correctly.
    while (c.strstr(@ptrCast(image.path), "  ") != null) {
        const old_len = c.strlen(@ptrCast(image.path));
        image.path = @ptrCast(
            c.realloc(@ptrCast(image.path), old_len + 2),
        );
        const ptr: [*c]u8 = c.strstr(@ptrCast(image.path), "  ") + 1;
        _ = c.memmove(ptr + 1, ptr, c.strlen(ptr) + 1);
        ptr[0] = '\\';
    }
    var p: c.wordexp_t = undefined;
    if (c.wordexp(@ptrCast(image.path), &p, 0) == 0) {
        c.free(@ptrCast(image.path));
        image.path = @ptrCast(
            joinArgs(p.we_wordv, @intCast(p.we_wordc)),
        );
        c.wordfree(&p);
    }
    image.cairo_surface = background_image.loadBackgroundImage(
        std.mem.span(image.path.?),
    );
    if (image.cairo_surface == null) {
        allocator.destroy(image);
        return;
    }
    st.images.append(allocator, image) catch @panic("OOM");
    log.slog(
        log.LogImportance.debug,
        @src(),
        "Loaded image {s} for output {s}",
        .{
            if (image.path) |img_path| @as([*:0]const u8, img_path) else "(null)",
            if (image.output_name) |n| @as([*:0]const u8, n) else "*",
        },
    );
}
