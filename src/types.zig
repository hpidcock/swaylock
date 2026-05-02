//! Zig-native shared type definitions for swaylock.
//! Replaces the C headers: swaylock.h, pool-buffer.h, seat.h,
//! loop.h, background-image.h, comm.h, and log.h.
//! Only external C library headers are imported via @cImport.

const std = @import("std");

/// External C library bindings used across all modules.
/// Includes Cairo, Wayland client, xkbcommon, and the generated
/// ext-session-lock protocol header.
pub const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cInclude("errno.h");
    @cInclude("poll.h");
    @cInclude("string.h");
    @cInclude("stdlib.h");
    @cInclude("wordexp.h");
    @cInclude("time.h");
    @cInclude("cairo/cairo.h");
    @cInclude("wayland-client.h");
    @cInclude("xkbcommon/xkbcommon.h");
    @cInclude("ext-session-lock-v1-client-protocol.h");
});

/// Rendering mode for background images.
pub const BackgroundMode = enum(i32) {
    stretch = 0,
    fill,
    fit,
    center,
    tile,
    solid_color,
    invalid,
};

/// IPC message type codes for main/PAM-child communication.
/// Frame: u8 type | u32 payload_len (LE) | u8 payload[].
pub const CommMsg = struct {
    // Main process to PAM child.
    pub const password: u8 = 0x01;
    pub const broker_sel: u8 = 0x02;
    pub const auth_mode_sel: u8 = 0x03;
    pub const button: u8 = 0x04;
    pub const cancel: u8 = 0x05;
    // PAM child to main process.
    pub const auth_result: u8 = 0x81;
    pub const brokers: u8 = 0x82;
    pub const auth_modes: u8 = 0x83;
    pub const ui_layout: u8 = 0x84;
    pub const stage: u8 = 0x85;
    pub const auth_event: u8 = 0x86;
};

/// Callback invoked when a registered fd becomes ready.
pub const FdCallback = *const fn (
    fd: i32,
    mask: i16,
    data: ?*anyopaque,
) callconv(.c) void;

/// Callback invoked when a one-shot timer expires.
pub const TimerCallback = *const fn (
    data: ?*anyopaque,
) callconv(.c) void;

/// File descriptor event registration.
pub const FdEvent = struct {
    callback: FdCallback,
    data: ?*anyopaque,
    fd: i32,
    mask: i16,
};

/// One-shot timer registered in the event loop.
pub const LoopTimer = struct {
    callback: TimerCallback,
    data: ?*anyopaque,
    expiry: std.posix.timespec,
    removed: bool,
};

/// Poll-based event loop managing fds and timers.
pub const Loop = struct {
    fd_events: std.ArrayListUnmanaged(FdEvent),
    timers: std.ArrayListUnmanaged(*LoopTimer),
};

/// Wayland shm buffer backed by a Cairo image surface.
pub const PoolBuffer = struct {
    buffer: ?*c.wl_buffer,
    surface: ?*c.cairo_surface_t,
    cairo: ?*c.cairo_t,
    width: u32,
    height: u32,
    data: ?*anyopaque,
    size: usize,
    busy: bool,
};

/// xkbcommon keyboard state.
pub const SwaylockXkb = struct {
    caps_lock: bool,
    control: bool,
    state: ?*c.xkb_state,
    context: ?*c.xkb_context,
    keymap: ?*c.xkb_keymap,
};

/// Wayland seat with pointer, keyboard, and repeat state.
pub const Seat = struct {
    g: ?*State,
    pointer: ?*c.wl_pointer,
    keyboard: ?*c.wl_keyboard,
    repeat_period_ms: i32,
    repeat_delay_ms: i32,
    repeat_sym: u32,
    repeat_codepoint: u32,
    repeat_timer: ?*LoopTimer,
};

/// Current authentication attempt status.
pub const AuthState = enum(i32) {
    idle = 0,
    validating,
    invalid,
};

/// Password buffer and recent keypress status.
pub const InputState = enum(i32) {
    idle = 0,
    clear,
    letter,
    backspace,
    neutral,
};

/// Authd multi-stage authentication step.
pub const AuthdStage = enum(i32) {
    none = 0,
    broker,
    auth_mode,
    challenge,
};

/// ARGB colour set for a single indicator role.
pub const SwaylockColorSet = struct {
    input: u32,
    cleared: u32,
    caps_lock: u32,
    verifying: u32,
    wrong: u32,
};

/// Complete colour palette for the lock indicator.
pub const SwaylockColors = struct {
    background: u32,
    bs_highlight: u32,
    key_highlight: u32,
    caps_lock_bs_highlight: u32,
    caps_lock_key_highlight: u32,
    separator: u32,
    layout_background: u32,
    layout_border: u32,
    layout_text: u32,
    inside: SwaylockColorSet,
    line: SwaylockColorSet,
    ring: SwaylockColorSet,
    text: SwaylockColorSet,
};

/// Parsed command-line and config-file arguments.
pub const SwaylockArgs = struct {
    colors: SwaylockColors,
    mode: BackgroundMode,
    font: ?[*:0]u8,
    font_size: u32,
    radius: u32,
    thickness: u32,
    indicator_x_position: u32,
    indicator_y_position: u32,
    override_indicator_x_position: bool,
    override_indicator_y_position: bool,
    ignore_empty: bool,
    steal_unlock: bool,
    show_indicator: bool,
    show_caps_lock_text: bool,
    show_caps_lock_indicator: bool,
    show_keyboard_layout: bool,
    hide_keyboard_layout: bool,
    show_failed_attempts: bool,
    daemonize: bool,
    ready_fd: i32,
    indicator_idle_visible: bool,
};

/// Locked, mlock'd password accumulation buffer.
pub const SwaylockPassword = struct {
    len: usize,
    buffer: ?[]u8,
};

/// Authd authentication broker (id and display name).
pub const AuthdBroker = struct {
    id: ?[*:0]u8,
    name: ?[*:0]u8,
};

/// Authd authentication mode (id and display label).
pub const AuthdAuthMode = struct {
    id: ?[*:0]u8,
    label: ?[*:0]u8,
};

/// UI layout descriptor from the authd broker.
pub const AuthdUiLayout = extern struct {
    type: ?[*:0]u8,
    label: ?[*:0]u8,
    button: ?[*:0]u8,
    /// Entry hint: "chars", "chars_password", "digits", etc.
    entry: ?[*:0]u8,
    wait: bool,
    /// Raw content to encode as a QR image.
    qr_content: ?[*:0]u8,
    /// Human-readable fallback for the QR code.
    qr_code: ?[*:0]u8,
};

/// Global swaylock process state (one per process).
pub const State = struct {
    eventloop: ?*Loop,
    input_idle_timer: ?*LoopTimer,
    auth_idle_timer: ?*LoopTimer,
    clear_password_timer: ?*LoopTimer,
    display: ?*c.wl_display,
    compositor: ?*c.wl_compositor,
    subcompositor: ?*c.wl_subcompositor,
    shm: ?*c.wl_shm,
    /// Per-output lock surfaces.
    surfaces: std.ArrayListUnmanaged(*Surface),
    /// Background images (one per -i argument).
    images: std.ArrayListUnmanaged(*Image),
    args: SwaylockArgs,
    password: SwaylockPassword,
    xkb: SwaylockXkb,
    /// Cairo surface used for font-size measurement.
    test_surface: ?*c.cairo_surface_t,
    test_cairo: ?*c.cairo_t,
    auth_state: AuthState,
    input_state: InputState,
    /// Highlight arc start; 2048 = one full revolution.
    highlight_start: u32,
    failed_attempts: i32,
    run_display: bool,
    locked: bool,
    lock_failed: bool,
    ext_session_lock_manager_v1: ?*c.ext_session_lock_manager_v1,
    ext_session_lock_v1: ?*c.ext_session_lock_v1,
    // Authd multi-stage fields; only used when authd_active.
    authd_active: bool,
    authd_stage: AuthdStage,
    authd_brokers: []AuthdBroker,
    /// Selected broker index; -1 means none selected.
    authd_sel_broker: i32,
    authd_auth_modes: []AuthdAuthMode,
    /// Selected auth mode index; -1 means none selected.
    authd_sel_auth_mode: i32,
    authd_layout: AuthdUiLayout,
    /// Error or info message from the broker.
    authd_error: ?[*:0]u8,
};

/// Per-output lock surface.
pub const Surface = struct {
    image: ?*c.cairo_surface_t,
    g: ?*State,
    output: ?*c.wl_output,
    output_global_name: u32,
    /// Background Wayland surface.
    surface: ?*c.wl_surface,
    /// Indicator child surface (subsurface).
    child: ?*c.wl_surface,
    subsurface: ?*c.wl_subsurface,
    ext_session_lock_surface_v1: ?*c.ext_session_lock_surface_v1,
    indicator_buffers: [2]PoolBuffer,
    // Debug-overlay fields are always present for layout
    // stability; null/zeroed when the feature is disabled.
    overlay: ?*c.wl_surface,
    overlay_sub: ?*c.wl_subsurface,
    overlay_buffers: [2]PoolBuffer,
    created: bool,
    dirty: bool,
    width: u32,
    height: u32,
    scale: i32,
    subpixel: c.wl_output_subpixel,
    output_name: ?[*:0]u8,
    frame: ?*c.wl_callback,
    /// Size of the last committed background buffer.
    last_buffer_width: i32,
    last_buffer_height: i32,
};

/// One background image (one per -i argument).
pub const Image = struct {
    path: ?[*:0]u8,
    output_name: ?[*:0]u8,
    cairo_surface: ?*c.cairo_surface_t,
};

pub const LineMode = enum { line, inside, ring };
