//! types.zig – Zig-native shared type definitions.
//! Replaces the shared local C headers: swaylock.h, pool-buffer.h,
//! seat.h, loop.h (struct types), background-image.h (mode enum),
//! comm.h (message constants), and log.h (importance enum).
//!
//! Only external C library headers are imported here.  All
//! project-local C headers are superseded by the Zig types below.

const std = @import("std");

/// External C library bindings re-exported for every module.
/// Covers Cairo, Wayland client, xkbcommon, and the generated
/// ext-session-lock protocol header.
/// poll.h and time.h supply the struct_pollfd / struct_timespec
/// layouts used by Loop and LoopTimer; replace with std.posix
/// equivalents once all field-name references (tv_sec, tv_nsec)
/// have been updated.
pub const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cInclude("errno.h");
    @cInclude("poll.h");
    @cInclude("time.h");
    @cInclude("cairo/cairo.h");
    @cInclude("wayland-client.h");
    @cInclude("xkbcommon/xkbcommon.h");
    @cInclude("ext-session-lock-v1-client-protocol.h");
});

// ── Background image ──────────────────────────────────────────────

/// Rendering mode for background images.
pub const BackgroundMode = enum(c_int) {
    stretch = 0,
    fill,
    fit,
    center,
    tile,
    solid_color,
    invalid,
};

// ── IPC message constants ─────────────────────────────────────────

/// Message type codes for the main↔PAM-child IPC protocol.
/// Frame layout: u8 type | u32 payload_len (LE) | u8 payload[].
pub const CommMsg = struct {
    // Sent from the main process to the PAM child.
    pub const password: u8 = 0x01;
    pub const broker_sel: u8 = 0x02;
    pub const auth_mode_sel: u8 = 0x03;
    pub const button: u8 = 0x04;
    pub const cancel: u8 = 0x05;
    // Sent from the PAM child to the main process.
    pub const auth_result: u8 = 0x81;
    pub const brokers: u8 = 0x82;
    pub const auth_modes: u8 = 0x83;
    pub const ui_layout: u8 = 0x84;
    pub const stage: u8 = 0x85;
    pub const auth_event: u8 = 0x86;
};

// ── Log importance ────────────────────────────────────────────────

/// Log verbosity levels; mirrors enum log_importance in log.h.
pub const LogImportance = enum(c_int) {
    silent = 0,
    err = 1,
    info = 2,
    debug = 3,
    last = 4,
};

// ── Event loop ────────────────────────────────────────────────────

/// Callback fired when a registered fd becomes ready.
pub const FdCallback = *const fn (
    fd: c_int,
    mask: c_short,
    data: ?*anyopaque,
) callconv(.c) void;

/// Callback fired when a one-shot timer expires.
pub const TimerCallback = *const fn (
    data: ?*anyopaque,
) callconv(.c) void;

/// Intrusive wl_list node pairing an fd with its callback.
pub const FdEvent = struct {
    callback: FdCallback,
    data: ?*anyopaque,
    link: c.wl_list,
};

/// A one-shot timer registered in the event loop.
pub const LoopTimer = struct {
    callback: TimerCallback,
    data: ?*anyopaque,
    expiry: c.struct_timespec,
    removed: bool,
    link: c.wl_list,
};

/// Poll-based event loop.  Owns a dynamically-sized pollfd array and
/// two intrusive wl_lists: one for fd events and one for timers.
pub const Loop = struct {
    fds: [*]c.struct_pollfd,
    fd_length: c_int,
    fd_capacity: c_int,
    fd_events: c.wl_list,
    timers: c.wl_list,
};

// ── Shared-memory pool buffer ─────────────────────────────────────

/// A Wayland shm buffer backed by a Cairo image surface.
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

// ── Keyboard / seat ───────────────────────────────────────────────

/// xkbcommon keyboard state.
pub const SwaylockXkb = struct {
    caps_lock: bool,
    control: bool,
    state: ?*c.xkb_state,
    context: ?*c.xkb_context,
    keymap: ?*c.xkb_keymap,
};

/// Wayland seat: pointer, keyboard, and key-repeat parameters.
pub const SwaylockSeat = struct {
    state: ?*SwaylockState,
    pointer: ?*c.wl_pointer,
    keyboard: ?*c.wl_keyboard,
    repeat_period_ms: i32,
    repeat_delay_ms: i32,
    repeat_sym: u32,
    repeat_codepoint: u32,
    repeat_timer: ?*LoopTimer,
};

// ── Authentication state ──────────────────────────────────────────

/// Status of the current authentication attempt.
pub const AuthState = enum(c_int) {
    idle = 0,
    validating,
    invalid,
};

/// Status of the password buffer and recent key presses.
pub const InputState = enum(c_int) {
    idle = 0,
    clear,
    letter,
    backspace,
    neutral,
};

/// Authd multi-stage authentication step.
pub const AuthdStage = enum(c_int) {
    none = 0,
    broker,
    auth_mode,
    challenge,
};

// ── Colours ───────────────────────────────────────────────────────

/// ARGB colour set for a single indicator role (ring, inside, etc.).
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

// ── Configuration ─────────────────────────────────────────────────

/// Parsed command-line / config-file arguments.
pub const SwaylockArgs = struct {
    colors: SwaylockColors,
    mode: BackgroundMode,
    font: [*c]u8,
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
    ready_fd: c_int,
    indicator_idle_visible: bool,
};

/// Locked, mlock'd password accumulation buffer.
pub const SwaylockPassword = struct {
    len: usize,
    buffer_len: usize,
    buffer: [*c]u8,
};

// ── Authd types ───────────────────────────────────────────────────

/// An authd authentication broker (id + display name).
pub const AuthdBroker = struct {
    id: [*c]u8,
    name: [*c]u8,
};

/// An authd authentication mode (id + display label).
pub const AuthdAuthMode = struct {
    id: [*c]u8,
    label: [*c]u8,
};

/// UI layout descriptor sent by the authd broker.
pub const AuthdUiLayout = struct {
    type: [*c]u8,
    label: [*c]u8,
    button: [*c]u8,
    /// Entry field hint: "chars", "chars_password", "digits", etc.
    entry: [*c]u8,
    wait: bool,
    /// Raw content to encode into a QR image.
    qr_content: [*c]u8,
    /// Human-readable fallback for the QR code.
    qr_code: [*c]u8,
};

// ── Global state ──────────────────────────────────────────────────

/// Global swaylock process state (one instance per process).
pub const SwaylockState = struct {
    eventloop: ?*Loop,
    input_idle_timer: ?*LoopTimer,
    auth_idle_timer: ?*LoopTimer,
    clear_password_timer: ?*LoopTimer,
    display: ?*c.wl_display,
    compositor: ?*c.wl_compositor,
    subcompositor: ?*c.wl_subcompositor,
    shm: ?*c.wl_shm,
    /// Head of the intrusive wl_list of SwaylockSurface.link nodes.
    surfaces: c.wl_list,
    /// Head of the intrusive wl_list of SwaylockImage.link nodes.
    images: c.wl_list,
    args: SwaylockArgs,
    password: SwaylockPassword,
    xkb: SwaylockXkb,
    /// Cairo surface/context used only for font-size measurements.
    test_surface: ?*c.cairo_surface_t,
    test_cairo: ?*c.cairo_t,
    auth_state: AuthState,
    input_state: InputState,
    /// Highlight arc start position; 2048 = one full revolution.
    highlight_start: u32,
    failed_attempts: c_int,
    run_display: bool,
    locked: bool,
    lock_failed: bool,
    ext_session_lock_manager_v1: ?*c.ext_session_lock_manager_v1,
    ext_session_lock_v1: ?*c.ext_session_lock_v1,
    // authd multi-stage fields; only meaningful when authd_active.
    authd_active: bool,
    authd_stage: AuthdStage,
    authd_brokers: ?[*]AuthdBroker,
    authd_num_brokers: c_int,
    /// Index of the selected broker; -1 = nothing selected yet.
    authd_sel_broker: c_int,
    authd_auth_modes: ?[*]AuthdAuthMode,
    authd_num_auth_modes: c_int,
    /// Index of the selected auth mode; -1 = nothing selected yet.
    authd_sel_auth_mode: c_int,
    authd_layout: AuthdUiLayout,
    /// Optional error / info message from the broker.
    authd_error: [*c]u8,
};

/// Per-output lock surface.
pub const SwaylockSurface = struct {
    image: ?*c.cairo_surface_t,
    state: ?*SwaylockState,
    output: ?*c.wl_output,
    output_global_name: u32,
    /// Background Wayland surface.
    surface: ?*c.wl_surface,
    /// Indicator child surface (made into a subsurface).
    child: ?*c.wl_surface,
    subsurface: ?*c.wl_subsurface,
    ext_session_lock_surface_v1: ?*c.ext_session_lock_surface_v1,
    indicator_buffers: [2]PoolBuffer,
    // Debug-overlay surfaces.  Always present in the struct so the
    // layout is independent of the have_debug_overlay option; fields
    // are null / zeroed when the feature is disabled.
    overlay: ?*c.wl_surface,
    overlay_sub: ?*c.wl_subsurface,
    overlay_buffers: [2]PoolBuffer,
    created: bool,
    dirty: bool,
    width: u32,
    height: u32,
    scale: i32,
    subpixel: c.wl_output_subpixel,
    output_name: [*c]u8,
    /// Intrusive wl_list node linked into SwaylockState.surfaces.
    link: c.wl_list,
    frame: ?*c.wl_callback,
    /// Size of the last wl_buffer committed to the background.
    last_buffer_width: c_int,
    last_buffer_height: c_int,
};

/// One background image (one per -i argument).
pub const SwaylockImage = struct {
    path: [*c]u8,
    output_name: [*c]u8,
    cairo_surface: ?*c.cairo_surface_t,
    /// Intrusive wl_list node linked into SwaylockState.images.
    link: c.wl_list,
};
