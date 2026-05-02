//! Process-wide allocator singletons for the swaylock Wayland
//! lock screen.
//!
//! Provides three allocators:
//!   general()  - FixedBuffer in release, DebugAllocator in debug
//!   render()   - arena allocator, reset each frame
//!   c_ffi      - always c_allocator for C FFI boundaries
//!
//! Call init() once at process start and deinit() on clean exit.

const std = @import("std");
const builtin = @import("builtin");

const is_debug = builtin.mode == .Debug;

var da: std.heap.DebugAllocator(.{}) = .{};

/// 256 KiB static backing buffer for the fixed-buffer allocator.
var gen_buf: [256 * 1024]u8 = undefined;
var gen_fba: std.heap.FixedBufferAllocator = undefined;

// In debug builds a DebugAllocator backs the arena so that
// resetRender() can check for leaks between frames.
// In release builds a plain PageAllocator is used instead.
var render_da: std.heap.DebugAllocator(.{}) = .{};
var render_arena: std.heap.ArenaAllocator = undefined;

/// Initialise all allocator singletons.
/// Must be called once before general() or render() are used.
pub fn init() void {
    gen_fba = .init(&gen_buf);
    if (is_debug) {
        render_da = .{};
        render_arena = .init(render_da.allocator());
    } else {
        render_arena = .init(std.heap.page_allocator);
    }
}

/// Release arena memory and check for leaks in debug builds.
pub fn deinit() void {
    render_arena.deinit();
    if (is_debug) {
        _ = render_da.deinit();
        _ = da.deinit();
    }
}

/// General-purpose allocator for non-render, non-FFI use.
/// Release: fixed-buffer over a 256 KiB static buffer.
/// Debug: DebugAllocator for leak/use-after-free detection.
pub fn general() std.mem.Allocator {
    return if (is_debug) da.allocator() else gen_fba.allocator();
}

/// Arena allocator for per-frame render allocations.
/// Reset between frames via resetRender().
pub fn render() std.mem.Allocator {
    return render_arena.allocator();
}

/// Reset the render arena between frames.
/// In release mode backing pages are retained for reuse.
/// In debug mode the arena and its backing allocator are
/// torn down to detect leaks, then reinitialised.
pub fn resetRender() void {
    if (is_debug) {
        render_arena.deinit();
        _ = render_da.deinit();
        render_da = .{};
        render_arena = .init(render_da.allocator());
    } else {
        _ = render_arena.reset(.retain_capacity);
    }
}

/// C allocator, used exclusively at FFI boundaries.
pub const c_ffi: std.mem.Allocator = std.heap.c_allocator;
