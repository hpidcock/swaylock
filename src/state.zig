//! Helpers for managing global render state.

const types = @import("types.zig");
const render = @import("render.zig");

/// Marks every surface as dirty and triggers a re-render.
pub fn damageState(st: *types.State) void {
    for (st.surfaces.items) |surface| {
        surface.dirty = true;
        render.render(surface);
    }
}
