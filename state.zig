const types = @import("types.zig");
const render = @import("render.zig");

const wl = types.c;

/// Returns a pointer to the struct enclosing the given wl_list member.
inline fn wlEntry(
    comptime T: type,
    comptime field: []const u8,
    node: *wl.wl_list,
) *T {
    return @ptrFromInt(@intFromPtr(node) - @offsetOf(T, field));
}

pub fn damageState(st: *types.SwaylockState) void {
    const head = &st.surfaces;
    var node = head.next;
    while (node != head) {
        const surface =
            wlEntry(types.SwaylockSurface, "link", node.?);
        node = surface.link.next;
        surface.dirty = true;
        render.render(surface);
    }
}
