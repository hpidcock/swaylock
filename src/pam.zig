//! PAM authentication and GDM/authd JSON protocol handling.

const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");
const comm = @import("comm.zig");
const password_buffer = @import("password_buffer.zig");

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    @cInclude("pwd.h");
    @cInclude("security/pam_appl.h");
    @cInclude("stdlib.h");
});

// GDM PAM extension types from gdm-pam-extensions-common.h and
// gdm-custom-json-pam-extension.h, re-implemented in Zig.
const GdmPamExtensionMessage = extern struct {
    length: u32,
    type: u8,
};

/// GDM PAM extension JSON protocol message.
const GdmPamExtensionJSONProtocol = extern struct {
    header: GdmPamExtensionMessage,
    protocol_name: [64]u8,
    version: c_uint,
    json: [*c]u8,
};

const authd_gdm_json_proto_name = "com.ubuntu.authd.gdm";
const authd_gdm_json_proto_version: c_uint = 1;
const gdm_pam_extension_custom_json =
    "org.gnome.DisplayManager.UserVerifier.CustomJSON";

// Static putenv buffer; must persist because putenv does not copy.
var gdm_pam_ext_env = std.mem.zeroes([4096]u8);

/// Sets GDM_SUPPORTED_PAM_EXTENSIONS so PAM modules can use
/// the authd GDM JSON extension.
fn gdmAdvertiseExtensions() void {
    const env_str = "GDM_SUPPORTED_PAM_EXTENSIONS=" ++
        gdm_pam_extension_custom_json;
    @memcpy(gdm_pam_ext_env[0..env_str.len], env_str);
    gdm_pam_ext_env[env_str.len] = 0;
    _ = c.putenv(@as([*c]u8, @ptrCast(&gdm_pam_ext_env)));
}

// Looks up the type index of name in GDM_SUPPORTED_PAM_EXTENSIONS.
fn gdmLookUpType(name: []const u8) ?u8 {
    const env_ptr = c.getenv(
        "GDM_SUPPORTED_PAM_EXTENSIONS",
    ) orelse return null;
    var it = std.mem.tokenizeScalar(
        u8,
        std.mem.span(env_ptr),
        ' ',
    );
    var t: u8 = 0;
    while (it.next()) |token| {
        if (std.mem.eql(u8, token, name)) return t;
        if (t == std.math.maxInt(u8)) break;
        t += 1;
    }
    return null;
}

/// Populates a GDM PAM extension request with the authd protocol
/// name, version, and the given JSON string.
fn gdmRequestInit(
    req: *GdmPamExtensionJSONProtocol,
    json: [*c]u8,
) void {
    req.header.type =
        gdmLookUpType(gdm_pam_extension_custom_json) orelse 0;
    req.header.length = std.mem.nativeToBig(
        u32,
        @sizeOf(GdmPamExtensionJSONProtocol),
    );
    const proto_len = @min(
        authd_gdm_json_proto_name.len,
        req.protocol_name.len - 1,
    );
    @memcpy(
        req.protocol_name[0..proto_len],
        authd_gdm_json_proto_name[0..proto_len],
    );
    req.protocol_name[proto_len] = 0;
    req.version = authd_gdm_json_proto_version;
    req.json = json;
}

/// Validates protocol name and version in a GDM message.
fn gdmMessageIsValid(msg: *const GdmPamExtensionJSONProtocol) bool {
    if (msg.version != authd_gdm_json_proto_version) return false;
    const name = std.mem.sliceTo(&msg.protocol_name, 0);
    return std.mem.eql(u8, name, authd_gdm_json_proto_name);
}

// Serialises v to JSON as an allocator-owned []u8.
fn jsonStringifyAllocBytes(
    alloc: std.mem.Allocator,
    v: anytype,
) ![]u8 {
    if (comptime @hasDecl(std.json, "stringifyAlloc")) {
        return std.json.stringifyAlloc(alloc, v, .{});
    } else {
        return std.json.Stringify.valueAlloc(alloc, v, .{});
    }
}

// Serialises v to JSON as a c_allocator-owned C string.
// Caller frees via std.heap.c_allocator.free(std.mem.span(p)).
fn jsonStringifyC(v: anytype) ?[*:0]u8 {
    const bytes = jsonStringifyAllocBytes(std.heap.c_allocator, v) catch
        return null;
    defer std.heap.c_allocator.free(bytes);
    return (std.heap.c_allocator.dupeZ(u8, bytes) catch return null).ptr;
}

/// Frees all heap fields of a ui-layout and zeros the struct.
pub fn authdUiLayoutClear(layout: *types.AuthdUiLayout) void {
    if (layout.type) |p|
        std.heap.c_allocator.free(std.mem.span(p));
    if (layout.label) |p|
        std.heap.c_allocator.free(std.mem.span(p));
    if (layout.button) |p|
        std.heap.c_allocator.free(std.mem.span(p));
    if (layout.entry) |p|
        std.heap.c_allocator.free(std.mem.span(p));
    if (layout.qr_content) |p|
        std.heap.c_allocator.free(std.mem.span(p));
    if (layout.qr_code) |p|
        std.heap.c_allocator.free(std.mem.span(p));
    layout.* = std.mem.zeroes(types.AuthdUiLayout);
}

/// Frees a heap-allocated slice of authd broker structs.
pub fn authdBrokersFree(brokers: []types.AuthdBroker) void {
    for (brokers) |b| {
        if (b.id) |p|
            std.heap.c_allocator.free(std.mem.span(p));
        if (b.name) |p|
            std.heap.c_allocator.free(std.mem.span(p));
    }
    if (brokers.len > 0) std.c.free(brokers.ptr);
}

/// Frees a heap-allocated slice of authd auth-mode structs.
pub fn authdAuthModesFree(modes: []types.AuthdAuthMode) void {
    for (modes) |m| {
        if (m.id) |p|
            std.heap.c_allocator.free(std.mem.span(p));
        if (m.label) |p|
            std.heap.c_allocator.free(std.mem.span(p));
    }
    if (modes.len > 0) std.c.free(modes.ptr);
}

/// Returns a human-readable description for a PAM status code.
/// The pointer is valid for the lifetime of the process.
fn getPamAuthError(pam_status: i32) [*:0]const u8 {
    return switch (pam_status) {
        c.PAM_AUTH_ERR => "invalid credentials",
        c.PAM_PERM_DENIED => "permission denied; check /etc/pam.d/swaylock" ++
            " is installed properly",
        c.PAM_CRED_INSUFFICIENT => "swaylock cannot authenticate users; check " ++
            "/etc/pam.d/swaylock has been installed properly",
        c.PAM_AUTHINFO_UNAVAIL => "authentication information unavailable",
        c.PAM_MAXTRIES => "maximum number of authentication tries exceeded",
        else => blk: {
            const S = struct {
                var buf: [64]u8 = undefined;
            };
            _ = std.fmt.bufPrintZ(
                &S.buf,
                "unknown error ({d})",
                .{pam_status},
            ) catch {};
            break :blk @as([*:0]const u8, @ptrCast(&S.buf));
        },
    };
}

/// Conversation callback state. pending[0..pending_count] holds
/// queued GDM events for the next pollResponse.
const ConvState = struct {
    pending: [64]GdmEvent = undefined,
    pending_count: usize = 0,
    user_selected_sent: bool = false,
    username: [*:0]const u8,
};

// Sends bytes over the IPC channel then frees the slice.
fn commSend(msg_type: u8, bytes: []u8) void {
    _ = comm.commChildWrite(msg_type, bytes);
    std.heap.c_allocator.free(bytes);
}

/// Form layout descriptor for supportedUiLayouts.
const UiLayoutForm = struct {
    type: []const u8 = "form",
    label: []const u8 = "required",
    entry: []const u8 =
        "optional:chars,chars_password,digits,digits_password",
    wait: []const u8 = "optional:true,false",
    button: []const u8 = "optional",
};

/// New-password layout descriptor for supportedUiLayouts.
const UiLayoutNewPassword = struct {
    type: []const u8 = "newpassword",
    label: []const u8 = "required",
    entry: []const u8 =
        "optional:chars,chars_password,digits,digits_password",
    button: []const u8 = "optional",
};

/// QR code layout descriptor for supportedUiLayouts.
const UiLayoutQrCode = struct {
    type: []const u8 = "qrcode",
    content: []const u8 = "required",
    code: []const u8 = "optional",
    wait: []const u8 = "required:true,false",
    label: []const u8 = "optional",
    button: []const u8 = "optional",
    rendersQrcode: bool = true,
};

/// Responses to GDM binary prompts. Each variant serialises as
/// {"type":"<tag>","<tag>":<payload>}.
const GdmResponse = union(enum) {
    hello: struct { version: u32 = 1 },
    eventAck,
    response: struct {
        type: []const u8 = "uiLayoutCapabilities",
        uiLayoutCapabilities: struct {
            /// Serialises as a JSON array.
            supportedUiLayouts: struct {
                UiLayoutForm,
                UiLayoutNewPassword,
                UiLayoutQrCode,
            } = .{ .{}, .{}, .{} },
        } = .{},
    },
    /// Borrowed from ConvState.pending; not freed here.
    pollResponse: []const GdmEvent,

    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("type");
        try jws.write(@tagName(self));
        switch (self) {
            .eventAck => {},
            inline else => |payload, tag| {
                try jws.objectField(@tagName(tag));
                try jws.write(payload);
            },
        }
        try jws.endObject();
    }
};

/// Events queued for the next pollResponse. Variants that own
/// string data must have deinit called after use.
const GdmEvent = union(enum) {
    /// Borrowed from ConvState.username; not freed.
    userSelected: struct { userId: []const u8 },
    brokerSelected: struct { brokerId: []u8 },
    authModeSelected: struct { authModeId: []u8 },
    reselectAuthMode: struct {},
    isAuthenticatedCancelled: struct {},
    isAuthenticatedRequested: struct {
        authenticationData: struct { secret: []u8 },
    },

    /// Frees owned data; secrets are zeroed first.
    fn deinit(self: GdmEvent) void {
        switch (self) {
            .brokerSelected => |v| std.heap.c_allocator.free(v.brokerId),
            .authModeSelected => |v| std.heap.c_allocator.free(v.authModeId),
            .isAuthenticatedRequested => |v| {
                const s = v.authenticationData.secret;
                @memset(s, 0);
                std.heap.c_allocator.free(s);
            },
            else => {},
        }
    }

    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("type");
        try jws.write(@tagName(self));
        switch (self) {
            inline else => |payload, tag| {
                try jws.objectField(@tagName(tag));
                try jws.write(payload);
            },
        }
        try jws.endObject();
    }
};

/// Processes a GDM/authd JSON message and returns a heap-allocated
/// null-terminated response. Caller must free the result.
fn handleGdmJson(
    state: *ConvState,
    json_in: [*c]const u8,
) ?[*:0]u8 {
    if (json_in == null) return null;
    const input = std.mem.span(@as([*:0]const u8, @ptrCast(json_in)));

    var parsed = std.json.parseFromSlice(
        std.json.Value,
        std.heap.c_allocator,
        input,
        .{},
    ) catch {
        log.slog(
            log.LogImportance.err,
            @src(),
            "json parse failed: {s}",
            .{input[0..@min(80, input.len)]},
        );
        return null;
    };
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };
    const tp = switch (root_obj.get("type") orelse return null) {
        .string => |s| s,
        else => return null,
    };
    log.slog(log.LogImportance.debug, @src(), "handle_gdm_json: type={s}", .{tp});

    if (std.mem.eql(u8, tp, "hello")) {
        return jsonStringifyC(GdmResponse{ .hello = .{} });
    } else if (std.mem.eql(u8, tp, "request")) {
        const is_ui_caps = blk: {
            const req = switch (root_obj.get("request") orelse .null) {
                .object => |o| o,
                else => break :blk false,
            };
            break :blk switch (req.get("type") orelse .null) {
                .string => |s| std.mem.eql(u8, s, "uiLayoutCapabilities"),
                else => false,
            };
        };
        if (is_ui_caps) {
            return jsonStringifyC(GdmResponse{ .response = .{} });
        } else {
            return jsonStringifyC(GdmResponse{ .eventAck = {} });
        }
    } else if (std.mem.eql(u8, tp, "event")) {
        const event_obj = switch (root_obj.get("event") orelse .null) {
            .object => |o| o,
            // No event object; reply with eventAck.
            else => return jsonStringifyC(GdmResponse{ .eventAck = {} }),
        };
        const etype: []const u8 = switch (event_obj.get("type") orelse .null) {
            .string => |s| s,
            else => "",
        };
        log.slog(
            log.LogImportance.debug,
            @src(),
            "handle_gdm_json: event type={s}",
            .{etype},
        );

        if (std.mem.eql(u8, etype, "brokersReceived")) {
            const infos_val = event_obj.get("brokersInfos") orelse .null;
            if (infos_val == .array) {
                const BrokerInfo = struct { id: []const u8, name: []const u8 };
                var brokers: std.ArrayListUnmanaged(BrokerInfo) = .{ .items = &.{}, .capacity = 0 };
                defer brokers.deinit(std.heap.c_allocator);
                for (infos_val.array.items) |b| {
                    const bo = switch (b) {
                        .object => |o| o,
                        else => continue,
                    };
                    const id = switch (bo.get("id") orelse .null) {
                        .string => |s| s,
                        else => continue,
                    };
                    const name = switch (bo.get("name") orelse .null) {
                        .string => |s| s,
                        else => "",
                    };
                    brokers.append(
                        std.heap.c_allocator,
                        .{ .id = id, .name = name },
                    ) catch continue;
                }
                if (jsonStringifyAllocBytes(
                    std.heap.c_allocator,
                    brokers.items,
                ) catch null) |bytes|
                    commSend(types.CommMsg.brokers, bytes);
            }
        } else if (std.mem.eql(u8, etype, "authModesReceived")) {
            const modes_val = event_obj.get("authModes") orelse .null;
            if (modes_val == .array) {
                const AuthModeInfo = struct {
                    id: []const u8,
                    label: []const u8,
                };
                var modes: std.ArrayListUnmanaged(AuthModeInfo) = .{ .items = &.{}, .capacity = 0 };
                defer modes.deinit(std.heap.c_allocator);
                for (modes_val.array.items) |m| {
                    const mo = switch (m) {
                        .object => |o| o,
                        else => continue,
                    };
                    const id = switch (mo.get("id") orelse .null) {
                        .string => |s| s,
                        else => continue,
                    };
                    const label = switch (mo.get("label") orelse .null) {
                        .string => |s| s,
                        else => "",
                    };
                    modes.append(
                        std.heap.c_allocator,
                        .{ .id = id, .label = label },
                    ) catch continue;
                }
                if (jsonStringifyAllocBytes(
                    std.heap.c_allocator,
                    modes.items,
                ) catch null) |bytes|
                    commSend(types.CommMsg.auth_modes, bytes);
            }
        } else if (std.mem.eql(u8, etype, "uiLayoutReceived")) {
            const layout_val = event_obj.get("uiLayout") orelse .null;
            if (jsonStringifyAllocBytes(
                std.heap.c_allocator,
                layout_val,
            ) catch null) |bytes|
                commSend(types.CommMsg.ui_layout, bytes);
        } else if (std.mem.eql(u8, etype, "stageChanged")) {
            const stage_val = event_obj.get("stage") orelse .null;
            var stage_byte: u8 = @intCast(
                @intFromEnum(types.AuthdStage.none),
            );
            if (stage_val == .string) {
                const s = stage_val.string;
                if (std.mem.eql(u8, s, "brokerSelection"))
                    stage_byte = @intCast(
                        @intFromEnum(types.AuthdStage.broker),
                    )
                else if (std.mem.eql(u8, s, "authModeSelection"))
                    stage_byte = @intCast(
                        @intFromEnum(types.AuthdStage.auth_mode),
                    )
                else if (std.mem.eql(u8, s, "challenge"))
                    stage_byte = @intCast(
                        @intFromEnum(types.AuthdStage.challenge),
                    );
                // "userSelection" maps to AUTHD_STAGE_NONE.
            }
            const stage_byte_array: [*]const u8 = @ptrCast(&stage_byte);
            _ = comm.commChildWrite(
                types.CommMsg.stage,
                stage_byte_array[0..1],
            );
        } else if (std.mem.eql(u8, etype, "startAuthentication")) {
            log.slog(
                log.LogImportance.debug,
                @src(),
                "handle_gdm_json: startAuthentication" ++
                    " -> sending COMM_MSG_STAGE challenge",
                .{},
            );
            const stage_byte: u8 = @intCast(
                @intFromEnum(types.AuthdStage.challenge),
            );
            const stage_byte_array: [*]const u8 = @ptrCast(&stage_byte);
            _ = comm.commChildWrite(
                types.CommMsg.stage,
                stage_byte_array[0..1],
            );
        } else if (std.mem.eql(u8, etype, "authEvent")) {
            const ev_resp = event_obj.get("response") orelse .null;
            if (jsonStringifyAllocBytes(
                std.heap.c_allocator,
                ev_resp,
            ) catch null) |bytes| {
                const access_str: []const u8 = switch (ev_resp) {
                    .object => |o| switch (o.get("access") orelse .null) {
                        .string => |s| s,
                        else => "(none)",
                    },
                    else => "(none)",
                };
                log.slog(
                    log.LogImportance.debug,
                    @src(),
                    "handle_gdm_json: authEvent access={s} -> AUTH_EVENT",
                    .{access_str},
                );
                commSend(types.CommMsg.auth_event, bytes);
            }
        }
        // All event subtypes get an eventAck reply.
        return jsonStringifyC(GdmResponse{ .eventAck = {} });
    } else if (std.mem.eql(u8, tp, "poll")) {
        if (!state.user_selected_sent) {
            state.pending[state.pending_count] = GdmEvent{
                .userSelected = .{ .userId = std.mem.span(state.username) },
            };
            state.pending_count += 1;
            state.user_selected_sent = true;
        }
        log.slog(
            log.LogImportance.debug,
            @src(),
            "handle_gdm_json: poll pending={d} user_sel_sent={d}",
            .{ state.pending_count, @intFromBool(state.user_selected_sent) },
        );

        while (state.pending_count < 64) {
            var pfds = [1]std.posix.pollfd{.{
                .fd = comm.getCommChildFd(),
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            if (std.posix.poll(&pfds, 0) catch 0 == 0) break;

            const r = comm.commChildRead();
            defer if (r.payload.len > 0) std.c.free(r.payload.ptr);
            if (r.msg_type <= 0) break;
            const mtype: u8 = @intCast(r.msg_type);
            log.slog(
                log.LogImportance.debug,
                @src(),
                "handle_gdm_json: poll read mtype=0x{x:0>2} plen={d}",
                .{ mtype, r.payload.len },
            );

            const maybe_event: ?GdmEvent = switch (mtype) {
                types.CommMsg.broker_sel => blk: {
                    const id = std.heap.c_allocator.dupe(
                        u8,
                        std.mem.sliceTo(r.payload, 0),
                    ) catch break :blk null;
                    break :blk GdmEvent{
                        .brokerSelected = .{ .brokerId = id },
                    };
                },
                types.CommMsg.auth_mode_sel => blk: {
                    const id = std.heap.c_allocator.dupe(
                        u8,
                        std.mem.sliceTo(r.payload, 0),
                    ) catch break :blk null;
                    break :blk GdmEvent{
                        .authModeSelected = .{ .authModeId = id },
                    };
                },
                types.CommMsg.button => GdmEvent{ .reselectAuthMode = .{} },
                types.CommMsg.cancel => GdmEvent{ .isAuthenticatedCancelled = .{} },
                types.CommMsg.password => blk: {
                    const secret = std.heap.c_allocator.dupe(
                        u8,
                        std.mem.sliceTo(r.payload, 0),
                    ) catch break :blk null;
                    // Zero the original credential before freeing.
                    password_buffer.zero(r.payload);
                    break :blk GdmEvent{
                        .isAuthenticatedRequested = .{
                            .authenticationData = .{ .secret = secret },
                        },
                    };
                },
                else => null,
            };
            if (maybe_event) |event| {
                state.pending[state.pending_count] = event;
                state.pending_count += 1;
            }
        }

        log.slog(
            log.LogImportance.debug,
            @src(),
            "handle_gdm_json: pollResponse nevents={d}",
            .{state.pending_count},
        );
        // Snapshot and reset before write so deinit runs on any exit.
        const events = state.pending[0..state.pending_count];
        state.pending_count = 0;
        defer for (events) |e| e.deinit();
        return jsonStringifyC(GdmResponse{ .pollResponse = events });
    } else {
        return jsonStringifyC(GdmResponse{ .eventAck = {} });
    }
}

/// PAM conversation callback. Handles password prompts, GDM
/// binary prompts, and informational messages.
fn handleConversation(
    num_msg: c_int,
    msg: [*c][*c]const c.pam_message,
    resp: [*c][*c]c.pam_response,
    data: ?*anyopaque,
) callconv(.c) c_int {
    const state: *ConvState = @ptrCast(@alignCast(data.?));
    log.slog(log.LogImportance.debug, @src(), "handle_conversation: num_msg={d}", .{num_msg});

    const pam_reply: [*c]c.pam_response = @ptrCast(@alignCast(
        std.c.calloc(@intCast(num_msg), @sizeOf(c.pam_response)),
    ));
    if (pam_reply == null) {
        log.slog(log.LogImportance.err, @src(), "allocation failed", .{});
        return c.PAM_ABORT;
    }
    resp.* = pam_reply;

    var i: c_int = 0;
    while (i < num_msg) : (i += 1) {
        const idx: usize = @intCast(i);
        log.slog(
            log.LogImportance.debug,
            @src(),
            "handle_conversation: msg[{d}] style={d}",
            .{ i, msg[idx].*.msg_style },
        );

        switch (msg[idx].*.msg_style) {
            c.PAM_PROMPT_ECHO_OFF,
            c.PAM_PROMPT_ECHO_ON,
            => {
                // Notify main we need a credential. Transitions
                // validating -> invalid -> idle if needed.
                const stage_byte: [1]u8 = .{@intCast(
                    @intFromEnum(types.AuthdStage.challenge),
                )};
                _ = comm.commChildWrite(
                    types.CommMsg.stage,
                    &stage_byte,
                );
                log.slog(
                    log.LogImportance.debug,
                    @src(),
                    "handle_conversation: PAM_PROMPT" ++
                        " sent STAGE, waiting for password",
                    .{},
                );

                var read = comm.commChildRead();
                while (read.msg_type != @as(i32, types.CommMsg.password)) {
                    if (read.msg_type <= 0) return c.PAM_ABORT;
                    if (read.payload.len > 0) std.c.free(read.payload.ptr);
                    read = comm.commChildRead();
                }
                log.slog(
                    log.LogImportance.debug,
                    @src(),
                    "handle_conversation: PAM_PROMPT got password (len={d})",
                    .{read.payload.len},
                );

                const pw_copy = std.heap.c_allocator.dupeZ(
                    u8,
                    read.payload,
                ) catch null;
                password_buffer.zero(read.payload);
                std.c.free(read.payload.ptr);
                pam_reply[idx].resp = if (pw_copy) |d| d.ptr else null;
                if (pam_reply[idx].resp == null) {
                    log.slog(log.LogImportance.err, @src(), "allocation failed", .{});
                    return c.PAM_ABORT;
                }
            },
            c.PAM_TEXT_INFO => log.slog(
                log.LogImportance.debug,
                @src(),
                "handle_conversation: PAM_TEXT_INFO: {s}",
                .{if (msg[idx].*.msg != null)
                    std.mem.span(msg[idx].*.msg)
                else
                    "(null)"},
            ),
            c.PAM_ERROR_MSG => log.slog(
                log.LogImportance.debug,
                @src(),
                "handle_conversation: PAM_ERROR_MSG: {s}",
                .{if (msg[idx].*.msg != null)
                    std.mem.span(msg[idx].*.msg)
                else
                    "(null)"},
            ),
            else => {
                // PAM_BINARY_PROMPT: Linux-PAM extension for the
                // authd GDM JSON protocol.
                if (comptime @hasDecl(c, "PAM_BINARY_PROMPT")) {
                    if (msg[idx].*.msg_style == c.PAM_BINARY_PROMPT) {
                        const ext: *const GdmPamExtensionJSONProtocol =
                            @ptrCast(@alignCast(msg[idx].*.msg));
                        if (!gdmMessageIsValid(ext))
                            return c.PAM_ABORT;
                        const response =
                            handleGdmJson(state, ext.json) orelse
                            return c.PAM_ABORT;
                        const raw = std.c.calloc(
                            1,
                            @sizeOf(GdmPamExtensionJSONProtocol),
                        );
                        if (raw == null) {
                            std.heap.c_allocator.free(
                                std.mem.span(response),
                            );
                            return c.PAM_ABORT;
                        }
                        const reply: *GdmPamExtensionJSONProtocol =
                            @ptrCast(@alignCast(raw));
                        gdmRequestInit(reply, response);
                        pam_reply[idx].resp = @ptrCast(reply);
                        continue;
                    }
                }
                log.slog(
                    log.LogImportance.debug,
                    @src(),
                    "handle_conversation: unknown msg_style={d}",
                    .{msg[idx].*.msg_style},
                );
            },
        }
    }
    log.slog(
        log.LogImportance.debug,
        @src(),
        "handle_conversation: returning PAM_SUCCESS",
        .{},
    );
    return c.PAM_SUCCESS;
}

/// Spawns the comm child process for PAM authentication.
pub fn initializePwBackend(argc: c_int, argv: [*c][*c]u8) void {
    _ = argc;
    _ = argv;
    if (!comm.spawnCommChild(runPwBackendChild)) std.process.exit(1);
}

/// Runs the PAM authentication loop in the child. Never returns.
pub fn runPwBackendChild() void {
    if (std.posix.access("/run/authd.sock", 0)) |_|
        gdmAdvertiseExtensions()
    else |_| {}

    const passwd_ptr = c.getpwuid(
        @intCast(std.os.linux.getuid()),
    );
    if (passwd_ptr == null) {
        log.slog(log.LogImportance.err, @src(), "getpwuid failed", .{});
        std.process.exit(1);
    }
    const username = passwd_ptr.*.pw_name;

    var state = ConvState{ .username = username };
    const conv = c.pam_conv{
        .conv = handleConversation,
        .appdata_ptr = &state,
    };

    var auth_handle: ?*c.pam_handle_t = null;
    if (c.pam_start(
        "swaylock",
        username,
        &conv,
        &auth_handle,
    ) != c.PAM_SUCCESS) {
        log.slog(log.LogImportance.err, @src(), "pam_start failed", .{});
        std.process.exit(1);
    }
    log.slog(
        log.LogImportance.debug,
        @src(),
        "Prepared to authorise user {s}",
        .{std.mem.span(username)},
    );

    var pam_status: i32 = undefined;
    while (true) {
        pam_status = c.pam_authenticate(auth_handle, 0);
        if (pam_status == c.PAM_SUCCESS) {
            _ = comm.commChildWrite(types.CommMsg.auth_result, "\x01"[0..1]);
        } else {
            log.slog(
                log.LogImportance.err,
                @src(),
                "pam_authenticate failed: {s}",
                .{std.mem.span(getPamAuthError(pam_status))},
            );
            _ = comm.commChildWrite(types.CommMsg.auth_result, "\x00"[0..1]);
        }
        if (pam_status != c.PAM_AUTH_ERR) break;
    }

    _ = c.pam_setcred(auth_handle, c.PAM_REFRESH_CRED);

    if (c.pam_end(auth_handle, pam_status) != c.PAM_SUCCESS) {
        log.slog(log.LogImportance.err, @src(), "pam_end failed", .{});
        std.process.exit(1);
    }
    std.process.exit(if (pam_status == c.PAM_SUCCESS) 0 else 1);
}
