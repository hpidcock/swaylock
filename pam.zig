//! pam.zig – Zig port of pam.c.
//! PAM authentication and GDM/authd JSON protocol handling.
//! All JSON processing uses std.json in place of cJSON.

const std = @import("std");
const types = @import("types");

const log_err: i32 = @intFromEnum(types.LogImportance.err);
const log_info: i32 = @intFromEnum(types.LogImportance.info);
const log_debug: i32 = @intFromEnum(types.LogImportance.debug);

const log = @import("log");
const comm = @import("comm");
extern fn password_buffer_create(size: usize) ?[*]u8;
extern fn password_buffer_destroy(buffer: ?[*]u8, size: usize) void;
extern fn clear_buffer(buf: ?[*]u8, size: usize) void;

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("_DEFAULT_SOURCE", "1");
    @cInclude("poll.h");
    @cInclude("pwd.h");
    @cInclude("security/pam_appl.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("gdm/gdm-custom-json-pam-extension.h");
});

/// Shims compiled from pam_gdm_shim.c to avoid Zig's C translator
/// choking on GNU statement-expression macros in the GDM headers.
extern fn pam_shim_gdm_advertise_extensions() void;
extern fn pam_shim_gdm_request_init(
    req: *c.GdmPamExtensionJSONProtocol,
    json: [*c]u8,
) void;

/// Returns true when the GDM PAM message carries the expected authd
/// protocol name ("com.ubuntu.authd.gdm") and version (1).
fn gdmMessageIsValid(msg: *const c.GdmPamExtensionJSONProtocol) bool {
    if (msg.version != 1) return false;
    const name = std.mem.sliceTo(
        @as([*:0]const u8, @ptrCast(&msg.protocol_name)),
        0,
    );
    return std.mem.eql(u8, name, "com.ubuntu.authd.gdm");
}

// jsonStringifyAllocBytes serialises v to JSON, returning an
// allocator-owned []u8. Compatible with Zig 0.14 and 0.16.
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

// jsonStringifyC serialises v to JSON and returns a c_allocator-owned
// null-terminated C string, or null on allocation failure.
// The caller is responsible for c.free()-ing the result.
fn jsonStringifyC(v: anytype) ?[*:0]u8 {
    const bytes = jsonStringifyAllocBytes(std.heap.c_allocator, v) catch
        return null;
    defer std.heap.c_allocator.free(bytes);
    return (std.heap.c_allocator.dupeZ(u8, bytes) catch return null).ptr;
}

/// Free all heap-allocated fields of a ui-layout and zero the struct.
export fn authd_ui_layout_clear(layout: *types.AuthdUiLayout) void {
    c.free(@ptrCast(layout.type));
    c.free(@ptrCast(layout.label));
    c.free(@ptrCast(layout.button));
    c.free(@ptrCast(layout.entry));
    c.free(@ptrCast(layout.qr_content));
    c.free(@ptrCast(layout.qr_code));
    layout.* = std.mem.zeroes(types.AuthdUiLayout);
}

/// Free a heap-allocated slice of authd_broker structs.
export fn authd_brokers_free(
    brokers: [*c]types.AuthdBroker,
    count: i32,
) void {
    var i: usize = 0;
    while (i < @as(usize, @intCast(count))) : (i += 1) {
        c.free(@ptrCast(brokers[i].id));
        c.free(@ptrCast(brokers[i].name));
    }
    c.free(brokers);
}

/// Free a heap-allocated slice of authd_auth_mode structs.
export fn authd_auth_modes_free(
    modes: [*c]types.AuthdAuthMode,
    count: i32,
) void {
    var i: usize = 0;
    while (i < @as(usize, @intCast(count))) : (i += 1) {
        c.free(@ptrCast(modes[i].id));
        c.free(@ptrCast(modes[i].label));
    }
    c.free(modes);
}

/// Return a human-readable description for a PAM status code.
/// The returned pointer is valid for the lifetime of the process;
/// for the default case it points into a static buffer.
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

/// State threaded through the PAM conversation callback.
/// pending[0..pending_count] holds queued GDM events for the next
/// pollResponse.
const ConvState = struct {
    pending: [64]GdmEvent = undefined,
    pending_count: usize = 0,
    user_selected_sent: bool = false,
    username: [*:0]const u8,
};

/// Send a byte slice over the IPC channel then free it.
fn commSend(msg_type: u8, bytes: []u8) void {
    _ = comm.commChildWrite(msg_type, bytes.ptr, bytes.len);
    std.heap.c_allocator.free(bytes);
}

// GDM/authd JSON protocol types.

/// "form" layout descriptor in the supportedUiLayouts array.
const UiLayoutForm = struct {
    type: []const u8 = "form",
    label: []const u8 = "required",
    entry: []const u8 =
        "optional:chars,chars_password,digits,digits_password",
    wait: []const u8 = "optional:true,false",
    button: []const u8 = "optional",
};

/// "newpassword" layout descriptor in the supportedUiLayouts array.
const UiLayoutNewPassword = struct {
    type: []const u8 = "newpassword",
    label: []const u8 = "required",
    entry: []const u8 =
        "optional:chars,chars_password,digits,digits_password",
    button: []const u8 = "optional",
};

/// "qrcode" layout descriptor in the supportedUiLayouts array.
const UiLayoutQrCode = struct {
    type: []const u8 = "qrcode",
    content: []const u8 = "required",
    code: []const u8 = "optional",
    wait: []const u8 = "required:true,false",
    label: []const u8 = "optional",
    button: []const u8 = "optional",
    rendersQrcode: bool = true,
};

/// Direct responses to GDM binary prompts.
/// Each variant serialises as {"type":"<tag>","<tag>":<payload>}.
/// eventAck carries no payload field.
const GdmResponse = union(enum) {
    hello: struct { version: u32 = 1 },
    eventAck,
    response: struct {
        type: []const u8 = "uiLayoutCapabilities",
        uiLayoutCapabilities: struct {
            /// Tuple-struct serialises as a JSON array.
            supportedUiLayouts: struct {
                UiLayoutForm,
                UiLayoutNewPassword,
                UiLayoutQrCode,
            } = .{ .{}, .{}, .{} },
        } = .{},
    },
    /// Slice is borrowed from ConvState.pending; not freed here.
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

/// Events queued for the next pollResponse.
/// Each variant serialises as {"type":"<tag>","<tag>":<payload>}.
/// brokerSelected, authModeSelected and isAuthenticatedRequested own
/// their string data; call deinit after use.
const GdmEvent = union(enum) {
    /// userId is borrowed from ConvState.username; not freed.
    userSelected: struct { userId: []const u8 },
    brokerSelected: struct { brokerId: []u8 },
    authModeSelected: struct { authModeId: []u8 },
    reselectAuthMode: struct {},
    isAuthenticatedCancelled: struct {},
    isAuthenticatedRequested: struct {
        authenticationData: struct { secret: []u8 },
    },

    /// Free owned string data; secrets are zeroed before freeing.
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

/// Process a GDM/authd JSON message and return a heap-allocated
/// null-terminated response string.  The caller must free the result.
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
            log_err,
            @src(),
            "cJSON_Parse failed: {s}",
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
    log.slog(log_debug, @src(), "handle_gdm_json: type={s}", .{tp});

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
            // No event object → nothing to process, reply with eventAck.
            else => return jsonStringifyC(GdmResponse{ .eventAck = {} }),
        };
        const etype: []const u8 = switch (event_obj.get("type") orelse .null) {
            .string => |s| s,
            else => "",
        };
        log.slog(
            log_debug,
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
                // "userSelection" → AUTHD_STAGE_NONE (default)
            }
            _ = comm.commChildWrite(
                types.CommMsg.stage,
                @ptrCast(&stage_byte),
                @sizeOf(u8),
            );
        } else if (std.mem.eql(u8, etype, "startAuthentication")) {
            log.slog(
                log_debug,
                @src(),
                "handle_gdm_json: startAuthentication" ++
                    " -> sending COMM_MSG_STAGE challenge",
                .{},
            );
            const stage_byte: u8 = @intCast(
                @intFromEnum(types.AuthdStage.challenge),
            );
            _ = comm.commChildWrite(
                types.CommMsg.stage,
                @ptrCast(&stage_byte),
                @sizeOf(u8),
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
                    log_debug,
                    @src(),
                    "handle_gdm_json: authEvent access={s} -> AUTH_EVENT",
                    .{access_str},
                );
                commSend(types.CommMsg.auth_event, bytes);
            }
        }
        // All event subtypes reply with eventAck.
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
            log_debug,
            @src(),
            "handle_gdm_json: poll pending={d} user_sel_sent={d}",
            .{ state.pending_count, @intFromBool(state.user_selected_sent) },
        );

        while (state.pending_count < 64) {
            var pfd = c.struct_pollfd{
                .fd = comm.getCommChildFd(),
                .events = c.POLLIN,
                .revents = 0,
            };
            if (c.poll(&pfd, 1, 0) <= 0) break;

            var payload: ?[*]u8 = null;
            var plen: usize = 0;
            const mtype_raw = comm.commChildRead(&payload, &plen);
            if (mtype_raw <= 0) {
                c.free(@ptrCast(payload));
                break;
            }
            const mtype: u8 = @intCast(mtype_raw);
            log.slog(
                log_debug,
                @src(),
                "handle_gdm_json: poll read mtype=0x{x:0>2} plen={d}",
                .{ mtype, plen },
            );

            const maybe_event: ?GdmEvent = switch (mtype) {
                types.CommMsg.broker_sel => blk: {
                    const raw: []const u8 = if (payload) |p|
                        std.mem.span(@as([*:0]const u8, @ptrCast(p)))
                    else
                        "";
                    const id = std.heap.c_allocator.dupe(u8, raw) catch {
                        c.free(@ptrCast(payload));
                        break :blk null;
                    };
                    c.free(@ptrCast(payload));
                    break :blk GdmEvent{
                        .brokerSelected = .{ .brokerId = id },
                    };
                },
                types.CommMsg.auth_mode_sel => blk: {
                    const raw: []const u8 = if (payload) |p|
                        std.mem.span(@as([*:0]const u8, @ptrCast(p)))
                    else
                        "";
                    const id = std.heap.c_allocator.dupe(u8, raw) catch {
                        c.free(@ptrCast(payload));
                        break :blk null;
                    };
                    c.free(@ptrCast(payload));
                    break :blk GdmEvent{
                        .authModeSelected = .{ .authModeId = id },
                    };
                },
                types.CommMsg.button => blk: {
                    c.free(@ptrCast(payload));
                    break :blk GdmEvent{ .reselectAuthMode = .{} };
                },
                types.CommMsg.cancel => blk: {
                    c.free(@ptrCast(payload));
                    break :blk GdmEvent{ .isAuthenticatedCancelled = .{} };
                },
                types.CommMsg.password => blk: {
                    const raw: []const u8 = if (payload) |p|
                        std.mem.span(@as([*:0]const u8, @ptrCast(p)))
                    else
                        "";
                    const secret = std.heap.c_allocator.dupe(u8, raw) catch {
                        if (payload != null) {
                            clear_buffer(payload, plen);
                            c.free(@ptrCast(payload));
                        }
                        break :blk null;
                    };
                    // Clear the original credential before freeing.
                    if (payload != null) {
                        clear_buffer(payload, plen);
                        c.free(@ptrCast(payload));
                    }
                    break :blk GdmEvent{
                        .isAuthenticatedRequested = .{
                            .authenticationData = .{ .secret = secret },
                        },
                    };
                },
                else => blk: {
                    c.free(@ptrCast(payload));
                    break :blk null;
                },
            };
            if (maybe_event) |event| {
                state.pending[state.pending_count] = event;
                state.pending_count += 1;
            }
        }

        log.slog(
            log_debug,
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

/// PAM conversation callback.  Handles password prompts, GDM binary
/// prompts, and informational messages from the PAM stack.
fn handleConversation(
    num_msg: c_int,
    msg: [*c][*c]const c.pam_message,
    resp: [*c][*c]c.pam_response,
    data: ?*anyopaque,
) callconv(.c) c_int {
    const state: *ConvState = @ptrCast(@alignCast(data.?));
    log.slog(log_debug, @src(), "handle_conversation: num_msg={d}", .{num_msg});

    const pam_reply: [*c]c.pam_response = @ptrCast(@alignCast(
        c.calloc(@intCast(num_msg), @sizeOf(c.pam_response)),
    ));
    if (pam_reply == null) {
        log.slog(log_err, @src(), "allocation failed", .{});
        return c.PAM_ABORT;
    }
    resp.* = pam_reply;

    var i: c_int = 0;
    while (i < num_msg) : (i += 1) {
        const idx: usize = @intCast(i);
        log.slog(
            log_debug,
            @src(),
            "handle_conversation: msg[{d}] style={d}",
            .{ i, msg[idx].*.msg_style },
        );

        switch (msg[idx].*.msg_style) {
            c.PAM_PROMPT_ECHO_OFF,
            c.PAM_PROMPT_ECHO_ON,
            => {
                // Tell the main process we are waiting for a new
                // credential.  If it was in AUTH_STATE_VALIDATING
                // this transitions it to AUTH_STATE_INVALID
                // ("Wrong") and then back to IDLE so the user
                // can type again.
                const stage_byte: u8 = @intCast(
                    @intFromEnum(types.AuthdStage.challenge),
                );
                _ = comm.commChildWrite(
                    types.CommMsg.stage,
                    @ptrCast(&stage_byte),
                    @sizeOf(u8),
                );
                log.slog(
                    log_debug,
                    @src(),
                    "handle_conversation: PAM_PROMPT" ++
                        " sent STAGE, waiting for password",
                    .{},
                );

                var payload: ?[*]u8 = null;
                var len: usize = 0;
                while (true) {
                    const t_raw = comm.commChildRead(&payload, &len);
                    if (t_raw <= 0) return c.PAM_ABORT;
                    const t: u8 = @intCast(t_raw);
                    if (t == types.CommMsg.password) break;
                    c.free(@ptrCast(payload));
                    payload = null;
                }
                log.slog(
                    log_debug,
                    @src(),
                    "handle_conversation: PAM_PROMPT got password (len={d})",
                    .{len},
                );

                pam_reply[idx].resp = c.strdup(@ptrCast(payload));
                clear_buffer(payload, len);
                c.free(@ptrCast(payload));
                if (pam_reply[idx].resp == null) {
                    log.slog(log_err, @src(), "allocation failed", .{});
                    return c.PAM_ABORT;
                }
            },
            c.PAM_TEXT_INFO => log.slog(
                log_debug,
                @src(),
                "handle_conversation: PAM_TEXT_INFO: {s}",
                .{if (msg[idx].*.msg != null)
                    std.mem.span(msg[idx].*.msg)
                else
                    "(null)"},
            ),
            c.PAM_ERROR_MSG => log.slog(
                log_debug,
                @src(),
                "handle_conversation: PAM_ERROR_MSG: {s}",
                .{if (msg[idx].*.msg != null)
                    std.mem.span(msg[idx].*.msg)
                else
                    "(null)"},
            ),
            else => {
                // PAM_BINARY_PROMPT is a Linux-PAM extension used
                // by the authd GDM JSON protocol.
                if (comptime @hasDecl(c, "PAM_BINARY_PROMPT")) {
                    if (msg[idx].*.msg_style == c.PAM_BINARY_PROMPT) {
                        const ext: *const c.GdmPamExtensionJSONProtocol =
                            @ptrCast(@alignCast(msg[idx].*.msg));
                        if (!gdmMessageIsValid(ext))
                            return c.PAM_ABORT;
                        const response =
                            handleGdmJson(state, ext.json) orelse
                            return c.PAM_ABORT;
                        const raw = c.calloc(
                            1,
                            @sizeOf(c.GdmPamExtensionJSONProtocol),
                        );
                        if (raw == null) {
                            c.free(response);
                            return c.PAM_ABORT;
                        }
                        const reply: *c.GdmPamExtensionJSONProtocol =
                            @ptrCast(@alignCast(raw));
                        pam_shim_gdm_request_init(reply, response);
                        pam_reply[idx].resp = @ptrCast(reply);
                        continue;
                    }
                }
                log.slog(
                    log_debug,
                    @src(),
                    "handle_conversation: unknown msg_style={d}",
                    .{msg[idx].*.msg_style},
                );
            },
        }
    }
    log.slog(
        log_debug,
        @src(),
        "handle_conversation: returning PAM_SUCCESS",
        .{},
    );
    return c.PAM_SUCCESS;
}

/// Initialise the password backend; spawns the comm child process.
export fn initialize_pw_backend(argc: c_int, argv: [*c][*c]u8) void {
    _ = argc;
    _ = argv;
    if (!comm.spawnCommChild()) c.exit(c.EXIT_FAILURE);
}

/// Run the PAM authentication loop in the child process.  Never returns.
export fn run_pw_backend_child() void {
    if (c.access("/run/authd.sock", c.F_OK) == 0)
        pam_shim_gdm_advertise_extensions();

    const passwd_ptr = c.getpwuid(c.getuid());
    if (passwd_ptr == null) {
        log.slog(log_err, @src(), "getpwuid failed", .{});
        c.exit(c.EXIT_FAILURE);
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
        log.slog(log_err, @src(), "pam_start failed", .{});
        c.exit(c.EXIT_FAILURE);
    }
    log.slog(
        log_debug,
        @src(),
        "Prepared to authorise user {s}",
        .{std.mem.span(username)},
    );

    var pam_status: i32 = undefined;
    while (true) {
        pam_status = c.pam_authenticate(auth_handle, 0);
        if (pam_status == c.PAM_SUCCESS) {
            _ = comm.commChildWrite(types.CommMsg.auth_result, "\x01", 1);
        } else {
            log.slog(
                log_err,
                @src(),
                "pam_authenticate failed: {s}",
                .{std.mem.span(getPamAuthError(pam_status))},
            );
            _ = comm.commChildWrite(types.CommMsg.auth_result, "\x00", 1);
        }
        if (pam_status != c.PAM_AUTH_ERR) break;
    }

    _ = c.pam_setcred(auth_handle, c.PAM_REFRESH_CRED);

    if (c.pam_end(auth_handle, pam_status) != c.PAM_SUCCESS) {
        log.slog(log_err, @src(), "pam_end failed", .{});
        c.exit(c.EXIT_FAILURE);
    }
    c.exit(if (pam_status == c.PAM_SUCCESS)
        c.EXIT_SUCCESS
    else
        c.EXIT_FAILURE);
}
