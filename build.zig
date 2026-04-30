//! Build script for swaylock. Compiles all C sources via the system
//! C compiler (cc) using addSystemCommand, with pkg-config supplying
//! system include paths. This avoids Zig 0.16's aro C-frontend bugs
//! that manifest in --listen=- server mode.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const have_pam = b.option(
        bool,
        "pam",
        "Use PAM for authentication (default: true)",
    ) orelse true;
    const have_gdk_pixbuf = b.option(
        bool,
        "gdk-pixbuf",
        "Enable gdk-pixbuf image loading (default: true)",
    ) orelse true;
    const have_qrencode = b.option(
        bool,
        "qrencode",
        "Enable QR code support (default: false)",
    ) orelse false;
    const debug_overlay = b.option(
        bool,
        "debug-overlay",
        "Render debug log overlay (default: false)",
    ) orelse false;
    const debug_unlock_on_crash = b.option(
        bool,
        "debug-unlock-on-crash",
        "Unlock on crash - dev only (default: false)",
    ) orelse false;

    const sysconfdir = b.option(
        []const u8,
        "sysconfdir",
        "System config directory",
    ) orelse "/etc";

    const wl_proto_dir = b.option(
        []const u8,
        "wl-proto-dir",
        "wayland-protocols pkgdatadir",
    ) orelse std.mem.trim(
        u8,
        b.run(&.{
            "pkg-config",
            "--variable=pkgdatadir",
            "wayland-protocols",
        }),
        " \t\n\r",
    );

    // Generate ext-session-lock-v1 protocol glue via wayland-scanner.
    const ext_lock_xml = b.fmt(
        "{s}/staging/ext-session-lock/ext-session-lock-v1.xml",
        .{wl_proto_dir},
    );

    const gen_proto_c = b.addSystemCommand(
        &.{ "wayland-scanner", "private-code" },
    );
    gen_proto_c.addArg(ext_lock_xml);
    const proto_c = gen_proto_c.addOutputFileArg(
        "ext-session-lock-v1-protocol.c",
    );

    const gen_proto_h = b.addSystemCommand(
        &.{ "wayland-scanner", "client-header" },
    );
    gen_proto_h.addArg(ext_lock_xml);
    const proto_h = gen_proto_h.addOutputFileArg(
        "ext-session-lock-v1-client-protocol.h",
    );
    const proto_h_dir = proto_h.dirname();

    // Query pkg-config for system include paths at configure time.
    // The list of packages varies with enabled features.
    var pc_args: std.ArrayListUnmanaged([]const u8) = .{ .items = &.{}, .capacity = 0 };
    pc_args.appendSlice(
        b.allocator,
        &.{ "pkg-config", "--cflags-only-I" },
    ) catch @panic("OOM");
    pc_args.appendSlice(
        b.allocator,
        &.{ "wayland-client", "cairo", "xkbcommon" },
    ) catch @panic("OOM");
    if (have_gdk_pixbuf)
        pc_args.append(b.allocator, "gdk-pixbuf-2.0") catch @panic("OOM");
    if (have_pam)
        pc_args.append(b.allocator, "pam") catch @panic("OOM");
    if (have_qrencode)
        pc_args.append(b.allocator, "libqrencode") catch @panic("OOM");

    const pc_raw = b.run(
        pc_args.toOwnedSlice(b.allocator) catch @panic("OOM"),
    );

    // Parse whitespace-separated -I flags from pkg-config output.
    var sys_includes: std.ArrayListUnmanaged([]const u8) = .{ .items = &.{}, .capacity = 0 };
    var pc_tok = std.mem.tokenizeAny(u8, pc_raw, " \t\n\r");
    while (pc_tok.next()) |flag| {
        const f = std.mem.trim(u8, flag, " \t\n\r");
        if (f.len > 0)
            sys_includes.append(b.allocator, f) catch @panic("OOM");
    }

    // Full C flags: system includes first, then compile flags and
    // feature defines. include/config.h provides #ifndef-guarded
    // defaults; the -D flags here take precedence.
    var flags: std.ArrayListUnmanaged([]const u8) = .{ .items = &.{}, .capacity = 0 };
    flags.appendSlice(b.allocator, sys_includes.items) catch @panic("OOM");
    flags.appendSlice(b.allocator, &.{
        "-std=c11",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
        "-Wno-unused-result",
    }) catch @panic("OOM");
    flags.append(
        b.allocator,
        b.fmt("-DSYSCONFDIR=\"{s}\"", .{sysconfdir}),
    ) catch @panic("OOM");
    flags.append(
        b.allocator,
        "-DSWAYLOCK_VERSION=\"1.8.5\"",
    ) catch @panic("OOM");
    flags.append(
        b.allocator,
        if (have_gdk_pixbuf) "-DHAVE_GDK_PIXBUF=1" else "-DHAVE_GDK_PIXBUF=0",
    ) catch @panic("OOM");
    flags.append(
        b.allocator,
        if (have_qrencode) "-DHAVE_QRENCODE=1" else "-DHAVE_QRENCODE=0",
    ) catch @panic("OOM");
    flags.append(
        b.allocator,
        if (debug_overlay)
            "-DHAVE_DEBUG_OVERLAY=1"
        else
            "-DHAVE_DEBUG_OVERLAY=0",
    ) catch @panic("OOM");
    flags.append(
        b.allocator,
        if (debug_unlock_on_crash)
            "-DHAVE_DEBUG_UNLOCK_ON_CRASH=1"
        else
            "-DHAVE_DEBUG_UNLOCK_ON_CRASH=0",
    ) catch @panic("OOM");
    const c_flags = flags.toOwnedSlice(b.allocator) catch @panic("OOM");

    // Protocol glue only needs basic flags, no feature defines.
    var proto_flags_list: std.ArrayListUnmanaged([]const u8) = .{ .items = &.{}, .capacity = 0 };
    proto_flags_list.appendSlice(
        b.allocator,
        sys_includes.items,
    ) catch @panic("OOM");
    proto_flags_list.appendSlice(
        b.allocator,
        &.{ "-std=c11", "-D_POSIX_C_SOURCE=200809L" },
    ) catch @panic("OOM");
    const proto_flags =
        proto_flags_list.toOwnedSlice(b.allocator) catch @panic("OOM");

    // Ctx compiles a single C file via the system cc, bypassing Zig's
    // aro C frontend entirely. addPrefixedDirectoryArg resolves
    // LazyPaths at make time, so the generated protocol header becomes
    // a proper build-graph dependency.
    const Ctx = struct {
        b: *std.Build,
        proto_h_dir: std.Build.LazyPath,

        fn cobj(
            ctx: @This(),
            src: std.Build.LazyPath,
            name: []const u8,
            file_flags: []const []const u8,
        ) std.Build.LazyPath {
            const cmd = ctx.b.addSystemCommand(&.{ "cc", "-c" });
            // Local include dirs must come first so that #include "cairo.h"
            // and similar quoted includes resolve to our headers in include/,
            // not to same-named headers inside the system Cairo package.
            cmd.addPrefixedDirectoryArg("-I", ctx.b.path("include"));
            cmd.addPrefixedDirectoryArg("-I", ctx.proto_h_dir);
            for (file_flags) |flag| cmd.addArg(flag);
            cmd.addFileArg(src);
            cmd.addArg("-o");
            return cmd.addOutputFileArg(
                ctx.b.fmt("{s}.o", .{name}),
            );
        }
    };

    const ctx: Ctx = .{
        .b = b,
        .proto_h_dir = proto_h_dir,
    };

    // types_mod provides Zig-native shared type definitions that
    // replace the local C headers.  It has no mutable global state
    // so it can safely be compiled into multiple separate objects
    // without causing linker conflicts.
    const types_mod = b.createModule(.{
        .root_source_file = b.path("types.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    types_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            types_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                types_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }

    const log_options = b.addOptions();
    log_options.addOption(bool, "have_debug_overlay", debug_overlay);

    const log_mod = b.createModule(.{
        .root_source_file = b.path("log.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    log_mod.addImport("log_options", log_options.createModule());
    log_mod.addImport("types", types_mod);

    // exe_mod carries library links; objects are added as LazyPaths
    // from the cc compilation steps above.
    const exe_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Compile unicode.zig as a Zig object; it replaces unicode.c.
    const unicode_mod = b.createModule(.{
        .root_source_file = b.path("unicode.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unicode_obj = b.addObject(.{
        .name = "unicode",
        .root_module = unicode_mod,
    });
    exe_mod.addObjectFile(unicode_obj.getEmittedBin());

    // Compile cairo.zig as a Zig object; it replaces cairo.c.
    const cairo_options = b.addOptions();
    cairo_options.addOption(bool, "have_gdk_pixbuf", have_gdk_pixbuf);
    const cairo_mod = b.createModule(.{
        .root_source_file = b.path("cairo.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    cairo_mod.addImport("cairo_options", cairo_options.createModule());
    cairo_mod.addImport("types", types_mod);
    cairo_mod.addIncludePath(b.path("include"));
    cairo_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            cairo_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                cairo_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const cairo_obj = b.addObject(.{
        .name = "cairo",
        .root_module = cairo_mod,
    });
    exe_mod.addObjectFile(cairo_obj.getEmittedBin());

    // Compile seat.zig as a Zig object; it replaces seat.c.
    const seat_mod = b.createModule(.{
        .root_source_file = b.path("seat.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    seat_mod.addImport("types", types_mod);
    seat_mod.addImport("log", log_mod);
    seat_mod.addIncludePath(b.path("include"));
    seat_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            seat_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                seat_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const seat_obj = b.addObject(.{
        .name = "seat",
        .root_module = seat_mod,
    });
    exe_mod.addObjectFile(seat_obj.getEmittedBin());

    // Compile pool-buffer.zig as a Zig object; it replaces pool-buffer.c.
    const pool_buffer_mod = b.createModule(.{
        .root_source_file = b.path("pool-buffer.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    pool_buffer_mod.addImport("types", types_mod);
    pool_buffer_mod.addIncludePath(b.path("include"));
    pool_buffer_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            pool_buffer_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                pool_buffer_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const pool_buffer_obj = b.addObject(.{
        .name = "pool-buffer",
        .root_module = pool_buffer_mod,
    });
    exe_mod.addObjectFile(pool_buffer_obj.getEmittedBin());

    // Compile background-image.zig as a Zig object; it replaces
    // background-image.c.
    const bg_image_options = b.addOptions();
    bg_image_options.addOption(
        bool,
        "have_gdk_pixbuf",
        have_gdk_pixbuf,
    );
    const bg_image_mod = b.createModule(.{
        .root_source_file = b.path("background-image.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    bg_image_mod.addImport(
        "background_image_options",
        bg_image_options.createModule(),
    );
    bg_image_mod.addImport("types", types_mod);
    bg_image_mod.addImport("log", log_mod);
    bg_image_mod.addImport("cairo", cairo_mod);
    bg_image_mod.addIncludePath(b.path("include"));
    bg_image_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            bg_image_mod.addSystemIncludePath(
                .{ .cwd_relative = path },
            );
            if (std.fs.path.dirname(path)) |parent| {
                bg_image_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    // Compile loop.zig as a Zig object; it replaces loop.c.
    const loop_mod = b.createModule(.{
        .root_source_file = b.path("loop.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    loop_mod.addImport("types", types_mod);
    loop_mod.addImport("log", log_mod);
    loop_mod.addIncludePath(b.path("include"));
    loop_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            loop_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                loop_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const loop_obj = b.addObject(.{
        .name = "loop",
        .root_module = loop_mod,
    });
    exe_mod.addObjectFile(loop_obj.getEmittedBin());
    seat_mod.addImport("loop", loop_mod);

    // Compile render.zig as a Zig object; it replaces render.c.
    const render_options = b.addOptions();
    render_options.addOption(bool, "have_qrencode", have_qrencode);
    render_options.addOption(bool, "have_debug_overlay", debug_overlay);
    // Compile main.zig as a Zig object; it replaces main.c.
    const main_options = b.addOptions();
    main_options.addOption(bool, "have_debug_overlay", debug_overlay);
    main_options.addOption(
        bool,
        "have_debug_unlock_on_crash",
        debug_unlock_on_crash,
    );
    main_options.addOption([]const u8, "sysconfdir", sysconfdir);
    main_options.addOption([]const u8, "swaylock_version", "1.8.5");

    const render_mod = b.createModule(.{
        .root_source_file = b.path("render.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    render_mod.addImport("render_options", render_options.createModule());
    render_mod.addImport("types", types_mod);
    render_mod.addImport("log", log_mod);
    render_mod.addImport("background_image", bg_image_mod);
    render_mod.addImport("cairo", cairo_mod);
    render_mod.addIncludePath(b.path("include"));
    render_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            render_mod.addSystemIncludePath(.{ .cwd_relative = path });
            // Also add the parent so that e.g. <cairo/cairo.h>
            // resolves when pkg-config gives .../include/cairo.
            if (std.fs.path.dirname(path)) |parent| {
                render_mod.addSystemIncludePath(.{ .cwd_relative = parent });
            }
        }
    }
    const render_obj = b.addObject(.{
        .name = "render",
        .root_module = render_mod,
    });
    exe_mod.addObjectFile(render_obj.getEmittedBin());

    const main_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    main_mod.addImport("main_options", main_options.createModule());
    main_mod.addImport("types", types_mod);
    main_mod.addImport("log", log_mod);
    main_mod.addImport("loop", loop_mod);
    main_mod.addImport("background_image", bg_image_mod);
    main_mod.addImport("cairo", cairo_mod);
    main_mod.addIncludePath(b.path("include"));
    main_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            main_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                main_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const main_obj = b.addObject(.{
        .name = "main",
        .root_module = main_mod,
    });
    exe_mod.addObjectFile(main_obj.getEmittedBin());

    // Compile password.zig as a Zig object; it replaces password.c
    // and password-buffer.c.
    const password_mod = b.createModule(.{
        .root_source_file = b.path("password.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    password_mod.addImport("types", types_mod);
    password_mod.addImport("log", log_mod);
    password_mod.addImport("loop", loop_mod);
    password_mod.addIncludePath(b.path("include"));
    password_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            password_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                password_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const password_obj = b.addObject(.{
        .name = "password",
        .root_module = password_mod,
    });
    exe_mod.addObjectFile(password_obj.getEmittedBin());

    const comm_mod = b.createModule(.{
        .root_source_file = b.path("comm.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    comm_mod.addImport("types", types_mod);
    comm_mod.addImport("log", log_mod);
    comm_mod.addIncludePath(b.path("include"));
    comm_mod.addIncludePath(proto_h_dir);
    for (sys_includes.items) |flag| {
        const fi = std.mem.trim(u8, flag, " \t\n\r");
        if (std.mem.startsWith(u8, fi, "-I")) {
            const path = fi[2..];
            comm_mod.addSystemIncludePath(.{ .cwd_relative = path });
            if (std.fs.path.dirname(path)) |parent| {
                comm_mod.addSystemIncludePath(
                    .{ .cwd_relative = parent },
                );
            }
        }
    }
    const comm_obj = b.addObject(.{
        .name = "comm",
        .root_module = comm_mod,
    });
    exe_mod.addObjectFile(comm_obj.getEmittedBin());
    main_mod.addImport("comm", comm_mod);
    password_mod.addImport("comm", comm_mod);

    const log_obj = b.addObject(.{
        .name = "log",
        .root_module = log_mod,
    });
    exe_mod.addObjectFile(log_obj.getEmittedBin());

    exe_mod.addObjectFile(
        ctx.cobj(
            proto_c,
            "ext-session-lock-v1-protocol",
            proto_flags,
        ),
    );

    if (have_pam) {
        const pam_mod = b.createModule(.{
            .root_source_file = b.path("pam.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        pam_mod.addImport("types", types_mod);
        pam_mod.addImport("log", log_mod);
        pam_mod.addImport("comm", comm_mod);
        pam_mod.addIncludePath(b.path("include"));
        pam_mod.addIncludePath(proto_h_dir);
        for (sys_includes.items) |flag| {
            const fi = std.mem.trim(u8, flag, " \t\n\r");
            if (std.mem.startsWith(u8, fi, "-I")) {
                const path = fi[2..];
                pam_mod.addSystemIncludePath(.{ .cwd_relative = path });
                if (std.fs.path.dirname(path)) |parent| {
                    pam_mod.addSystemIncludePath(.{ .cwd_relative = parent });
                }
            }
        }
        const pam_obj = b.addObject(.{
            .name = "pam",
            .root_module = pam_mod,
        });
        exe_mod.addObjectFile(pam_obj.getEmittedBin());
        exe_mod.addObjectFile(
            ctx.cobj(b.path("pam_gdm_shim.c"), "pam_gdm_shim", c_flags),
        );
        exe_mod.linkSystemLibrary("pam", .{});
        if (have_qrencode)
            exe_mod.linkSystemLibrary("libqrencode", .{});
    } else {
        exe_mod.addObjectFile(
            ctx.cobj(b.path("shadow.c"), "shadow", c_flags),
        );
        // libcrypt is not a pkg-config package; link directly.
        exe_mod.linkSystemLibrary("crypt", .{ .use_pkg_config = .no });
    }

    exe_mod.linkSystemLibrary("wayland-client", .{});
    exe_mod.linkSystemLibrary("xkbcommon", .{});
    exe_mod.linkSystemLibrary("cairo", .{});
    if (have_gdk_pixbuf)
        exe_mod.linkSystemLibrary("gdk-pixbuf-2.0", .{});
    // libm and librt are glibc components that still need explicit
    // link flags in some configurations.
    exe_mod.linkSystemLibrary("m", .{ .use_pkg_config = .no });
    exe_mod.linkSystemLibrary("rt", .{ .use_pkg_config = .no });

    const exe = b.addExecutable(.{
        .name = "swaylock",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);
}
