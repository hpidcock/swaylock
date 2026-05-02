//! Linux Landlock sandbox enforcement.
//! Restricts filesystem access for both the main process (after
//! locking) and the PAM child process (after fork) to reduce the
//! attack surface to the minimum required for correct operation.

const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");

// Checks whether a raw Linux syscall return value signals an error.
// std.posix.errno uses the libc convention (rc == -1) when libc is
// linked, which is wrong for direct syscalls whose errors are encoded
// as negative values in [-4095, -1]. We always do the kernel check.
fn syscallFailed(rc: usize) bool {
    const signed: isize = @bitCast(rc);
    return signed < 0 and signed >= -4095;
}

// Passed as flags to landlock_create_ruleset to query ABI version.
const CREATE_RULESET_VERSION: u32 = 1 << 0;

// The only rule type we use: restrict access beneath a path.
const RULE_PATH_BENEATH: u32 = 1;

// Filesystem access rights.
// ABI v1 (Linux 5.13).
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SYM: u64 = 1 << 9;
const FS_MAKE_SOCK: u64 = 1 << 10;
const FS_MAKE_FIFO: u64 = 1 << 11;
const FS_MAKE_BLOCK: u64 = 1 << 12;
const FS_MAKE_IPC: u64 = 1 << 13;
// ABI v2 (Linux 5.19).
const FS_REFER: u64 = 1 << 14;
// ABI v3 (Linux 6.2).
const FS_TRUNCATE: u64 = 1 << 15;
// ABI v4 (Linux 6.7).
const FS_IOCTL_DEV: u64 = 1 << 16;

const ABI1: u64 =
    FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_READ_DIR |
    FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_CHAR | FS_MAKE_DIR |
    FS_MAKE_REG | FS_MAKE_SYM | FS_MAKE_SOCK | FS_MAKE_FIFO |
    FS_MAKE_BLOCK | FS_MAKE_IPC;
const ABI2: u64 = ABI1 | FS_REFER;
const ABI3: u64 = ABI2 | FS_TRUNCATE;
const ABI4: u64 = ABI3 | FS_IOCTL_DEV;

fn allForAbi(abi: u32) u64 {
    return switch (abi) {
        0 => 0,
        1 => ABI1,
        2 => ABI2,
        3 => ABI3,
        else => ABI4,
    };
}

// Active Landlock ruleset. Returned by init(); caller must deinit().
const Ruleset = struct {
    fd: i32,
    // Union of all access rights the kernel understands.
    all: u64,

    // Opens a new ruleset sized for the running kernel's ABI.
    // Returns null when Landlock is unavailable (kernel < 5.13
    // or the feature is disabled via CONFIG_SECURITY_LANDLOCK).
    fn init() ?Ruleset {
        // A zero-size attr with the VERSION flag returns the ABI
        // version rather than creating a ruleset.
        const ver_rc = linux.syscall3(
            .landlock_create_ruleset,
            0,
            0,
            CREATE_RULESET_VERSION,
        );
        if (syscallFailed(ver_rc)) return null;
        const abi: u32 = @truncate(ver_rc);
        const all = allForAbi(abi);
        // The ruleset attribute is a single u64 (handled_access_fs).
        var attr: [8]u8 = undefined;
        std.mem.writeInt(u64, &attr, all, .little);
        const fd_rc = linux.syscall3(
            .landlock_create_ruleset,
            @intFromPtr(&attr),
            attr.len,
            0,
        );
        if (syscallFailed(fd_rc)) return null;
        return Ruleset{ .fd = @intCast(fd_rc), .all = all };
    }

    fn deinit(self: Ruleset) void {
        std.posix.close(self.fd);
    }

    // Adds a PATH_BENEATH rule granting the given access mask
    // under path. Silently skips paths that do not exist.
    // Flags not supported by the current ABI are masked away;
    // if the resulting mask is empty the call is skipped.
    fn add(self: Ruleset, path: [:0]const u8, access: u64) void {
        const masked = access & self.all;
        if (masked == 0) return;
        const path_fd = std.posix.openZ(
            path,
            .{ .PATH = true, .CLOEXEC = true },
            0,
        ) catch return;
        defer std.posix.close(path_fd);
        // struct landlock_path_beneath_attr is __attribute__((packed)):
        // u64 allowed_access followed immediately by i32 parent_fd.
        // We construct it as 12 raw bytes to avoid C struct padding.
        var attr: [12]u8 = undefined;
        std.mem.writeInt(u64, attr[0..8], masked, .little);
        std.mem.writeInt(i32, attr[8..12], path_fd, .little);
        _ = linux.syscall4(
            .landlock_add_rule,
            @as(usize, @intCast(self.fd)),
            RULE_PATH_BENEATH,
            @intFromPtr(&attr),
            0,
        );
    }

    // Sets PR_SET_NO_NEW_PRIVS and applies the ruleset to the
    // calling thread (and, transitively, all its children).
    // Returns true on success.
    fn enforce(self: Ruleset) bool {
        // NO_NEW_PRIVS is required before restrict_self.
        _ = std.posix.prctl(
            .SET_NO_NEW_PRIVS,
            .{ @as(usize, 1), 0, 0, 0 },
        ) catch {};
        const rc = linux.syscall2(
            .landlock_restrict_self,
            @as(usize, @intCast(self.fd)),
            0,
        );
        return !syscallFailed(rc);
    }
};

/// Applies Landlock to the main process.
/// Must be called after the screen is locked and all file
/// resources (config, images) have been loaded, and after any
/// call to daemonize(). Prevents execve and confines writes to
/// the paths needed for Wayland shared-memory rendering.
pub fn applyToMain() void {
    const rs = Ruleset.init() orelse {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "landlock not supported by kernel, skipping sandbox",
            .{},
        );
        return;
    };
    defer rs.deinit();

    // Read-only view of the whole filesystem. This covers fonts,
    // shared libraries, and config from any path layout, including
    // NixOS /nix/store paths that are impossible to enumerate.
    // execve is not included so no child process can be spawned.
    const ro = FS_READ_FILE | FS_READ_DIR;

    // Read-write access for POSIX shared-memory files used by
    // the Wayland wl_shm pool buffers (shm_open + shm_unlink).
    const shm_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR |
        FS_MAKE_REG | FS_REMOVE_FILE | FS_TRUNCATE;

    // Device access for /dev/null and /dev/urandom; ioctl is
    // needed by some devices (e.g. DRM, evdev) accessed by libs.
    const dev_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR | FS_IOCTL_DEV;

    // Temporary files created by graphics libraries (Cairo, GDK).
    const tmp_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR |
        FS_MAKE_REG | FS_REMOVE_FILE | FS_MAKE_DIR |
        FS_REMOVE_DIR | FS_TRUNCATE;

    rs.add("/", ro);
    // Wayland shared-memory pool buffers.
    rs.add("/dev/shm", shm_rw);
    // Fallback shm path on some distributions.
    rs.add("/run/shm", shm_rw);
    // /dev/null, /dev/urandom, and device ioctls.
    rs.add("/dev", dev_rw);
    // Temporary files from graphics libraries.
    rs.add("/tmp", tmp_rw);

    // Wayland socket lives in XDG_RUNTIME_DIR (usually
    // /run/user/<uid>). We need read+write to send/recv frames.
    if (std.posix.getenv("XDG_RUNTIME_DIR")) |dir| {
        var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
        if (std.fmt.bufPrintZ(&buf, "{s}", .{dir})) |path| {
            rs.add(
                path,
                FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR,
            );
        } else |_| {}
    } else {
        // Best-effort fallback when the env var is absent.
        rs.add(
            "/run/user",
            FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR,
        );
    }

    // Fontconfig rewrites its user cache on first use after a
    // font change; without write access it silently degrades.
    if (std.posix.getenv("HOME")) |home| {
        var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
        if (std.fmt.bufPrintZ(
            &buf,
            "{s}/.cache/fontconfig",
            .{home},
        )) |path| {
            rs.add(path, shm_rw);
        } else |_| {}
    }

    if (rs.enforce()) {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "landlock sandbox active",
            .{},
        );
    } else {
        log.slog(
            log.LogImportance.info,
            @src(),
            "landlock_restrict_self failed",
            .{},
        );
    }
}

/// Applies Landlock to the PAM child process.
/// Must be called immediately after fork and stdio redirection,
/// before PAM is initialised. Prevents execve (blocking pam_exec
/// and similar) and confines writes to paths PAM legitimately
/// needs at runtime.
pub fn applyToPamChild() void {
    const rs = Ruleset.init() orelse return;
    defer rs.deinit();

    // Read-only view of everything: PAM modules are loaded via
    // dlopen from /lib/security (or distro equivalents), NSS
    // reads /etc/nsswitch.conf and /etc/passwd, and various
    // modules reach into /usr/share, /etc/ssl, etc.
    // execve is intentionally absent.
    const ro = FS_READ_FILE | FS_READ_DIR;

    // /dev/null is needed because stdio has been redirected there
    // before this function is called.
    const dev_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR | FS_IOCTL_DEV;

    // PAM writes authentication events to the system log.
    const log_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR |
        FS_MAKE_REG | FS_TRUNCATE;

    // PAM modules and authd need to create/remove sockets and
    // state files under /run (and its /var/run alias).
    const run_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR |
        FS_MAKE_REG | FS_REMOVE_FILE | FS_MAKE_SOCK;

    // Some PAM modules (e.g. pam_tmpfiles helpers) use /tmp.
    const tmp_rw =
        FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR |
        FS_MAKE_REG | FS_REMOVE_FILE | FS_MAKE_DIR |
        FS_REMOVE_DIR | FS_TRUNCATE;

    rs.add("/", ro);
    rs.add("/dev", dev_rw);
    rs.add("/var/log", log_rw);
    rs.add("/run", run_rw);
    // /var/run is a symlink to /run on modern systems but may
    // be a real directory on older ones.
    rs.add("/var/run", run_rw);
    rs.add("/tmp", tmp_rw);

    if (rs.enforce()) {
        log.slog(
            log.LogImportance.debug,
            @src(),
            "landlock sandbox active for PAM child",
            .{},
        );
    } else {
        log.slog(
            log.LogImportance.info,
            @src(),
            "landlock_restrict_self failed for PAM child",
            .{},
        );
    }
}
