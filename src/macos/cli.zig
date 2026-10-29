//! Native macOS entry point. Activate updates the installed app with a backup;
//! patch and activate --out retain the separate-copy workflow.
const std = @import("std");
const builtin = @import("builtin");
const macho = @import("macho.zig");
const license = @import("license.zig");
const rsa = @import("../common/rsa.zig");
const openssl = @import("../common/openssl.zig");
const serial = @import("../common/serial.zig");
const local_entitlements = @embedFile("local.entitlements.plist");
const default_app = "/Applications/Navicat Premium.app";
const library_relative = "Contents/Frameworks/libcc.dylib";
const manifest_relative = "Contents/Resources/lejav-gen-navicat-patch.json";

const usage =
    \\lejav-gen-navicat (macOS Apple Silicon) <command> [options]
    \\
    \\  activate          备份并处理原位置应用，再启动激活引导
    \\  doctor / status   Inspect application, ARM64 slice and patch status (read only)
    \\  repair-signature  修复本工具旧副本的本地签名（activate 会自动处理）
    \\  keygen            Generate an RSA-2048 PEM private key (mode 0600)
    \\  serial            Generate a version/product/language-specific serial
    \\  patch             Create and ad-hoc sign a separate patched .app copy
    \\  sign              Generate a manual activation response from a request
    \\
    \\activate:      [--name <name>] [--org <org>] [--prepare-only]
    \\               [--app <installed.app>] [--out <separate.app>] [--key <pem>]
    \\doctor/status: [--app <app>] [--key <pem>]
    \\keygen:        [--out <pem>] [--force]
    \\serial:        [--version 18] [--language SimplifiedChinese] [--product Premium]
    \\patch:         [--app <app>] --out <new.app> [--key <pem>] [--dry-run]
    \\sign:          --request <base64|@file> --name <name> --org <org> [--key <pem>]
    \\
    \\Default app: /Applications/Navicat Premium.app
    \\Default key: RegPrivateKey.pem
    \\Patch profile: Navicat Premium 18.0.5 (321), macOS arm64 only.
    \\activate updates --app in place with an original backup; --out selects a separate copy.
    \\Other versions fail before writing. Explicit --out paths are never overwritten.
    \\The patch command does not claim activation; complete manual activation in the app.
    \\This macOS-only tool uses manual activation; it does not edit hosts.
    \\
;

pub fn usageText() []const u8 {
    return usage;
}

const Options = struct {
    app: []const u8 = default_app,
    key: []const u8 = "RegPrivateKey.pem",
    out: ?[]const u8 = null,
    request: ?[]const u8 = null,
    name: ?[]const u8 = null,
    org: ?[]const u8 = null,
    version: u8 = 18,
    product: serial.Product = .Premium,
    language: serial.Language = .SimplifiedChinese,
    dry_run: bool = false,
    force: bool = false,
    explicit_key: bool = false,
    prepare_only: bool = false,
    quiet: bool = false,
    allow_legacy_signature: bool = false,

    fn parse(args: []const []const u8, allowed: []const []const u8) !Options {
        var out: Options = .{};
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            var accepted = false;
            for (allowed) |option| if (std.mem.eql(u8, option, arg)) {
                accepted = true;
                break;
            };
            if (!accepted) return error.UnknownOption;
            if (std.mem.eql(u8, arg, "--prepare-only")) {
                out.prepare_only = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--dry-run")) {
                out.dry_run = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--force")) {
                out.force = true;
                continue;
            }
            i += 1;
            if (i >= args.len or std.mem.startsWith(u8, args[i], "--")) return error.MissingValue;
            const value = args[i];
            if (std.mem.eql(u8, arg, "--app")) out.app = value else if (std.mem.eql(u8, arg, "--key")) {
                out.key = value;
                out.explicit_key = true;
            } else if (std.mem.eql(u8, arg, "--out")) out.out = value else if (std.mem.eql(u8, arg, "--request")) out.request = value else if (std.mem.eql(u8, arg, "--name")) out.name = value else if (std.mem.eql(u8, arg, "--org")) out.org = value else if (std.mem.eql(u8, arg, "--version")) out.version = try std.fmt.parseInt(u8, value, 10) else if (std.mem.eql(u8, arg, "--product")) out.product = serial.Product.fromName(value) orelse return error.InvalidProduct else if (std.mem.eql(u8, arg, "--language")) out.language = serial.Language.fromName(value) orelse return error.InvalidLanguage;
        }
        return out;
    }
};

fn print(io: std.Io, comptime format: []const u8, args: anytype) !void {
    var buffer: [8192]u8 = undefined;
    try std.Io.File.stdout().writeStreamingAll(io, try std.fmt.bufPrint(&buffer, format, args));
}

fn read(allocator: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit));
}

fn command(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) ![]u8 {
    const result = try std.process.run(allocator, io, .{ .argv = argv, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20) });
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        allocator.free(result.stdout);
        try std.Io.File.stderr().writeStreamingAll(io, result.stderr);
        return error.ExternalCommandFailed;
    }
    return result.stdout;
}

fn runCommand(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    const out = try command(allocator, io, argv);
    allocator.free(out);
}

fn join(allocator: std.mem.Allocator, root: []const u8, leaf: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, leaf });
}

fn appPath(allocator: std.mem.Allocator, io: std.Io, raw: []const u8) ![:0]u8 {
    const path = try std.Io.Dir.cwd().realPathFileAlloc(io, raw, allocator);
    errdefer allocator.free(path);
    const plist = try join(allocator, path, "Contents/Info.plist");
    defer allocator.free(plist);
    const id = try command(allocator, io, &.{ "/usr/bin/plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", plist });
    defer allocator.free(id);
    if (!std.mem.eql(u8, std.mem.trim(u8, id, "\r\n"), "com.navicat.NavicatPremium")) return error.UnexpectedApplication;
    return path;
}

fn privateKey(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !rsa.PrivateKey {
    const data = try read(allocator, io, path, 64 * 1024);
    defer allocator.free(data);
    return rsa.PrivateKey.fromPem(allocator, data);
}

fn publicBase64(allocator: std.mem.Allocator, key: rsa.PrivateKey) ![]u8 {
    const der = try key.publicSpkiDer(allocator);
    defer allocator.free(der);
    const encoder = std.base64.standard.Encoder;
    const result = try allocator.alloc(u8, encoder.calcSize(der.len));
    _ = encoder.encode(result, der);
    return result;
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, init: std.process.Init, args: []const []const u8) !void {
    if (args.len == 0) return print(io, "{s}", .{usage});
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "activate")) {
        return activate(allocator, io, init, try Options.parse(args[1..], &.{ "--app", "--out", "--key", "--name", "--org", "--prepare-only" }));
    } else if (std.mem.eql(u8, cmd, "doctor") or std.mem.eql(u8, cmd, "status")) {
        return status(allocator, io, try Options.parse(args[1..], &.{ "--app", "--key" }));
    } else if (std.mem.eql(u8, cmd, "repair-signature")) {
        return repairSignature(allocator, io, try Options.parse(args[1..], &.{ "--app", "--key" }));
    } else if (std.mem.eql(u8, cmd, "keygen")) {
        return keygen(allocator, io, try Options.parse(args[1..], &.{ "--out", "--force" }));
    } else if (std.mem.eql(u8, cmd, "serial")) {
        const options = try Options.parse(args[1..], &.{ "--version", "--product", "--language" });
        if (options.version < 16 or options.version > 31) return error.UnsupportedVersion;
        const value = try serial.makeSerial(allocator, io, options.version, options.product, options.language);
        return print(io, "{s}-{s}-{s}-{s}\n", .{ value[0..4], value[4..8], value[8..12], value[12..16] });
    } else if (std.mem.eql(u8, cmd, "patch")) {
        return patchApp(allocator, io, try Options.parse(args[1..], &.{ "--app", "--out", "--key", "--dry-run" }));
    } else if (std.mem.eql(u8, cmd, "sign")) {
        const options = try Options.parse(args[1..], &.{ "--request", "--name", "--org", "--key" });
        const request = options.request orelse return error.MissingRequest;
        const name = options.name orelse return error.MissingName;
        const org = options.org orelse return error.MissingOrganization;
        const key = try privateKey(allocator, io, options.key);
        const text = if (std.mem.startsWith(u8, request, "@")) try read(allocator, io, request[1..], 64 * 1024) else try allocator.dupe(u8, request);
        defer allocator.free(text);
        const signed = try license.sign(allocator, key, text, name, org, std.Io.Clock.real.now(io).toSeconds());
        defer allocator.free(signed);
        return print(io, "{s}\n", .{signed});
    }
    return error.UnknownCommand;
}

fn keygen(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const path = options.out orelse "RegPrivateKey.pem";
    // Exclusive creation prevents accidental overwrite. --force uses atomic
    // replacement, so an existing symlink is not followed or chmod'ed.
    const key = try openssl.generatePrivateKey(allocator);
    defer allocator.free(key);
    if (options.force) {
        var atomic = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .permissions = .fromMode(0o600) });
        defer atomic.deinit(io);
        try atomic.file.writeStreamingAll(io, key);
        try atomic.replace(io);
    } else {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, key);
    }
    if (!options.quiet) try print(io, "Private key: {s} (0600)\n", .{path});
}

const Manifest = struct {
    tool: []const u8 = "lejav-gen-navicat",
    schema: u8 = 1,
    signing_revision: u8 = 0,
    profile: []const u8 = macho.profile_name,
    source_sha256: []const u8,
    patched_sha256: []const u8,
    public_key_sha256: []const u8,
};

fn status(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const app = try appPath(allocator, io, options.app);
    defer allocator.free(app);
    const path = try join(allocator, app, library_relative);
    defer allocator.free(path);
    const data = try read(allocator, io, path, 512 << 20);
    defer allocator.free(data);
    const image = try macho.Image.parse(data);
    if (!options.quiet) try print(io, "Host:       {s}/{s}\nApp:        {s}\nLibrary:    ARM64 Mach-O (slice +0x{x})\nSHA-256:    {s}\n", .{ @tagName(builtin.os.tag), @tagName(builtin.cpu.arch), app, image.slice_offset, macho.digest(image.bytes()) });
    if (macho.installedKey(image)) |public| {
        const manifest_path = try join(allocator, app, manifest_relative);
        defer allocator.free(manifest_path);
        const json = try read(allocator, io, manifest_path, 64 * 1024);
        defer allocator.free(json);
        const manifest = try std.json.parseFromSlice(Manifest, allocator, json, .{});
        defer manifest.deinit();
        if (!std.mem.eql(u8, manifest.value.tool, "lejav-gen-navicat") or manifest.value.schema != 1 or !std.mem.eql(u8, manifest.value.patched_sha256, &macho.digest(data)) or !std.mem.eql(u8, manifest.value.public_key_sha256, &macho.digest(public))) return error.PatchVerificationFailed;
        try runCommand(allocator, io, &.{ "/usr/bin/codesign", "--verify", "--deep", "--strict", app });
        if (!options.allow_legacy_signature and try needsSignatureRepair(allocator, io, app)) return error.LocalSignatureNeedsRepair;
        if (!options.quiet) try print(io, "Patch:      Installed; manifest and code signature verified\n", .{});
        if (options.explicit_key) {
            const key = try privateKey(allocator, io, options.key);
            const expected = try publicBase64(allocator, key);
            defer allocator.free(expected);
            if (!std.mem.eql(u8, public, expected)) return error.KeyMismatch;
            if (!options.quiet) try print(io, "Key:        Matches installed public key\n", .{});
        }
    } else {
        image.requireSupported() catch |err| {
            if (!options.quiet) try print(io, "Patch:      Unsupported binary; no files changed\n", .{});
            return err;
        };
        if (!options.quiet) try print(io, "Patch:      Original supported binary: {s}\n", .{macho.profile_name});
    }
    if (!options.quiet) try print(io, "Activation: Not inferred from files; confirm in Navicat's registration window\n", .{});
}

fn isInside(path: []const u8, parent: []const u8) bool {
    return std.mem.eql(u8, path, parent) or (std.mem.startsWith(u8, path, parent) and path.len > parent.len and path[parent.len] == '/');
}

fn validateBundleLinks(allocator: std.mem.Allocator, io: std.Io, app: []const u8) !void {
    const output = try command(allocator, io, &.{ "/usr/bin/find", "-P", app, "-type", "l", "-print0" });
    defer allocator.free(output);
    var links = std.mem.splitScalar(u8, output, 0);
    while (links.next()) |link| {
        if (link.len == 0) continue;
        const resolved = try std.Io.Dir.cwd().realPathFileAlloc(io, link, allocator);
        defer allocator.free(resolved);
        if (!isInside(resolved, app)) return error.ExternalBundleSymlink;
    }
}

fn patchApp(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const output = options.out orelse return error.MissingOutputApp;
    if (!std.mem.endsWith(u8, output, ".app")) return error.OutputMustBeApp;
    const app = try appPath(allocator, io, options.app);
    defer allocator.free(app);
    const parent = try std.Io.Dir.cwd().realPathFileAlloc(io, std.fs.path.dirname(output) orelse ".", allocator);
    defer allocator.free(parent);
    const destination = try join(allocator, parent, std.fs.path.basename(output));
    defer allocator.free(destination);
    if (isInside(destination, app)) return error.OutputInsideSource;
    // access/stat follows symlinks; opening the parent and exclusive rename at
    // publication also protects against a dangling link appearing meanwhile.
    if (std.Io.Dir.cwd().statFile(io, destination, .{ .follow_symlinks = false })) |_| return error.OutputExists else |err| if (err != error.FileNotFound) return err;
    const key_path = try std.Io.Dir.cwd().realPathFileAlloc(io, options.key, allocator);
    defer allocator.free(key_path);
    if (isInside(key_path, app)) return error.PrivateKeyInsideApp;
    const key = try privateKey(allocator, io, key_path);
    const public = try publicBase64(allocator, key);
    defer allocator.free(public);
    const source_path = try join(allocator, app, library_relative);
    defer allocator.free(source_path);
    try validateBundleLinks(allocator, io, app);
    const original = try read(allocator, io, source_path, 512 << 20);
    defer allocator.free(original);
    const patched = try macho.patch(allocator, original, public);
    defer allocator.free(patched);
    if (!options.quiet) try print(io, "Profile:    {s}\nSource:     {s}\nOutput:     {s}\nPatch:      0x{x}, {d} bytes; original hash verified\n", .{ macho.profile_name, app, destination, macho.function_offset, macho.patch_len });
    if (options.dry_run) return print(io, "Dry run: no files written.\n", .{});
    var random: [12]u8 = undefined;
    io.random(&random);
    const stage_name = try std.fmt.allocPrint(allocator, ".lejav-gen-navicat-stage-{s}.app", .{std.fmt.bytesToHex(&random, .lower)});
    defer allocator.free(stage_name);
    const stage = try join(allocator, parent, stage_name);
    defer allocator.free(stage);
    try std.Io.Dir.cwd().createDir(io, stage, .fromMode(0o700));
    var published = false;
    defer if (!published) {
        std.Io.Dir.cwd().deleteTree(io, stage) catch {};
    };
    if (!options.quiet) try print(io, "Copying application…\n", .{});
    try runCommand(allocator, io, &.{ "/usr/bin/ditto", app, stage });
    try validateBundleLinks(allocator, io, stage);
    const target = try join(allocator, stage, library_relative);
    defer allocator.free(target);
    // Detect updates/races during ditto before applying the precomputed patch.
    const copied = try read(allocator, io, target, 512 << 20);
    defer allocator.free(copied);
    if (!std.mem.eql(u8, &macho.digest(copied), &macho.digest(original))) return error.SourceChangedDuringCopy;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = target, .data = patched });
    try runCommand(allocator, io, &.{ "/usr/bin/codesign", "--force", "--sign", "-", target });
    // Re-sign nested components in the disposable copy first. The supplied app
    // may already have invalid helper signatures; verify the complete copy.
    try runCommand(allocator, io, &.{ "/usr/bin/codesign", "--force", "--deep", "--sign", "-", stage });
    try signRoot(allocator, io, stage);
    const signed = try read(allocator, io, target, 512 << 20);
    defer allocator.free(signed);
    const installed = macho.installedKey(try macho.Image.parse(signed)) orelse return error.PatchVerificationFailed;
    if (!std.mem.eql(u8, installed, public)) return error.PatchVerificationFailed;
    const source_digest = macho.digest((try macho.Image.parse(original)).bytes());
    const patched_digest = macho.digest(signed);
    const key_digest = macho.digest(public);
    const manifest = try std.json.Stringify.valueAlloc(allocator, Manifest{ .signing_revision = 1, .source_sha256 = &source_digest, .patched_sha256 = &patched_digest, .public_key_sha256 = &key_digest }, .{ .whitespace = .indent_2 });
    defer allocator.free(manifest);
    const manifest_path = try join(allocator, stage, manifest_relative);
    defer allocator.free(manifest_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = manifest_path, .data = manifest });
    try signRoot(allocator, io, stage);
    try runCommand(allocator, io, &.{ "/usr/bin/codesign", "--verify", "--deep", "--strict", stage });
    if (try needsSignatureRepair(allocator, io, stage)) return error.LocalSignatureNeedsRepair;
    try std.Io.Dir.cwd().renamePreserve(stage, .cwd(), destination, io);
    published = true;
    if (!options.quiet) try print(io, "Created and verified: {s}\nNext: open this copy and complete manual activation with lejav-gen-navicat serial / lejav-gen-navicat sign.\nActivation has not been verified.\n", .{destination});
}

test "paths respect directory boundaries" {
    try std.testing.expect(isInside("/A.app/Contents", "/A.app"));
    try std.testing.expect(!isInside("/A.app2", "/A.app"));
    try std.testing.expect(isInside("/A.app", "/A.app"));
}

test "CLI rejects misspelled flags and missing values" {
    try std.testing.expectError(error.UnknownOption, Options.parse(&.{"--overwrite"}, &.{"--out"}));
    try std.testing.expectError(error.MissingValue, Options.parse(&.{"--out"}, &.{"--out"}));
    try std.testing.expectError(error.MissingValue, Options.parse(&.{ "--out", "--dry-run" }, &.{ "--out", "--dry-run" }));
}

fn exists(io: std.Io, path: []const u8) !bool {
    _ = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn artifactsForExecutable(allocator: std.mem.Allocator, executable: []const u8) ![]u8 {
    var root = std.fs.path.dirname(executable) orelse return error.InvalidOutputPath;
    if (std.mem.eql(u8, std.fs.path.basename(root), "bin")) root = std.fs.path.dirname(root) orelse root;
    if (std.mem.eql(u8, std.fs.path.basename(root), "zig-out")) root = std.fs.path.dirname(root) orelse root;
    return join(allocator, root, "artifacts");
}

fn copyClipboard(io: std.Io, value: []const u8) !void {
    var child = try std.process.spawn(io, .{ .argv = &.{"/usr/bin/pbcopy"}, .stdin = .pipe, .stdout = .ignore, .stderr = .ignore });
    child.stdin.?.writeStreamingAll(io, value) catch |err| {
        child.stdin.?.close(io);
        child.stdin = null;
        _ = child.wait(io) catch {};
        return err;
    };
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.ClipboardFailed;
}

fn requireNavicatClosed(allocator: std.mem.Allocator, io: std.Io) !void {
    const result = try std.process.run(allocator, io, .{ .argv = &.{ "/usr/bin/pgrep", "-x", "Navicat Premium" }, .stdout_limit = .limited(8192), .stderr_limit = .limited(8192) });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited) return error.ExternalCommandFailed;
    if (result.term.exited == 0) return error.NavicatAlreadyRunning;
    if (result.term.exited != 1) {
        try std.Io.File.stderr().writeStreamingAll(io, result.stderr);
        return error.ProcessCheckFailed;
    }
}

// Both directories remain present across this operation, including interruption.
// Never fall back to deleting or incrementally overwriting the installed bundle.
fn exchangePaths(allocator: std.mem.Allocator, first: []const u8, second: []const u8) !void {
    const first_z = try allocator.dupeSentinel(u8, first, 0);
    defer allocator.free(first_z);
    const second_z = try allocator.dupeSentinel(u8, second, 0);
    defer allocator.free(second_z);
    switch (std.c.errno(std.c.renameatx_np(std.c.AT.FDCWD, first_z, std.c.AT.FDCWD, second_z, .{ .SWAP = true, .NOFOLLOW_ANY = true }))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        else => return error.AtomicExchangeFailed,
    }
}

test "atomic app replacement preserves original and can be reversed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try temp.dir.createDir(io, "installed.app", .default_dir);
    try temp.dir.createDirPath(io, "backup/installed.app");
    try temp.dir.writeFile(io, .{ .sub_path = "installed.app/content", .data = "original" });
    try temp.dir.writeFile(io, .{ .sub_path = "backup/installed.app/content", .data = "patched" });
    const installed = try temp.dir.realPathFileAlloc(io, "installed.app", allocator);
    defer allocator.free(installed);
    const backup = try temp.dir.realPathFileAlloc(io, "backup/installed.app", allocator);
    defer allocator.free(backup);
    const original_stat = try temp.dir.statFile(io, "installed.app", .{});
    const patched_stat = try temp.dir.statFile(io, "backup/installed.app", .{});
    try exchangePaths(allocator, installed, backup);
    try std.testing.expectEqual(original_stat.inode, (try temp.dir.statFile(io, "backup/installed.app", .{})).inode);
    try std.testing.expectEqual(patched_stat.inode, (try temp.dir.statFile(io, "installed.app", .{})).inode);
    try exchangePaths(allocator, installed, backup);
    try std.testing.expectEqual(original_stat.inode, (try temp.dir.statFile(io, "installed.app", .{})).inode);
    const missing = try join(allocator, backup, "missing");
    defer allocator.free(missing);
    try std.testing.expectError(error.FileNotFound, exchangePaths(allocator, installed, missing));
    try std.testing.expectEqual(original_stat.inode, (try temp.dir.statFile(io, "installed.app", .{})).inode);
}

fn verifyOrRepair(allocator: std.mem.Allocator, io: std.Io, app: []const u8, key: []const u8) !void {
    status(allocator, io, .{ .app = app, .key = key, .explicit_key = true, .quiet = true }) catch |err| switch (err) {
        error.LocalSignatureNeedsRepair => {
            try print(io, "检测到旧版签名配置，正在修复启动兼容性…\n", .{});
            try repairSignature(allocator, io, .{ .app = app, .key = key, .explicit_key = true, .quiet = true });
        },
        else => return err,
    };
}

fn prepareInstalledApp(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    try requireNavicatClosed(allocator, io);
    const source_stat = try std.Io.Dir.cwd().statFile(io, options.app, .{ .follow_symlinks = false });
    if (source_stat.kind != .directory) return error.AppMustBeDirectory;
    const app = try appPath(allocator, io, options.app);
    defer allocator.free(app);
    try validateBundleLinks(allocator, io, app);
    const library = try join(allocator, app, library_relative);
    defer allocator.free(library);
    const original = try read(allocator, io, library, 512 << 20);
    defer allocator.free(original);
    const image = try macho.Image.parse(original);
    if (macho.installedKey(image) != null) {
        if (!try exists(io, options.key)) return error.MissingMatchingKey;
        try verifyOrRepair(allocator, io, app, options.key);
        return;
    }
    // Reject unknown versions before creating a key or backup directory.
    try image.requireSupported();
    const key_parent_raw = std.fs.path.dirname(options.key) orelse ".";
    if (!options.explicit_key) try std.Io.Dir.cwd().createDirPath(io, key_parent_raw);
    const key_parent = try std.Io.Dir.cwd().realPathFileAlloc(io, key_parent_raw, allocator);
    defer allocator.free(key_parent);
    if (isInside(key_parent, app)) return error.PrivateKeyInsideApp;
    if (!try exists(io, options.key)) try keygen(allocator, io, .{ .out = options.key, .quiet = true });
    var random: [12]u8 = undefined;
    io.random(&random);
    const backup_dir = try std.fmt.allocPrint(allocator, "{s}.original-backup-{s}", .{ app, std.fmt.bytesToHex(&random, .lower) });
    defer allocator.free(backup_dir);
    const backup_app = try join(allocator, backup_dir, std.fs.path.basename(app));
    defer allocator.free(backup_app);
    try std.Io.Dir.cwd().createDir(io, backup_dir, .fromMode(0o700));
    var keep_backup = false;
    defer if (!keep_backup) {
        std.Io.Dir.cwd().deleteTree(io, backup_dir) catch {};
    };
    // Prepare and verify everything away from the installed app. After the swap,
    // this location contains the untouched original, not the prepared bundle.
    try patchApp(allocator, io, .{ .app = app, .out = backup_app, .key = options.key, .quiet = true });
    try status(allocator, io, .{ .app = backup_app, .key = options.key, .explicit_key = true, .quiet = true });
    try requireNavicatClosed(allocator, io);
    const current_stat = try std.Io.Dir.cwd().statFile(io, app, .{ .follow_symlinks = false });
    if (current_stat.kind != .directory or current_stat.inode != source_stat.inode) return error.SourceChangedDuringCopy;
    const current = try read(allocator, io, library, 512 << 20);
    defer allocator.free(current);
    if (!std.mem.eql(u8, &macho.digest(original), &macho.digest(current))) return error.SourceChangedDuringCopy;
    try print(io, "原位置：{s}\n原文件备份将保留在：{s}\n", .{ app, backup_app });
    try exchangePaths(allocator, app, backup_app);
    keep_backup = true;
    status(allocator, io, .{ .app = app, .key = options.key, .explicit_key = true, .quiet = true }) catch |err| {
        exchangePaths(allocator, app, backup_app) catch {
            std.debug.print("替换后校验失败，自动回退未成功；原文件仍保留在：{s}\n", .{backup_app});
            return error.RestoreFailed;
        };
        keep_backup = false;
        return err;
    };
    try print(io, "原位置应用已更新，完整备份已保留。激活状态仍需在注册窗口确认。\n", .{});
}

fn activate(allocator: std.mem.Allocator, io: std.Io, init: std.process.Init, options: Options) !void {
    // Check interaction before creating files or touching the clipboard.
    if (!options.prepare_only) {
        if (!try std.Io.File.stdin().isTty(io)) return error.InteractiveTerminalRequired;
        try requireNavicatClosed(allocator, io);
    }
    const executable = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(executable);
    const artifacts = try artifactsForExecutable(allocator, executable);
    defer allocator.free(artifacts);
    const key_path = if (options.explicit_key) try allocator.dupe(u8, options.key) else try join(allocator, artifacts, "RegPrivateKey.pem");
    defer allocator.free(key_path);
    const output = try allocator.dupe(u8, options.out orelse options.app);
    defer allocator.free(output);
    try print(io, "\nlejav-gen-navicat 激活引导\n\n[1/3] 准备并检查{s}…\n", .{if (options.out == null) "原位置应用（保留原文件备份）" else "应用副本"});
    if (options.out == null) {
        try prepareInstalledApp(allocator, io, .{ .app = output, .key = key_path, .explicit_key = options.explicit_key });
    } else {
        const has_app = try exists(io, output);
        const has_key = try exists(io, key_path);
        if (has_app and !has_key) return error.MissingMatchingKey;
        if (!has_app) {
            // Unknown input fails before creating a private key or an output folder.
            try status(allocator, io, .{ .app = options.app, .quiet = true });
            if (!options.explicit_key) try std.Io.Dir.cwd().createDirPath(io, artifacts);
            if (!has_key) try keygen(allocator, io, .{ .out = key_path, .quiet = true });
            try patchApp(allocator, io, .{ .app = options.app, .key = key_path, .out = output, .quiet = true });
        }
        try verifyOrRepair(allocator, io, output, key_path);
    }
    try print(io, "应用和配套密钥检查通过。\n当前目标：{s}\n", .{output});
    if (options.prepare_only) {
        return print(io, "\n准备完成。未启动应用、未访问剪贴板，也未执行界面激活。\n", .{});
    }
    const name = options.name orelse init.environ_map.get("USER") orelse "User";
    const org = options.org orelse "Personal";
    const key = try privateKey(allocator, io, key_path);
    const value = try serial.makeSerial(allocator, io, 18, .Premium, .SimplifiedChinese);
    var serial_text: [19]u8 = undefined;
    const display = try std.fmt.bufPrint(&serial_text, "{s}-{s}-{s}-{s}", .{ value[0..4], value[4..8], value[8..12], value[12..16] });
    try copyClipboard(io, display);
    runCommand(allocator, io, &.{ "/usr/bin/open", "-n", output }) catch return error.ApplicationLaunchFailed;
    try print(
        io,
        "\n[2/3] 已打开目标应用，序列号已复制：{s}\n" ++
            "在 Navicat 菜单 → 注册 中粘贴序列号。\n" ++
            "先保存联网工作，临时断开 Wi-Fi/网线，再点“激活”；若出现“手动激活”，点击进入。\n" ++
            "请求码是该窗口中的一长段文本；90010003 是错误码，不是请求码。\n" ++
            "断网后仍没有手动激活入口时先停止。完成或取消后恢复网络。\n" ++
            "复制窗口里的“请求码”，回到这里按回车，我会读取剪贴板。\n" ++
            "也可以直接把请求码粘贴在这里。输入 q 退出。\n" ++
            "注册名：{s}；组织：{s}\n",
        .{ display, name, org },
    );
    var input_buffer: [8192]u8 = undefined;
    var input = std.Io.File.stdin().reader(io, &input_buffer);
    while (true) {
        try print(io, "\n请求码已复制后按回车（或粘贴请求码）> ", .{});
        const raw_line = (try input.interface.takeDelimiter('\n')) orelse return error.UserCanceled;
        const line = std.mem.trim(u8, raw_line, " \r\t");
        if (std.ascii.eqlIgnoreCase(line, "q")) return error.UserCanceled;
        const request = if (line.len == 0) try command(allocator, io, &.{"/usr/bin/pbpaste"}) else try allocator.dupe(u8, line);
        defer allocator.free(request);
        const signed = license.sign(allocator, key, request, name, org, std.Io.Clock.real.now(io).toSeconds()) catch |err| {
            switch (err) {
                error.InvalidRequestCode, error.SigningFailed, error.NotMacRequest, error.MissingField => {
                    try print(io, "读取到的内容不是此应用的有效请求码（{s}）。\n请复制“请求码”区域的完整内容，再按回车重试。\n", .{@errorName(err)});
                    continue;
                },
                else => return err,
            }
        };
        defer allocator.free(signed);
        try copyClipboard(io, signed);
        try print(
            io,
            "\n[3/3] 响应码已生成并复制。\n" ++
                "回到 Navicat 的“手动激活”窗口，粘贴到响应码区域，然后点“激活”。\n" ++
                "最终结果以注册窗口为准；工具尚未读取或确认激活状态。\n",
            .{},
        );
        return;
    }
}

test "activate state paths do not depend on working directory" {
    const allocator = std.testing.allocator;
    const release = try artifactsForExecutable(allocator, "/Users/me/Downloads/lejav-gen-navicat/bin/lejav-gen-navicat");
    defer allocator.free(release);
    try std.testing.expectEqualStrings("/Users/me/Downloads/lejav-gen-navicat/artifacts", release);
    const development = try artifactsForExecutable(allocator, "/Users/me/Downloads/lejav-gen-navicat/zig-out/bin/lejav-gen-navicat");
    defer allocator.free(development);
    try std.testing.expectEqualStrings(release, development);
}

fn containsIdentityEntitlements(xml: []const u8) bool {
    const names = [_][]const u8{
        "com.apple.application-identifier",    "application-identifier",
        "com.apple.developer.team-identifier", "com.apple.security.application-groups",
        "keychain-access-groups",
    };
    inline for (names) |name| {
        if (std.mem.indexOf(u8, xml, "<key>" ++ name ++ "</key>") != null) return true;
    }
    return false;
}

fn needsSignatureRepair(allocator: std.mem.Allocator, io: std.Io, app: []const u8) !bool {
    const xml = try command(allocator, io, &.{ "/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", app });
    defer allocator.free(xml);
    return containsIdentityEntitlements(xml);
}

// Only preserve the target's existing unrestricted runtime capabilities. Never
// copy vendor/team/keychain identities into an ad-hoc signature: AMFI rejects it
// even when `codesign --verify` succeeds (launchd error 163).
fn signRoot(allocator: std.mem.Allocator, io: std.Io, app: []const u8) !void {
    var random: [12]u8 = undefined;
    io.random(&random);
    const name = try std.fmt.allocPrint(allocator, ".lejav-gen-navicat-entitlements-{s}.plist", .{std.fmt.bytesToHex(&random, .lower)});
    defer allocator.free(name);
    const path = try join(allocator, std.fs.path.dirname(app) orelse ".", name);
    defer allocator.free(path);
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        defer file.close(io);
        try file.writeStreamingAll(io, local_entitlements);
    }
    try runCommand(allocator, io, &.{ "/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", path, app });
}

fn repairSignature(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    try requireNavicatClosed(allocator, io);
    const app = try appPath(allocator, io, options.app);
    defer allocator.free(app);
    try validateBundleLinks(allocator, io, app);
    // A genuine lejav-gen-navicat manifest, unchanged patched library and matching
    // key (when supplied) are required. This never repairs an original vendor app.
    try status(allocator, io, .{ .app = app, .key = options.key, .explicit_key = options.explicit_key, .quiet = true, .allow_legacy_signature = true });
    const manifest_path = try join(allocator, app, manifest_relative);
    defer allocator.free(manifest_path);
    const json = try read(allocator, io, manifest_path, 64 * 1024);
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(Manifest, allocator, json, .{});
    defer parsed.deinit();
    if (!try needsSignatureRepair(allocator, io, app)) {
        if (!options.quiet) try print(io, "签名配置已经兼容，无需修改。\n", .{});
        return;
    }
    var random: [8]u8 = undefined;
    io.random(&random);
    const backup = try std.fmt.allocPrint(allocator, "{s}.signature-backup-{s}", .{ app, std.fmt.bytesToHex(&random, .lower) });
    defer allocator.free(backup);
    try std.Io.Dir.cwd().createDir(io, backup, .fromMode(0o700));
    const executable = try join(allocator, app, "Contents/MacOS/Navicat Premium");
    defer allocator.free(executable);
    const signature = try join(allocator, app, "Contents/_CodeSignature");
    defer allocator.free(signature);
    const backup_executable = try join(allocator, backup, "Navicat Premium");
    defer allocator.free(backup_executable);
    const backup_signature = try join(allocator, backup, "_CodeSignature");
    defer allocator.free(backup_signature);
    const backup_manifest = try join(allocator, backup, "manifest.json");
    defer allocator.free(backup_manifest);
    try std.Io.Dir.cwd().copyFile(executable, .cwd(), backup_executable, io, .{ .replace = false });
    try std.Io.Dir.cwd().copyFile(manifest_path, .cwd(), backup_manifest, io, .{ .replace = false });
    try runCommand(allocator, io, &.{ "/usr/bin/ditto", signature, backup_signature });
    errdefer {
        std.Io.Dir.cwd().copyFile(backup_executable, .cwd(), executable, io, .{ .replace = true }) catch {};
        std.Io.Dir.cwd().copyFile(backup_manifest, .cwd(), manifest_path, io, .{ .replace = true }) catch {};
        runCommand(allocator, io, &.{ "/usr/bin/ditto", backup_signature, signature }) catch {};
        std.debug.print("签名修复失败，已尝试还原。原始备份保留在：{s}\n", .{backup});
    }
    var manifest = parsed.value;
    manifest.signing_revision = 1;
    const updated = try std.json.Stringify.valueAlloc(allocator, manifest, .{ .whitespace = .indent_2 });
    defer allocator.free(updated);
    var atomic = try std.Io.Dir.cwd().createFileAtomic(io, manifest_path, .{});
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, updated);
    try atomic.replace(io);
    try signRoot(allocator, io, app);
    try status(allocator, io, .{ .app = app, .key = options.key, .explicit_key = options.explicit_key, .quiet = true });
    if (!options.quiet) try print(io, "已修复本地签名配置，并通过整包校验。\n备份：{s}\n", .{backup});
}

test "local signing excludes vendor identities and retains runtime capabilities" {
    try std.testing.expect(!containsIdentityEntitlements(local_entitlements));
    try std.testing.expect(std.mem.indexOf(u8, local_entitlements, "com.apple.security.cs.allow-jit") != null);
    try std.testing.expect(containsIdentityEntitlements("<plist><dict><key>keychain-access-groups</key><array/></dict></plist>"));
    try std.testing.expect(containsIdentityEntitlements("<key>com.apple.developer.team-identifier</key><string>VENDOR</string>"));
    try std.testing.expect(!containsIdentityEntitlements("<key>com.apple.security.app-sandbox</key><true/>"));
}
