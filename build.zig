const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    if (target.result.os.tag != .macos or target.result.cpu.arch != .aarch64) {
        @panic("This project builds for macOS ARM64 only. Use an Apple Silicon Mac.");
    }
    const prefix = b.option([]const u8, "openssl-prefix", "ARM64 OpenSSL 3 installation prefix") orelse "/opt/homebrew/opt/openssl@3";
    const crypto = b.pathJoin(&.{ prefix, "lib", "libcrypto.a" });
    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    // Static linkage: the delivered executable has no Homebrew runtime dependency.
    module.addObjectFile(.{ .cwd_relative = crypto });
    const executable = b.addExecutable(.{ .name = "lejav-gen-navicat", .root_module = module });
    b.installArtifact(executable);

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_module.addObjectFile(.{ .cwd_relative = crypto });
    const tests = b.addTest(.{ .root_module = test_module });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run macOS ARM64 tests");
    test_step.dependOn(&run_tests.step);
}
