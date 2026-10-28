//! Standalone macOS Apple Silicon CLI.
const std = @import("std");
const builtin = @import("builtin");
const cli = @import("macos/cli.zig");

comptime {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64)
        @compileError("lejav-gen-navicat requires macOS ARM64");
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or std.mem.eql(u8, args[1], "help") or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        return std.Io.File.stdout().writeStreamingAll(init.io, cli.usageText());
    }
    if (std.mem.eql(u8, args[1], "version") or std.mem.eql(u8, args[1], "--version")) {
        return std.Io.File.stdout().writeStreamingAll(init.io, "lejav-gen-navicat 0.4.1 (macos/arm64)\n");
    }
    cli.run(init.gpa, init.io, init, args[1..]) catch |err| {
        std.debug.print("error: {s}\n", .{explain(err)});
        std.process.exit(1);
    };
}

fn explain(err: anyerror) []const u8 {
    return switch (err) {
        error.UnsupportedMacBinary => "此 Mac 应用文件与已验证的 18.0.5 (321) ARM64 文件不匹配，未写入补丁。",
        error.NoArm64Slice, error.UnsupportedArm64Subtype => "需要普通 ARM64 的 Mac 应用；不支持 Intel-only 或 arm64e。",
        error.NotMachO, error.InvalidMachO, error.TruncatedMachO => "目标不是完整、有效的 ARM64 Mach-O 文件。",
        error.MissingOutputApp => "请用 --out 指定新的 .app 输出路径。",
        error.OutputMustBeApp => "输出路径必须以 .app 结尾。",
        error.OutputInsideSource => "输出不能等于原应用或位于原应用内部。",
        error.ExternalBundleSymlink => "应用包含指向包外的符号链接，已停止复制补丁流程。",
        error.PrivateKeyInsideApp => "私钥必须存放在应用包之外。",
        error.KeyMismatch => "私钥与应用副本中的公钥不匹配。",
        error.PatchVerificationFailed => "补丁或文件摘要校验失败。",
        error.SourceChangedDuringCopy => "复制过程中源文件发生变化，请在更新完成后重试。",
        error.NotMacRequest => "请求码不是 MAC 平台请求码。",
        error.MissingName => "缺少 --name 注册名。",
        error.MissingOrganization => "缺少 --org 组织名。",
        error.MissingRequest => "缺少 --request 请求码，推荐使用 --request @request.txt。",
        error.InvalidRequestCode => "请求码应为 Base64 编码的 256 字节密文。",
        error.SigningFailed => "此私钥无法解开请求码，请确认请求来自使用同一密钥处理过的应用副本。",
        error.PayloadTooLarge => "注册信息过长，请缩短名称或组织名。",
        error.OutputExists, error.PathAlreadyExists => "输出路径已存在；请选择新路径。只有 keygen 支持 --force 替换密钥。",
        error.FileNotFound => "文件或目录不存在，请检查 --app、--key、--request 和输出父目录。",
        error.AccessDenied, error.PermissionDenied => "无法访问该路径，请选择当前用户可读写的目录。",
        error.MissingMatchingKey => "已有应用副本，但找不到配套私钥；请找回原私钥，或用 --out 选择新副本路径。",
        error.NavicatAlreadyRunning => "请先手动退出正在运行的 Navicat，再运行 activate。工具不会强制关闭连接。",
        error.InteractiveTerminalRequired => "activate 的引导需要交互终端；只准备文件请使用 --prepare-only。",
        error.UserCanceled => "已退出引导；应用副本和私钥已保留，可以稍后重新运行 activate。",
        error.ClipboardFailed => "无法访问剪贴板，请在本机桌面终端运行。",
        error.MissingValue => "命令参数缺少值，运行 lejav-gen-navicat --help 查看用法。",
        error.UnknownOption, error.UnknownCommand => "未知命令或参数，运行 lejav-gen-navicat --help 查看用法。",
        error.UnsupportedVersion => "序列号生成支持 16–31；应用补丁仅支持已验证的 18.0.5 (321)。",
        error.UnexpectedApplication => "--app 必须指向 Navicat Premium.app。",
        error.LocalSignatureNeedsRepair => "副本仍携带原厂受限权限，无法使用本地签名启动。运行 activate 将自动修复。",
        error.ApplicationLaunchFailed => "应用副本已准备并保留，但启动失败。请保留上方系统错误；这不代表补丁生成失败。",
        error.ExternalCommandFailed => "系统命令执行失败，具体原因见上方输出。",
        else => @errorName(err),
    };
}
