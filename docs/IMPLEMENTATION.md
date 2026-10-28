# 实现与验证记录

日期：2026-10-28（Asia/Shanghai）。

## 参考材料

- `~/Downloads/keygen`：参考序列号、RSA 与请求响应格式。
- `~/Downloads/navz`：较早的 Zig 实现。
- `~/Downloads/navz (1)`：新项目最初采用的代码基础。

保留可复用的 DER、PEM、RSA、DES 和序列号代码，并将依赖统一放到 `src/common/`。
新项目只保留 `src/macos/` 平台入口。没有保留其他操作系统的实现或构建目标。

## Mac 差异

本机目标为 `/Applications/Navicat Premium.app`：

- `CFBundleIdentifier`：`com.navicat.NavicatPremium`。
- 版本：18.0.5，构建号 321。
- 主程序和 `libcc.dylib` 为 Mach-O ARM64。
- `libcc.dylib` 原始 ARM64 切片 SHA-256：
  `0a51210bb5fc20e0931a6326d7c0d51953e009b3da0d910c4a66003f0a839ff5`。

使用 Mach-O 装载命令、RTTI 字符串 `29CSRegistrationInfoFetcher_MAC` 和虚表交叉
定位到返回公钥的函数。虚表第 7 个槽位（从 0 开始）指向 `0x2a7fbfc`，函数起点
由 `LC_FUNCTION_STARTS` 核对；下一函数起点为 `0x2a94068`。
该函数开始构造 `MI…` 公钥字符串，内部使用 `0x23b0` 的字符串存储分配函数。

补丁覆盖该函数开头 448 字节：56 字节 ARM64 指令和 392 字节 SPKI Base64 公钥。
它使用 Apple ARM64 ABI 的 x8 间接返回地址，调用原有 libc++ 字符串分配函数，
填入公钥并写入结尾 NUL。BL 位移通过带范围和对齐检查的编码器生成。全文件指纹
和可执行段范围必须同时匹配后才允许生成补丁；不对未知版本猜测偏移。

解析器识别 ARM64 thin Mach-O，以及 FAT32/FAT64 容器中的普通 ARM64 切片。
当前真实应用验证样本为 thin ARM64；通用二进制容器只进行了合成样本测试。

## 单命令引导

`activate` 组合已有命令：自动定位状态目录、匹配并复用已有密钥及副本、准备缺失文件、
生成序列号、启动副本、引导复制请求码并生成响应码。不会自动关闭正在运行的 Navicat。
`--prepare-only` 只执行准备和校验；正常模式要求交互终端。GUI 最后确认仍由用户操作。

## 文件与签名处理

- 必须指定新的 `.app` 输出路径，且拒绝覆盖已有目录及符号链接。
- 源应用和复制后的应用均检查包外符号链接。
- 使用 `ditto` 复制到随机临时目录，复制后再次校验原库摘要。
- 只在副本中修改库，使用系统 `codesign` 对嵌套组件和根应用重新签名。
- 附带 `Contents/Resources/lejav-gen-navicat-patch.json`，记录原库摘要、签名后库摘要和公钥
  摘要；不包含私钥。
- 通过 `codesign --verify --deep --strict` 后再以不覆盖方式发布最终目录。
- 原样本的签名验证已经失败；副本的嵌套重新签名也修复了辅助程序的校验问题。

本地 ad-hoc 签名只用于副本的代码完整性验证，不等于厂商签名或公证。

## 已执行验证

- Zig 0.17.0，原生 ARM64 ReleaseSafe 编译；18 项单元测试通过。
- `file` 确认为 ARM64 Mach-O；`otool -L` 仅列出系统 libSystem。
- `doctor` 识别源应用及其完整文件指纹。
- 对真实应用创建副本，完成补丁、公钥匹配、清单摘要与整包签名检查。
- 原生 C 测试执行实际生成的补丁和从目标库复制的原字符串分配函数 100 次，
  验证返回对象边界、392 字节正文、长度、容量和 NUL；只将 operator-new 调用
  接到测试分配器，不加载完整应用或访问用户偏好。
- 31 项子进程集成检查通过：Python 使用 OpenSSL CLI 独立生成 RSA 加密请求，验证工具响应签名，
  覆盖 UTF-8/引号转义、错误密钥、无效请求码、私钥 0600 权限、禁止覆盖、
  符号链接保护、未知文件拒绝、dry-run 不写入及 activate 准备流程重复运行不改写现有文件。
- 新建临时应用副本和现有已修复副本均通过完整签名验证；确认签名不含厂商绑定权限，
  清单中的 signing_revision 为 1；测试后自动删除临时副本。
- 对现有副本完成旧签名自动迁移，并通过系统启动服务实际打开 Navicat 主窗口。

**尚未验证：** 在 Navicat GUI 中输入请求响应后能否完成注册并在重启后保持；
应用启动已验证；检查注册窗口时，在线激活返回 90010003，尚未完成离线请求响应流程。
工具的 `status` 会明确报告激活状态需要界面确认，
不会把补丁成功或签名通过报告为激活成功。

## 构建依赖

Mac 可执行文件静态链接 OpenSSL 3 `libcrypto.a`。随附其 Apache 2.0 许可证：
`licenses/OpenSSL-LICENSE.txt`。运行无需额外安装 OpenSSL；编译需要匹配 ARM64 的
静态库。编译器按 [Zig 官方下载清单](https://ziglang.org/download/index.json)
校验 SHA-256 后使用。

## v0.4.1：启动错误 163 修复

系统 AMFI 日志确认旧副本被拒绝的原因是本地 ad-hoc 签名保留了受限权限。
旧代码使用 `--preserve-metadata=entitlements`，把厂商绑定的应用身份、Team ID、
应用分组和钥匙串分组带进了本地签名。此时 `codesign --verify` 可以通过，
实际启动仍会失败。

新版使用 `src/macos/local.entitlements.plist` 明确列出的目标运行时权限签名，
不继承厂商身份信息；没有修改系统安全设置。新副本在发布前额外检查签名权限。
`activate` 检测旧副本后会自动修复，也可单独运行 `repair-signature`。

修复前必须退出 Navicat，并验证清单、库摘要、完整签名以及提供的配套密钥。
主程序、签名资源和清单先备份到副本旁的 `.signature-backup-随机值` 目录；
失败时尝试还原并保留备份。修复不重新生成密钥，也不改写补丁库。
启动失败的提示现已明确说明副本保留，不再误报为“未发布不完整的应用副本”。
