# lejav-gen-navicat — Apple Silicon 版

仅面向 **macOS + Apple Silicon（ARM64）** 的命令行工具。

当前补丁只适配本机读取并核对过的 **Navicat Premium 18.0.5，build 321，ARM64**。

## 源码与本机产物

GitHub 仓库包含源码、脚本和文档。下表中的 `bin/` 与 `artifacts/` 是本机生成的文件，
不随仓库分发；从源码使用时请先完成[重新构建](#重新构建)，再运行 `activate`。

| 路径 | 用途 |
| --- | --- |
| `bin/lejav-gen-navicat` | 已编译、签名的 ARM64 程序，直接使用 |
| `artifacts/Navicat Premium ARM64.app` | 已生成的应用副本，补丁及完整代码签名已验证 |
| `artifacts/RegPrivateKey.pem` | 与上述应用副本配套的私钥，权限 0600 |
| `src/` | Mac 版源码及公共加密模块 |
| `tools/build-macos.sh` | 在 Apple Silicon 上重新编译和测试 |
| `tools/test-macos.py` | 加密互操作与命令行集成测试 |
| `tools/test-arm64-stub.c` | 真机执行 ARM64 补丁指令的测试 |
| `docs/IMPLEMENTATION.md` | 实现依据、验证范围及限制 |

私钥与副本配套使用。不要重新生成后继续使用旧副本，也不要把私钥放进 `.app`
或对外分享。预编译的程序仅依赖系统 `libSystem`，运行时不需要安装 Zig 或 Homebrew。
源码构建仍需要 Zig 和 ARM64 OpenSSL 3 静态库。

## 使用现有产物

在终端进入目录：

```bash
cd ~/Downloads/lejav-gen-navicat
./bin/lejav-gen-navicat --version
./bin/lejav-gen-navicat doctor
./bin/lejav-gen-navicat status \
  --app "artifacts/Navicat Premium ARM64.app" \
  --key artifacts/RegPrivateKey.pem
```

`status` 校验补丁内容、文件摘要、应用签名，以及显式指定的密钥是否匹配。
**这些校验不代表 Navicat 已完成激活。最终状态以应用的注册窗口为准。**
当前已验证副本能够打开主窗口；完整 GUI 激活尚未验证通过。

手动流程：

1. 关闭当前正在运行的 Navicat，在 Finder 中打开
   `artifacts/Navicat Premium ARM64.app`。确保启动的是该副本。
2. 生成序列号：

   ```bash
   ./bin/lejav-gen-navicat serial --version 18 --language SimplifiedChinese
   ```

3. 在应用菜单中打开注册窗口，填入序列号，进入“手动激活”页面。该入口通常在
   在没有互联网连接时出现；不能把所有在线激活失败都当作已进入离线流程。
   可以保存联网工作后临时断开 Wi-Fi 和网线，再点击激活检查入口；完成或取消后恢复网络。
   若只有 90010003 提示而没有手动激活按钮，则尚未进入请求码页面。界面入口说明可参见
   [Navicat 官方离线激活说明](https://help.navicat.com/hc/en-us/articles/47144754843801-Can-I-activate-my-license-without-internet-connection)。
   本工具没有界面自动点击功能，也不会修改 hosts。
4. 将页面上的请求码保存为 `request.txt`，然后执行：

   ```bash
   ./bin/lejav-gen-navicat sign \
     --key artifacts/RegPrivateKey.pem \
     --request @request.txt \
     --name "你的名字" \
     --org "你的组织"
   ```

5. 将终端输出的响应码填回同一个手动激活窗口，检查界面结果；再次启动后也应
   重新检查注册状态。若请求无法解密，优先核对是否打开了对应副本、是否使用
   配套私钥，以及请求码是否来自本次启动。

## 从原应用生成一个新副本

本机已经准备好副本时无需重复执行这一节。需要新建时，选择全新的输出目录：

```bash
./bin/lejav-gen-navicat keygen --out my-private.pem

# 只检查，不写文件
./bin/lejav-gen-navicat patch \
  --app "/Applications/Navicat Premium.app" \
  --key my-private.pem \
  --out "$HOME/Downloads/Navicat ARM64 New.app" \
  --dry-run

# 在新路径创建副本、打补丁、重新签名并验证
./bin/lejav-gen-navicat patch \
  --app "/Applications/Navicat Premium.app" \
  --key my-private.pem \
  --out "$HOME/Downloads/Navicat ARM64 New.app"
```

输出父目录必须已存在。工具拒绝覆盖已有路径（包括符号链接），拒绝输出到源
应用内部，也拒绝应用中指向包外的符号链接。失败时会清理本次创建的临时副本；
只有整包验证通过后才发布最终目录。无需 `sudo`。

本工具不修改 `/Applications` 中的原应用、系统 Gatekeeper 设置或用户注册配置。
应用副本使用本地 ad-hoc 签名，没有厂商公证身份；代码签名验证通过不等同于
Gatekeeper、公证或完整功能验证。若系统提示无法打开，请保留错误信息进一步
定位，不要自行关闭整个系统的安全检查。

## 重新构建

已验证编译器为 [Zig 0.17.0](https://ziglang.org/download/)，依赖 ARM64 OpenSSL 3。
如果本机缺少构建依赖，可以通过 Homebrew 安装相应版本。已编译产物无需此步骤。

```bash
# Zig 0.17.0 已在 PATH 时
./tools/build-macos.sh

# 也可明确指定工具路径
LEJAV_GEN_NAVICAT_ZIG=/完整路径/zig \
LEJAV_GEN_NAVICAT_OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3 \
./tools/build-macos.sh
```

脚本先运行单元测试，再构建并更新 `bin/lejav-gen-navicat`。构建只支持 macOS ARM64。

运行集成测试：

```bash
python3 tools/test-macos.py \
  --binary bin/lejav-gen-navicat \
  --source-app "/Applications/Navicat Premium.app"

xcrun clang -arch arm64 -Wall -Wextra -Werror -O2 \
  tools/test-arm64-stub.c -o /tmp/lejav-gen-navicat-test-arm64-stub
/tmp/lejav-gen-navicat-test-arm64-stub \
  "artifacts/Navicat Premium ARM64.app/Contents/Frameworks/libcc.dylib"
```

集成测试使用临时目录和临时密钥，不启动 Navicat、不写用户偏好配置。
`--source-app` 默认只用于只读的目标匹配与 dry-run 检查。
加上 `--build-copy` 可在临时目录创建并验证一个副本，测试完成后自动清理；源应用保持只读。
可加 `--prepared-app` 与 `--prepared-key` 检查现有副本的签名和重复准备行为。

## 回退与版本范围

`patch` 产生独立副本。停止使用并删除你生成的副本即可回退该文件级操作。
若随后手动改变了应用注册状态，注册设置由 Navicat 自身管理，不属于文件副本
回退范围；程序没有实现用户注册设置的备份或恢复。

当前只在这台 Apple Silicon Mac 的 macOS 27.0.1 上验证了构建、文件补丁、签名、
ARM64 指令执行、加密协议互操作与应用主窗口启动。没有声称覆盖其他 Navicat 构建、所有 macOS
版本或所有 M 系列机器的 GUI 激活。后续版本需要重新核对二进制和添加明确配置，
不能通过修改版本字符串绕过指纹检查。

## 单命令引导

`activate` 自动查找工具目录下的 `artifacts/`，与终端当前目录无关。
它会复用匹配的副本和私钥；已有副本却缺少私钥时停止，不会偷偷生成不匹配的密钥。
可用 `--prepare-only` 只准备和校验文件，不启动应用、不读写剪贴板。
交互模式会将序列号写入剪贴板；用户复制请求码并按回车后才读取剪贴板，再把响应码
写回剪贴板。不会自动点击注册按钮，也不会把生成响应码报告为激活成功。
默认注册名取当前用户名，组织为 Personal，可用 `--name`、`--org` 修改。

## 启动错误 163 的修复

v0.4.1 修复旧副本的受限签名权限。先退出 Navicat，再运行 README 中的 `activate`
命令会自动处理，复用原来的私钥和补丁库。只修复文件、不启动应用时可运行：

```bash
./bin/lejav-gen-navicat activate --prepare-only
```

指定其他由本工具生成的旧副本时：

```bash
./bin/lejav-gen-navicat repair-signature \
  --app "/完整路径/你的副本.app" \
  --key "/完整路径/配套私钥.pem"
```

修复会在副本旁保留 `.signature-backup-随机值` 备份目录；没有受限权限时不改写文件。
它不会处理缺少本工具清单的原应用。该修复解决启动兼容性，不等同于激活成功。
