# lejav-gen-navicat

适用于 Mac M 系列芯片。当前支持 **Navicat Premium 18.0.5（321）ARM64**。

## 怎么用

**从 GitHub 获取源码后**，先安装 Zig 0.17.0 与 ARM64 OpenSSL 3，在项目目录运行 `./tools/build-macos.sh`，生成 `bin/lejav-gen-navicat`。完整步骤见[编译说明](docs/ADVANCED.md#重新构建)。本机下载文件夹中已经编译好的版本可直接使用。

仓库只保存源码、脚本和文档；应用副本、配套私钥、编译产物和备份均不上传。

先退出正在运行的 Navicat，然后在终端执行这一条：

```bash
~/Downloads/lejav-gen-navicat/bin/lejav-gen-navicat activate
```

也可以在这个文件夹里双击 **`开始激活.command`**。

**v0.5.0 默认处理原安装位置 `/Applications/Navicat Premium.app`，之后仍从原来的入口打开。**
工具会复用现有配套密钥，先在临时位置完成补丁和签名检查，再原子替换原位置应用。
原文件完整保留在 `/Applications/Navicat Premium.app.original-backup-随机值/Navicat Premium.app`，
终端会显示确切路径。重复运行会检查并复用已处理的应用，不重复备份。
接着按终端提示做三步：

1. **粘贴序列号并打开手动激活**：在 Navicat 的注册窗口粘贴。先保存正在进行的联网工作，临时断开 Wi-Fi；如果还接着网线，也要断开，再点击“激活”。若出现“手动激活”，点击它。
2. **复制请求码**：回到终端按回车，工具自动生成并复制响应码。
3. **粘贴响应码**：回到 Navicat，粘贴后点击“激活”。

“请求码”是手动激活窗口中生成的一长段文本，不是序列号，也不是 `90010003` 错误码。
如果只看到 `90010003` 和“好”，说明还没进入请求码页面；断网后仍没有“手动激活”时，先停止，不要将错误码粘贴进终端。完成或取消后恢复网络。
[Navicat 18 Mac 官方手册（Registration）](https://www.navicat.com/manual/pdf_manual/en/navicat_18/mac_manual/navicat_mac_en.pdf) 说明手动激活适用于没有互联网连接的情况；当前尚未实测本机断网后的入口。

**这是一条命令启动的引导流程，还不是无需操作的全自动激活。**
是否激活成功，以 Navicat 注册窗口显示为准；`status` 只检查文件、签名和密钥。
序列号旁边的绿色勾、关于页面显示序列号，都不代表激活完成。如果注册页仍写着
“现在激活来完成…激活进程”或“请在…前激活”，就是尚未完成激活。
当前没有验证通过完整的界面激活流程；退出并重开同一个应用后，还应复查注册状态。

## 文件在哪里

- `bin/lejav-gen-navicat`：工具。
- `/Applications/Navicat Premium.app`：默认处理并启动的应用。
- `/Applications/Navicat Premium.app.original-backup-随机值/`：原应用的完整备份。
- `artifacts/Navicat Premium ARM64.app`：旧版生成的独立副本，新默认流程不启动它。
- `artifacts/RegPrivateKey.pem`：配套私钥，请保留，不要分享或随意替换。

工具不会强制关闭你的数据库连接。原位置模式即使指定 `--prepare-only`，也要求先退出 Navicat。
**v0.4.1 已修复启动错误 163**；已处理应用的旧签名会自动修复，无需重新生成密钥。

若仍需要独立副本，可显式指定 `--out`：

```bash
./bin/lejav-gen-navicat activate --out "artifacts/Navicat Premium ARM64.app"
```

如需自定义注册名，命令后加 `--name "你的名字" --org "你的组织"`。

[详细命令与编译方法](docs/ADVANCED.md) · [实现与验证记录](docs/IMPLEMENTATION.md)
