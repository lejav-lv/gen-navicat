# lejav-gen-navicat

适用于 Mac M 系列芯片。当前支持 **Navicat Premium 18.0.5（321）ARM64**。

## 怎么用

**从 GitHub 获取源码后**，先安装 Zig 0.17.0 与 ARM64 OpenSSL 3，在项目目录运行 `./tools/build-macos.sh`，生成 `bin/lejav-gen-navicat`。完整步骤见[编译说明](docs/ADVANCED.md#重新构建)。本机下载文件夹中已经编译好的版本可直接使用。

仓库只保存源码、脚本和文档；应用副本、配套私钥、编译产物和备份均不上传。

先退出正在运行的 Navicat，且断网

双击 **`开始激活.command`**。

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

## Community

- **[linux.do](https://linux.do)** - A thriving developer community.
