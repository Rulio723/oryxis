<p align="center">
  <img src="resources/logo_128.png" width="120" alt="Oryxis logo">
</p>

<h1 align="center">Oryxis</h1>

<p align="center">
  完全使用 Rust 构建的现代 SSH 客户端。快速、加密、原生。
</p>

<p align="center">
  <a href="README.md">English</a> | 简体中文 | <a href="README.zh-TW.md">繁體中文</a> | <a href="README.ja.md">日本語</a> | <a href="README.ko.md">한국어</a> | <a href="README.fa.md">فارسی</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <a href="https://github.com/wilsonglasser/oryxis/releases/latest"><img src="https://img.shields.io/github/v/release/wilsonglasser/oryxis?color=green" alt="Release"></a>
  <img src="https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-blue" alt="Platforms">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License"></a>
  <a href="https://oryxis.app"><img src="https://img.shields.io/badge/website-oryxis.app-3CBBB1" alt="Website"></a>
</p>

<p align="center">
  <img src="resources/screen_1.gif" width="720" alt="Oryxis 演示：连接主机、运行代码片段、浏览 SFTP">
</p>

> 本文档基于 v0.15.0 之后的英文 README 翻译（2026-08-24 同步）。
> 详细文档（[功能一览](docs/FEATURES.md)、[架构说明](docs/ARCHITECTURE.md)）为英文。

## Oryxis 是什么？

Oryxis 是 [Termius](https://termius.com/) 的开源替代品：一款桌面 SSH
客户端，拥有现代化界面和本地加密保险库来保存凭据，全程没有任何云账号。
没有 Electron、没有 webview、没有厂商服务器，只有一个原生二进制文件。

|  | Oryxis | Termius | PuTTY | Tabby |
|--|--------|---------|-------|-------|
| 界面技术栈 | 原生 Rust（iced + wgpu） | Electron | 原生 | Electron |
| 许可证 | AGPL-3.0，开源 | 专有 | MIT | MIT |
| 凭据存储 | 本地加密保险库 | 厂商云账号 | 无 | 本地配置文件 |
| 多设备同步 | P2P 端到端加密，可自建中继 | 厂商云（订阅） | 无 | 通过 Tabby Web |
| SFTP 图形界面 | 内置双栏 | 付费版 | 仅命令行 | 基础面板 |
| 价格 | 免费 | 免费版 + 订阅 | 免费 | 免费 |

## 安装

**Windows**

[![从 Microsoft Store 获取](https://get.microsoft.com/images/zh-cn%20dark.svg)](https://apps.microsoft.com/detail/9NTKPPSHBTG2)

或使用终端：

```powershell
winget install WilsonGlasser.Oryxis
```

**Arch Linux (AUR)**

```bash
yay -S oryxis-bin
```

**直接下载**：前往[最新版本页](https://github.com/wilsonglasser/oryxis/releases/latest)，
提供 Linux（`.tar.gz` / `.deb` / `.AppImage`，x86_64 与 ARM64）、
macOS（Apple Silicon `.dmg`）和 Windows（系统级与用户级安装器、便携版
`.zip`，x86_64 与 ARM64）。Windows 二进制已进行 Authenticode 签名。

### 便携数据模式

在可执行文件旁放置名为 `oryxis.portable` 的文件后，Oryxis 自有数据会
保存到同目录的 `.oryxis/`，不再写入用户主目录。需要移动到 U 盘时，
请一起复制可执行文件、标记文件和 `.oryxis/`。用户自行选择的外部路径，
例如 SSH 配置、下载目录和自定义会话日志目录，不会被强制迁移。

### 中国大陆网络说明

在无法顺畅访问 GitHub 的网络环境下，Oryxis 内置了下载镜像支持：

- **自动模式（默认）**：中日韩字体、插件和应用更新会先尝试 GitHub，
  无法访问时自动回退到项目镜像 `dl-cn.oryxis.app`（腾讯 EdgeOne
  加速，与三大运营商直连）。无需任何配置。
- **自定义镜像**：在 设置 > 高级 > 下载镜像 中选择"自定义镜像"，
  可以填入任何 ghproxy 前缀代理，例如 `https://gh-proxy.com` 或
  `https://ghfast.top`，并用"测试"按钮验证连通性。
- 所有下载内容均经过 SHA-256 或 Ed25519 签名校验，镜像本身无需被信任。

首次把界面语言切换为简体中文时会自动下载 Noto Sans SC 字体（走同样的
镜像逻辑）。连接旧设备时可在主机编辑器中按主机选择 GBK / GB18030 /
Big5 编码。

## 亮点

- **原生且快速**：纯 Rust、GPU 加速的 [iced](https://iced.rs) 界面、
  单一二进制。没有 Electron。
- **本地加密保险库**：Argon2id + ChaCha20-Poly1305 字段级加密，可选
  主密码、生物识别解锁（Windows Hello / Touch ID / Linux 密钥环）、
  闲置自动锁定、TOTP 两步验证自动填充，以及在 `sudo` 提示处
  提供保险库密码（绝不自动发送）。
- **完整的 SSH 能力**：自动认证、多级跳板机、SOCKS / HTTP / 命令代理、
  Agent 转发、独立的 `-L`/`-R`/`-D` 端口转发、面向菜单式堡垒机
  （JumpServer 等）的 expect/send 登录脚本、一键导入 `~/.ssh/config`。
- **不止 SSH**：Telnet 与串口控制台、面向控制台服务器的裸 TCP 连接、
  ZMODEM 传输、本地 Shell，以及通过 SSH 隧道一键 RDP/VNC。
- **能扛住网络变化的会话**：为主机开启 mosh，Shell 就能挺过休眠、
  切换 Wi-Fi 与更换地址；界面会直接告诉你链路已经多久没有联系，
  而不是假装一切正常。原生 Rust 客户端，说的是官方 `mosh-server`
  的协议，本机无需额外安装任何东西。
- **真正的终端**：基于 alacritty 的仿真器、分屏、会话组、按主机主题、
  内置 Nerd 字体外加可下载字体包（JetBrains Mono、Fira Code、
  MesloLGS 等）、标记长时间运行命令的智能标签页、按主机命令历史。
- **文件无处不在**：双栏 SFTP 支持拖放、原位编辑、服务器到服务器复制；
  每个 SSH 标签页还带有跟随工作目录的文件侧栏。
- **会话录制**：静态加密存储；可导出 asciinema `.cast`（内嵌主题）或
  纯文本记录，设计上只录制输出。
- **云账号**：AWS、Google Cloud、Azure 与 Kubernetes 的资源发现和连接
  （EC2、SSM、ECS Exec、GKE、AKS、`kubectl`），以签名插件按需下载。
- **AI 伴随工作**：每个标签页的 AI 助手（自带密钥：Anthropic、OpenAI、
  Gemini 或兼容服务），多层自动执行安全控制，另有
  [MCP 服务器](docs/FEATURES.md#mcp-server)可把主机暴露给 Claude Code
  等 AI 客户端。
- **P2P 同步，无云端**：端到端加密（X25519 + XChaCha20-Poly1305），
  基于 QUIC；局域网内 mDNS 发现，跨网络可[自建](SELF_HOSTING.md)
  信令/中继。没有账号，没有厂商服务器。
- **键盘优先**：`user@host` 快速连接（Ctrl+K）、最近标签页切换、
  覆盖到每一个开关的完整键盘导航、所有快捷键可重绑定。
- **隐私为本**：无任何遥测、隐私模式打码、粘贴前给你确认内容的
  粘贴保护，以及包含完整 RTL 支持的
  [23 种语言](docs/FEATURES.md#themes--internationalization)：English、
  Português、Español、Français、Deutsch、Italiano、简体中文、繁體中文、
  日本語、Русский、فارسی、العربية、עברית、한국어、Polski、Türkçe、
  Bahasa Indonesia、Tiếng Việt、Українська、ไทย、हिन्दी、Čeština、Ελληνικά。

完整功能清单见英文[功能一览](docs/FEATURES.md)。
在用 tmux？**[tmux 下的日志与命令历史](docs/TMUX.md)**（英文）说明了哪些功能开箱即用、哪些需要自行安装。
想让文件浏览器精确跟随 shell 的目录？**[跟随 shell 的目录](docs/CWD.md)**（英文）提供了代码片段。

## 快速上手

1. **首次启动**：设置主密码，或先跳过（之后可在设置中开启，并启用
   生物识别解锁）。
2. **添加主机**：点击 `+ HOST`，或直接输入 `user@host`（Ctrl+K）
   免保存连接。`~/.ssh/config` 一键导入。
3. **连接**：点击主机卡片。分屏、文件侧栏、SFTP 和代码片段都只有
   一个按键的距离。
4. **可选扩展**：AI 聊天（设置 > AI）、MCP 服务器（设置 > 安全）、
   设备间 P2P 同步（设置 > 同步）。

有问题？看看 [FAQ](https://github.com/wilsonglasser/oryxis/discussions/66)
（含中文板块），或发起
[讨论](https://github.com/wilsonglasser/oryxis/discussions)。

## 安全

所有敏感数据均以字段级加密存储（Argon2id + ChaCha20-Poly1305），主机
密钥采用 TOFU 固定，同步载荷端到端加密，插件在执行前经过 Ed25519 签名
校验，并且没有任何遥测。

完整的安全模型与漏洞披露政策见 [SECURITY.md](SECURITY.md)。请通过私密
渠道报告安全漏洞。

## 路线图

Oryxis 以大约每周一次的节奏持续发布，功能就绪即上线。最新稳定版为
**v0.15.0**；完整历史见 [CHANGELOG.md](CHANGELOG.md)，交互式路线图见
[路线图讨论](https://github.com/wilsonglasser/oryxis/discussions/67)。
正在推进的方向包括：原生 FIDO2（通过 USB / NFC 直接与安全密钥通信）、
多保险库，
以及面向中文用户的阿里云 / 腾讯云支持和东亚宽度选项。原生 mosh
客户端、按主机启用的磁盘密钥（`~/.ssh`）以及重新打开上一个关闭的
标签页已在本版本发布。

## 参与贡献

欢迎贡献。**可以直接用中文提 issue 或参与讨论**，维护者会阅读并尽力
回复；代码、提交信息与代码注释保持英文。开发环境、质量门槛与项目约定
见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

Copyright (C) 2026 Wilson Glasser。基于
[AGPL-3.0-or-later](LICENSE) 许可发布：任何人都可以使用、修改和分发
Oryxis，但通过网络提供的修改版本必须以相同许可证公开其源代码。详见
[NOTICE](NOTICE)。

---

<p align="center">
  用 Rust 构建，献给以终端为家的人。
</p>
