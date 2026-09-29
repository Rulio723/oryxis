# Oryxis 官方上游二次开发说明

> 更新日期：2026-09-29<br>
> 适用分支：`feature/native-fido2-windows`<br>
> 本轮提交前基线：`fab5d986467620ad1c363949e54a2a5ff91f6b43`<br>
> 最新功能提交：以本文件所在提交为准

本文记录本 Fork 相对 Oryxis 官方上游增加或修改的功能、实现边界、关键文件、验证方法、便携版交付方式，以及以后同步官方更新的标准流程。它是维护文档，不替代源码和测试；如果文档与当前代码冲突，以代码和提交历史为准。

## 1. 仓库、基线与分支关系

- 官方上游：`https://github.com/wilsonglasser/oryxis`
- 本人 Fork：`https://github.com/Rulio723/oryxis`
- 本地 `origin`：目前指向本人 Fork。
- 二次开发分支：`feature/native-fido2-windows`
- 本轮开始时的上游基线：`16ad2af8`
- 本轮提交前 HEAD：`fab5d986`

当前提交链如下：

| 顺序 | 提交 | 功能 |
| --- | --- | --- |
| 1 | `3e16de22` | Windows 原生 FIDO2 SSH 认证 |
| 2 | `a58dc63e` | 侧栏“上次打开/指定默认页”持久化修复 |
| 3 | `5728bd2d` | 基于 `oryxis.portable` 标记的真正便携数据模式 |
| 4 | `fab5d986` | Windows 便携版任务栏图标修复 |
| 5 | 本文件所在提交 | 文件侧栏拖拽上传、下载位置选择、进度显示及管理员跨权限拖放 |

查看二次开发的总体差异：

```powershell
git log --oneline origin/main..feature/native-fido2-windows
git diff --stat origin/main...feature/native-fido2-windows
```

## 2. 功能一：Windows 原生 FIDO2 SSH 认证

### 2.1 用户可见行为

- 支持导入和使用 OpenSSH `sk-ssh-ed25519@openssh.com` 密钥句柄。
- SSH 登录时直接调用 YubiKey/FIDO2 安全密钥，不依赖外部 `ssh-agent`。
- 普通权限 Windows 使用 `webauthn.dll`，通过 Windows 安全中心完成选择和触摸。
- 管理员权限优先使用原生 CTAP2-over-HID，避免再次弹出 Windows 安全中心窗口。
- `SecurityKey` 认证方式是严格的硬件密钥模式：失败时不回退到密码、软件私钥或 agent。
- `Auto`/`Key` 遇到真正的 SK 句柄时，也会分派到原生硬件签名路径。

### 2.2 当前边界

- 已完整支持 Ed25519-SK。
- ECDSA-SK 可以识别和导入，但签名路径尚未完成，必须明确返回“不支持”，不能错误落入软件签名。
- Windows WebAuthn 与管理员 HID 两条路径都依赖真实硬件做最终验收。
- FIDO2 句柄不是私钥标量；Ed25519 私钥永远留在安全密钥内部。
- SK 记录不会暴露给 Oryxis 自带 ssh-agent，因为自家 agent 没有硬件交互上下文。

### 2.3 架构与关键文件

模型及持久化：

- `crates/oryxis-core/src/models/connection.rs`
  - 新增 `AuthMethod::SecurityKey`。
  - SSH 密钥算法增加 SK 类型和 `is_security_key()` 判定。
- `crates/oryxis-vault/src/store/connections.rs`
  - 保存和恢复 `security_key` 认证方式。
- `crates/oryxis-vault/src/keygen/mod.rs`
  - 接受 OpenSSH SK 密钥文件并保留完整 PEM。
  - 将 SK 密钥强制设置为不向 agent 暴露。
- `crates/oryxis-vault/src/keygen/disk.rs`
  - 默认扫描顺序末尾增加 `id_ed25519_sk`，避免遮蔽普通软件密钥。

SSH 原生实现位于 `crates/oryxis-ssh/src/sk/`：

- `credential.rs`：解析 application、flags、credential handle 和公钥。
- `signature.rs`：组装 OpenSSH SK 签名块。
- `signer.rs`：实现 `russh::Signer` 返回契约。
- `authenticator.rs`：选择 Windows WebAuthn 或管理员 HID。
- `webauthn_windows.rs`：调用 `WebAuthNAuthenticatorGetAssertion`。
- `hid_windows.rs`：SetupAPI/HID 枚举、CTAPHID 传输与诊断日志。
- `ctap.rs`：CTAPHID 分帧、CTAP2 CBOR 和状态码映射。
- `examples/sk_acceptance.rs`：不经过 UI 的真实硬件验收程序。

应用层：

- `crates/oryxis-app/src/connect_methods.rs`
- `crates/oryxis-app/src/dispatch_editor/`
- `crates/oryxis-app/src/views/host_panel/auth.rs`
- `crates/oryxis-app/src/dispatch_ssh/connect.rs`
- `crates/oryxis-app/src/agent_server/source.rs`
- `crates/oryxis-app/src/i18n/en.rs`

### 2.4 不能破坏的协议不变量

1. `AssertionRequest` 保留原始 SSH 待签名数据；HID 侧计算其 SHA-256，WebAuthn 侧把原始数据交给 Windows，避免双重哈希。
2. CTAPHID 初始命令必须带 `0x80` 标志：INIT/CBOR/KEEPALIVE/ERROR 为 `0x86/0x90/0xBB/0xBF`。
3. 初始包最多 57 字节，续包最多 59 字节；初始包长度表示整条消息长度。
4. CTAPHID_CBOR 的 payload 第一个字节是 CTAP 命令 `0x02`，之后才是 CBOR。
5. `allowList` 内的凭据描述符必须使用文本键 `"type"` 和 `"id"`，不能使用整数键。
6. WebAuthn 返回的 `authenticatorData[32]` 是 flags，`[33..37]` 是大端 counter。
7. `russh::Signer` 返回值必须是原始 `to_sign` 加一个外层 SSH string；不能只返回内层签名块。
8. `SecurityKey` 模式不得偷偷回退到其他认证方式。

### 2.5 FIDO2 验证

```powershell
$toolchain = 'C:\Users\Rulio\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin'
$env:PATH = 'D:\WorkBuddy\toolchains\gcc\mingw64\bin;' + $toolchain + ';' + $env:PATH
$env:CARGO_INCREMENTAL = '0'

& "$toolchain\cargo.exe" test -p oryxis-ssh sk:: --locked
& "$toolchain\cargo.exe" test -p oryxis-vault keygen:: --locked
& "$toolchain\cargo.exe" run -p oryxis-ssh --example sk_acceptance --locked -- `
  'C:\Users\Rulio\.ssh\id_ed25519_sk_la_vps'
```

已获得的真实硬件证据：

- 普通权限 WebAuthn：签名有效，退出码 0。
- 管理员权限 HID：签名有效，退出码 0。
- 两条路径都使用真实 `id_ed25519_sk` 句柄且不依赖 ssh-agent。

仍建议用户用保存的真实服务器执行一次完整登录，以覆盖服务器配置、UI 选择、触摸和终端进入全过程。

## 3. 功能二：侧栏活动页持久化与默认页优先级

提交：`a58dc63e`

### 3.1 原问题

- 设置“默认侧栏标签页”为“上次打开”后，关闭并重新启动程序，侧栏仍回到该侧第一个标签页。
- 指定“代码片段”等固定默认页后，连接自动打开侧栏时仍可能显示之前记住的“文件”页。

### 3.2 最终规则

```text
明确指定默认页 > 上次打开的活动页 > 当前侧可用的安全回退页
```

- 左右物理侧栏分别保存：
  - `sidebar_last_tab_left`
  - `sidebar_last_tab_right`
- 选择固定默认页时，设置立即作用于已打开的侧栏。
- 新连接自动打开侧栏时，固定默认页覆盖“上次打开”。
- 选择“上次打开”时，保留最近使用的标签页。
- 标签页被隐藏、移动到另一侧或功能不可用时，现有校验逻辑选择可用回退，不会渲染空侧栏。

### 3.3 关键文件

- `crates/oryxis-app/src/state/modes.rs`
- `crates/oryxis-app/src/boot/load.rs`
- `crates/oryxis-app/src/sidebar_regions.rs`
- `crates/oryxis-app/src/dispatch_settings/terminal_prefs.rs`

### 3.4 手工验收矩阵

1. 设置为“上次打开”，分别在左右侧栏选择不同标签页，退出并重开，确认各自恢复。
2. 设置固定默认页为“代码片段”，当前停在“文件”，建立连接后应打开“代码片段”。
3. 修改固定默认页时，已经打开的侧栏应立即切换。
4. 把默认页移动到另一侧或禁用相应功能，确认不会出现空白侧栏。

## 4. 功能三：标记文件驱动的便携数据模式

提交：`5728bd2d`

### 4.1 启用方法

在 `oryxis.exe` 同目录创建：

```text
oryxis.portable
```

之后 Oryxis 自有数据从用户主目录切换到程序目录：

```text
便携目录/
├─ oryxis.exe
├─ oryxis.portable
└─ .oryxis/
   ├─ vault.db
   ├─ bin/
   ├─ plugins/
   ├─ fonts/
   ├─ sync-git/
   └─ 其他 Oryxis 自有数据
```

### 4.2 路径优先级

`crates/oryxis-core/src/paths.rs` 的解析顺序：

```text
非空 ORYXIS_HOME > 最近祖先目录中的 oryxis.portable > 操作系统用户目录
```

祖先查找很重要：`.oryxis/bin/` 或 `.oryxis/plugins/...` 内的辅助程序也能找到便携根目录，不会在插件目录里再创建一层错误的 `.oryxis`。

### 4.3 不会被搬到程序目录的内容

便携模式只接管 Oryxis 自有数据，不强制改变用户选择或操作系统管理的路径，例如：

- `~/.ssh/config` 和外部 SSH 私钥文件；
- 下载目录；
- 自定义会话日志目录；
- AWS 配置、Xauthority 等外部配置；
- Windows Credential Manager 中的 Windows Hello 凭据。

因此把 U 盘插到另一台电脑时，`vault.db` 会跟随，但 Windows Hello 注册不会跟随。首次需要输入主密码，并在新机器/新 Windows 用户下重新启用 Hello。

### 4.4 保险库与便携包安全

- 设置主密码后，敏感字段使用由 Argon2id 派生密钥保护的 ChaCha20-Poly1305 加密。
- 整个 SQLite 文件并非 SQLCipher 全盘加密；主机名、用户名、标签、部分设置等元数据仍可能明文可见。
- 弱主密码仍可被离线猜测。建议使用密码管理器生成的长随机密码，或至少 5～6 个随机词。
- U 盘建议同时使用 BitLocker To Go，以保护未加密元数据和目录中的其他文件。

### 4.5 私人便携包与公开发行包必须分开

当前本地 `target/portable/.oryxis/` 包含用户自己的保险库副本，因此：

> `target/oryxis-portable-windows-x86_64.zip` 是私人随身包，禁止上传到公开 GitHub Release、网盘公开链接或发送给其他人。

公开发行时应制作干净包：

```text
oryxis.exe
oryxis.portable
便携版说明.txt
```

公开包不要包含现有 `.oryxis/vault.db`。程序首次启动时会自行创建空数据目录。

## 5. 功能四：Windows 便携版任务栏图标

提交：`fab5d986`

### 5.1 原问题

EXE 内已经正确嵌入 Oryxis 图标，窗口内部也能显示 Logo，但任务栏按钮显示 Windows 通用应用图标。

### 5.2 根因

窗口通过 `PKEY_AppUserModel_ID` 绑定了 `io.oryxis.Oryxis`，但未在设置 ID 前提供对应的重启命令、显示名和图标资源。安装版可以通过开始菜单快捷方式补齐身份；便携版没有该快捷方式，Explorer 因而回退到通用图标。

### 5.3 修复

`crates/oryxis-app/src/jumplist.rs` 在设置 AUMID 前依次写入：

- `PKEY_AppUserModel_RelaunchCommand`：当前运行的 `oryxis.exe`；
- `PKEY_AppUserModel_RelaunchDisplayNameResource`：`Oryxis`；
- `PKEY_AppUserModel_RelaunchIconResource`：当前 EXE 中资源 ID 1；
- 最后才写 `PKEY_AppUserModel_ID`，触发任务栏刷新。

路径来自 `std::env::current_exe()`，所以安装版、开发版和 U 盘路径都不会被写死。

### 5.4 验证

- `cargo check -p oryxis-app --locked`：通过。
- Windows release 构建：通过。
- 使用 `ExtractAssociatedIcon` 从最终便携 EXE 提取到正确的 Oryxis 图标。
- 最终任务栏显示仍需用户启动程序做 UI 验收；维护代理不要擅自启动 GUI。

## 6. 功能五：文件侧栏传输增强与管理员拖拽上传

提交：与本节文档位于同一提交；可使用 `git log -1 -- docs/UPSTREAM_CUSTOMIZATIONS.zh-CN.md` 查询实际 SHA。

### 6.1 用户可见行为

- 文件侧栏工具栏提供明确的上传按钮，不需要依赖隐藏入口。
- 可以从 Windows 资源管理器把一个或多个文件直接拖入当前文件侧栏，上传目标是侧栏当前显示的远端目录。
- 可以拖入文件夹；程序递归遍历本地目录并在远端保留相对目录结构。
- 上传使用文件侧栏自己的传输队列和进度条，并沿用现有取消能力，不会把进度错误显示在终端区域。
- 选中远端文件后可点击下载按钮并选择本地保存目录；下载不再固定落入预设目录。
- Oryxis 以管理员身份运行时，也可以接收来自普通权限 Windows 资源管理器的文件和文件夹拖放。

### 6.2 侧栏路由与传输约束

文件拖放首先进入现有 `SftpMessage::SftpFileDropped` 路径，再根据当前可见界面决定归属。不能破坏以下规则：

1. 只有当前屏幕上可见的文件侧栏才能认领拖放，不能把文件静默上传到后台标签页。
2. 文件侧栏的远端当前目录优先于终端的 OSC 7 工作目录；用户看到哪个目录，就上传到哪个目录。
3. 侧栏只认领当前活动/聚焦 pane 的文件浏览器，避免拆分终端时上传到另一 pane。
4. 正在上传或下载时，第二次拖放不能覆盖当前进度状态。
5. 多文件拖放仍通过原有短暂 debounce 合并为同一批次。
6. 文件夹展开失败、路径不可读或 SFTP 操作失败必须显示错误提示，不能静默跳过整个批次。
7. 本地路径和文件名都视为不可信输入；只能作为 SFTP 传输源，不得拼接为终端命令执行。

核心路由位于：

- `crates/oryxis-app/src/dispatch_terminal/drop.rs`：识别可见文件侧栏，把拖放直接送入侧栏上传队列，并检查侧栏传输占用状态。
- `crates/oryxis-app/src/dispatch_sidebar_files/transfer.rs`：递归展开本地文件夹、构造上传项目、启动传输及错误提示。
- `crates/oryxis-app/src/views/sidebar_files.rs`：上传按钮、选中文件后的下载按钮、进度和取消界面。

### 6.3 管理员模式为何需要单独实现

Windows 的 UIPI 会阻止普通权限进程向高完整性窗口发送大多数窗口消息。Oryxis 正常情况下由 winit 注册为 OLE `IDropTarget`；当 Oryxis 提权而资源管理器仍是普通权限时，这条 OLE 拖放路径不可用，鼠标通常显示禁止标记。

当前实现只在确认进程已经提权后，为主窗口启用兼容路径：

1. 使用进程令牌的 `TokenElevation` 判断当前是否管理员运行。
2. 撤销 winit 为该窗口注册的 OLE 拖放目标，避免 Explorer 继续优先选择一条必然被 UIPI 阻断的路径。
3. 对当前 HWND 使用 `ChangeWindowMessageFilterEx`，仅放行 Shell 拖放需要的 `WM_DROPFILES`、`WM_COPYDATA` 和 `WM_COPYGLOBALDATA (0x0049)`。
4. 调用 `DragAcceptFiles` 注册经典 Shell 文件拖放。
5. Win32 subclass 收到 `WM_DROPFILES` 后使用 `DragQueryFileW` 提取路径，并始终调用 `DragFinish` 释放系统资源。
6. 路径先写入线程安全队列，再由现有 Windows heartbeat 转换回 `SftpFileDropped`；之后与普通权限拖放共用完全相同的侧栏路由、批处理和进度逻辑。

普通权限运行时不启用以上兼容路径，也不撤销 winit 的 OLE 目标，避免同一次拖放被重复处理。窗口 subclass 只有在管理员兼容开关生效后才解析 `WM_DROPFILES`，不会把普通窗口收到的任意消息误当作 `HDROP`。

相关文件：

- `crates/oryxis-app/src/tray.rs`：提权检测、每窗口 UIPI 消息过滤、经典 Shell 拖放注册、`HDROP` 解析及队列。
- `crates/oryxis-app/src/dispatch_tray.rs`：在 heartbeat 中清空队列并重新进入统一拖放消息路径。
- `crates/oryxis-app/Cargo.toml`：启用 `windows-sys` 的 `Win32_System_Ole` feature，以便只在管理员兼容路径撤销 OLE 目标。

对应的 Microsoft 官方 API 说明：

- [`ChangeWindowMessageFilterEx`](https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-changewindowmessagefilterex)：按窗口修改 UIPI 消息过滤器。
- [`DragAcceptFiles`](https://learn.microsoft.com/zh-cn/windows/win32/api/shellapi/nf-shellapi-dragacceptfiles) 与 [`WM_DROPFILES`](https://learn.microsoft.com/zh-cn/windows/win32/shell/wm-dropfiles)：注册并接收经典 Shell 文件拖放。
- [`RevokeDragDrop`](https://learn.microsoft.com/zh-cn/windows/win32/api/ole2/nf-ole2-revokedragdrop)：撤销窗口的 OLE 拖放目标注册。

### 6.4 Windows 安全边界

- 消息过滤使用 `ChangeWindowMessageFilterEx` 绑定单个 Oryxis HWND，不修改整个进程或系统的全局过滤器。
- 只在确认当前进程已经提权后放行三类 Shell 拖放消息；普通权限进程不扩大消息面。
- 跨完整性级别拖入的所有路径都必须视为低权限发送方提供的不可信数据。
- 此兼容层只接收文件路径，不提供任意 IPC、命令执行或权限提升能力。
- 未来若上游 winit 原生支持跨完整性级别拖放，应优先移除本地 `RevokeDragDrop`/`WM_DROPFILES` 兼容层，避免同时维护两套目标。

### 6.5 验证

已完成的自动验证：

- `cargo check -p oryxis-app --locked`：通过。
- `cargo-clippy clippy -p oryxis-app --all-targets --locked -- -D warnings`：通过。
- `dispatch_terminal::drop::tests` 定向测试：1 项通过。
- Windows release 构建：通过；只有第 8.3 节记录的既有 `.rsrc` 非致命提示。
- 最终 release EXE 与便携目录 EXE 哈希一致。

需要用户分别在普通权限和管理员权限下完成 UI 验收：

1. 打开 SSH 连接及文件侧栏，把单个文件拖入当前远端目录，确认出现进度并成功上传。
2. 一次拖入多个文件，确认属于同一批次且每个文件都上传。
3. 拖入含多级子目录的文件夹，确认远端目录结构和内容完整。
4. 传输期间尝试再次拖放并测试取消，确认当前进度不会被覆盖。
5. 选中远端文件，点击下载按钮，选择新的本地目录并确认文件落在该目录。
6. 右键“以管理员身份运行” Oryxis，再从普通权限 Explorer 重复文件与文件夹拖入；这是自动化测试无法覆盖的 UIPI/UAC 实机路径。

## 7. 保险库启动解锁语义

“锁定保险库按钮行为”只控制用户手动按下锁定按钮时的动作：

- 每次询问；
- 休眠：锁定保险库但保留会话；
- 锁定保险库：关闭会话并完整锁定。

它不控制下次启动是否自动解锁。只要设置了主密码，程序退出时就会清除内存中的解密密钥；下次启动必须使用主密码或 Windows Hello/PIN 重新解锁。不要把这一行为当成设置失效，也不要在没有明确产品设计和安全提示的情况下改成无提示自动解锁。

## 8. Windows 本机构建环境

### 8.1 工具链

- Rust：`stable-x86_64-pc-windows-gnu`
- Rust 真正可执行文件目录：
  `C:\Users\Rulio\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin`
- MinGW-w64：`D:\WorkBuddy\toolchains\gcc\mingw64\bin`
- 必须设置：`CARGO_INCREMENTAL=0`

`C:\Users\Rulio\.cargo\bin\cargo-fmt.exe` 当前是 0 字节坏垫片，会报 Win32 error 193。需要直接调用工具链里的 `rustfmt.exe`，不要通过 `cargo fmt`。

### 8.2 推荐命令

```powershell
$toolchain = 'C:\Users\Rulio\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin'
$env:PATH = 'D:\WorkBuddy\toolchains\gcc\mingw64\bin;' + $toolchain + ';' + $env:PATH
$env:CARGO_INCREMENTAL = '0'

& "$toolchain\cargo.exe" check --workspace --all-targets --locked
& "$toolchain\cargo.exe" test -p oryxis-core paths::tests --locked
& "$toolchain\cargo.exe" test -p oryxis-vault --test oryxis_home --locked
& "$toolchain\cargo.exe" test -p oryxis-ssh sk:: --locked
& "$toolchain\cargo.exe" build --release -p oryxis-app --locked
```

只格式化修改过的 Rust 文件：

```powershell
& "$toolchain\rustfmt.exe" --edition 2024 path\to\changed.rs
```

### 8.3 已知非致命构建提示

GNU linker 会报告：

```text
.rsrc merge failure: multiple non-default manifests
```

当前不会阻止 release 生成，EXE 图标资源也已确认存在。未来若调整 Windows manifest、`winresource` 或 `tray-icon` 的 common-controls-v6 feature，应重新调查该提示，不能直接假定永久无害。

## 9. 与官方上游同步的标准流程

### 9.1 首次配置官方 remote

当前本地只有指向 Fork 的 `origin`。第一次同步前添加官方 remote：

```powershell
git remote add upstream https://github.com/wilsonglasser/oryxis.git
git remote -v
git fetch upstream --prune
```

如果已经存在 `upstream`，不要重复添加，只执行 fetch。

### 9.2 同步前检查

```powershell
git status --short --branch
git log --oneline --decorate -10
git fetch origin --prune
git fetch upstream --prune
```

要求：

1. 当前修改已经提交或安全备份。
2. `.workbuddy-ai/` 属于本地交接资料，不应误加入公开源码提交。
3. `target/portable/.oryxis/` 含私人数据，绝不能进入 Git。
4. 记录当前 HEAD 和产物哈希，便于回滚。

### 9.3 推荐：在备份分支上 rebase

二次开发目前只有少量逻辑清晰的提交，推荐保持线性历史：

```powershell
git switch feature/native-fido2-windows
git branch backup/native-fido2-windows-before-upstream-YYYYMMDD
git rebase upstream/main
```

每解决一个冲突：

```powershell
git add -- <已解决文件>
git rebase --continue
```

放弃本次同步：

```powershell
git rebase --abort
```

验证全部通过后才更新 Fork：

```powershell
git push --force-with-lease origin feature/native-fido2-windows
```

只能使用 `--force-with-lease`，不要使用裸 `--force`。如果分支已有多人协作、不允许改写历史，则改用：

```powershell
git merge upstream/main
git push origin feature/native-fido2-windows
```

### 9.4 高概率冲突区域

- `crates/oryxis-ssh/src/engine/auth.rs`：上游 SSH 认证重构与 FIDO2 分派。
- `crates/oryxis-core/src/models/connection.rs`：认证枚举新增变体。
- `crates/oryxis-vault/src/keygen/`：密钥解析和默认磁盘扫描。
- `crates/oryxis-app/src/views/host_panel/auth.rs`：认证 UI。
- `crates/oryxis-app/src/sidebar_regions.rs` 与 `state/modes.rs`：侧栏模型。
- `crates/oryxis-core/src/paths.rs`：所有数据目录解析。
- `crates/oryxis-app/src/jumplist.rs`：Windows AUMID/JumpList/图标。
- `crates/oryxis-app/src/dispatch_terminal/drop.rs` 与 `dispatch_sidebar_files/transfer.rs`：上游拖放/SFTP 传输路由调整。
- `crates/oryxis-app/src/tray.rs` 与 `dispatch_tray.rs`：Win32 subclass、管理员拖放和 heartbeat 队列。
- `Cargo.lock` 与 Windows feature 列表。

解决冲突时不要只追求“能编译”。必须重新确认本文第 2.4 节的协议不变量、侧栏优先级、路径优先级、AUMID 属性设置顺序，以及第 6.2～6.4 节的拖放路由和安全边界。

### 9.5 上游同步后的验收顺序

1. `git diff --check`。
2. `cargo check --workspace --all-targets --locked`。
3. FIDO2 单元测试和 `sk_acceptance` 普通/管理员双路径。
4. 侧栏四项手工矩阵。
5. 无 marker 启动时仍使用用户目录；有 marker 时使用程序旁 `.oryxis/`。
6. 嵌套 helper 能找到祖先 marker。
7. release 编译。
8. 检查 EXE 内图标并由用户验证任务栏图标。
9. 执行第 6.5 节的普通/管理员文件拖放、目录递归、进度、取消和下载位置验收。
10. 重新制作私人便携包时，先确认 Oryxis 进程已退出，再复制数据库。

## 10. 当前构建产物

私人便携目录：

```text
D:\WorkBuddy\oryxis\target\portable
```

私人便携 ZIP：

```text
D:\WorkBuddy\oryxis\target\oryxis-portable-windows-x86_64.zip
```

当前哈希：

| 文件 | SHA-256 |
| --- | --- |
| `target/portable/oryxis.exe` | `5103499D640A7D31C7ABA42DBE550D65E819CCE8FC8EACDE303CCD9E6D305380` |
| `target/oryxis-portable-windows-x86_64.zip` | `CAB2847B3E6E75476A78E94481FDEEE7908282A0D1BBF5FA1D06F93C624C5B58` |

ZIP 校验状态：包含 `oryxis.exe`、`oryxis.portable` 和 `.oryxis/vault.db`，不包含 `.oryxis/runtime/` 临时目录。

## 11. 回滚与故障定位

按功能独立回滚时，优先 revert 对应提交，而不是手工删除零散代码：

```powershell
git revert fab5d986   # 任务栏图标
git revert 5728bd2d   # 便携数据目录
git revert a58dc63e   # 侧栏持久化
git revert 3e16de22   # 原生 FIDO2（大提交，需完整回归）
```

文件侧栏传输增强与管理员拖放和本文件位于同一提交。需要独立回滚时，先用 `git log -1 -- docs/UPSTREAM_CUSTOMIZATIONS.zh-CN.md` 定位实际 SHA，再审查该提交的完整 diff；不要用范围过大的 `git restore`，以免连同用户文档或其他未提交内容一起丢失。

在执行 revert 前先确认这些提交是否已经被后续上游同步改写或合并；如果 SHA 已变化，应按提交信息和实际 diff 定位。

故障定位原则：

- FIDO2：先用 `sk_acceptance` 区分“硬件传输/签名错误”和“SSH 认证/UI 错误”。
- 侧栏：检查 `sidebar_default_tab` 与两个 `sidebar_last_tab_*` 的优先级。
- 便携模式：检查 marker 是否与主 EXE 同级，以及 helper 的祖先链是否能找到它。
- 图标：先用 `ExtractAssociatedIcon` 验证 EXE 资源，再检查窗口的 AUMID relaunch 属性。
- 侧栏传输：先确认可见侧栏是否认领拖放，再检查 `SidebarFilesUploadPicked`、传输占用状态和远端当前目录。
- 管理员拖放：先确认进程确实提权并出现“enabled elevated Explorer file-drop compatibility”日志，再检查每窗口消息过滤、`WM_DROPFILES` 队列和 heartbeat drain。
- 保险库：不要把正常的启动解锁提示误判为故障。
