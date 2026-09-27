<p align="center"><img src="assets/banner.svg" alt="Codex SSH Helper for Windows" width="100%"></p>

<h1 align="center">Codex SSH 连接助手</h1>
<p align="center">为 Windows 用户简化远端 Linux 的 SSH 配置、Codex 安装与登录引导。</p>
<p align="center"><strong>填写服务器信息 → 核对指纹 → 完成认证 → 连接远端项目</strong></p>
<p align="center"><a href="https://github.com/keeperruner/codex-ssh-helper-windows/releases/tag/v0.2.0"><strong>下载 Windows v0.2.0</strong></a> · <a href="#快速开始">快速开始</a> · <a href="FAQ.md">常见问题</a> · <a href="README.en.md">English</a></p>
<p align="center"><img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0f766e" alt="Windows 10 / 11"> <img src="https://img.shields.io/badge/release-v0.2.0-0f766e" alt="v0.2.0"> <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-334155" alt="MIT license"></a> <img src="https://img.shields.io/badge/community-unofficial-64748b" alt="Unofficial community project"></p>

这是独立社区项目，并非 OpenAI 官方产品。程序帮助准备连接；浏览器授权需要你本人完成，随后在桌面端启用 SSH 连接并打开远端项目。

## 把重复的准备工作交给助手

| 你需要处理的事情 | 助手提供的功能 |
| --- | --- |
| SSH 密钥和 Windows 文件权限 | 按连接创建或复用 Ed25519 密钥，设置文件访问权限 |
| 服务器首次登录 | 核对服务器指纹后，用密码安装公钥 |
| SSH 配置文件 | 写入连接别名，保留其他配置；修改已有配置时备份 |
| 远端没有 Codex | 可选自动安装，并检查登录 shell 的 PATH |
| 无界面服务器认证 | 显示设备代码，在本机浏览器完成授权 |
| 桌面端该填什么 | 在执行进度中显示连接名称、主机名和身份文件路径 |

## 界面预览

<p align="center"><img src="assets/app-preview.png" alt="连接助手初始界面，未输入任何真实服务器信息" width="840"></p>

## 快速开始

1. 打开 [v0.2.0 下载页](https://github.com/keeperruner/codex-ssh-helper-windows/releases/tag/v0.2.0)，下载 `Codex-SSH-Helper-Windows-v0.2.0.exe` 和 `SHA256SUMS.txt`。使用 EXE 不需要单独安装 Python。
2. 在 PowerShell 中运行下方命令，核对结果与校验文件一致。
3. 双击 EXE，在本地页面输入服务器地址、SSH 端口、服务器账号和首次登录密码。建议为连接取名，例如 `my-linux`。
4. 点击配置按钮，通过服务器服务商控制台核对 SHA-256 身份指纹；一致后继续。
5. 按程序显示的本次设备代码完成官方页面授权。保持程序和进度页打开，回到进度页确认结果。
6. 在桌面端 SSH 连接设置中按下表填写，保存并连接，再选择远端项目文件夹。

```powershell
Get-FileHash .\Codex-SSH-Helper-Windows-v0.2.0.exe -Algorithm SHA256
```

### 桌面端“编辑 SSH 连接”怎么填

以下 `my-linux` 是示例连接名称。**请复制程序实际输出的值，不要照抄示例路径。**

| 桌面端字段 | 填写内容 |
| --- | --- |
| 显示名称 | 程序显示的连接名称，例如 `my-linux` |
| 主机名 | 同一个 SSH 别名，例如 `my-linux`；该别名关联程序写入的用户、端口及指纹文件 |
| SSH 端口（可选） | **留空**，使用 SSH 配置中的实际端口，尤其是非 22 端口的服务器 |
| 身份验证方式 | 选择“身份文件” |
| 身份文件路径 | 复制程序显示的完整私钥路径，文件名以 `_ed25519` 结尾 |

私钥通常位于 `%USERPROFILE%\.ssh\my-linux_ed25519`；桌面端应填写程序显示的展开后的完整路径。**不要选择 `.pub` 或 `_known_hosts` 文件。**

## 运行条件与测试范围

- Windows 10/11 64 位，已安装 OpenSSH Client，可运行 `ssh` 和 `ssh-keygen`。
- 提供 SSH 远端连接功能的桌面端版本。
- 远端 Linux 支持 SSH 密码登录、SFTP，具有 `sh` 及 `curl` 或 `wget`，账号有相应写入权限。
- 本机能打开认证页面，远端能访问安装与认证服务。
- 已有用户反馈在另一台 Windows 电脑完成试用；具体系统与网络组合尚未形成完整兼容性矩阵。

当前 EXE 未签名，Windows 可能提示“未知发布者”。请核对下载来源和 SHA-256，不要关闭系统防护。

## 数据保存在哪里

助手没有遥测或集中收集服务。连接时仍会向你指定的服务器传输 SSH 登录信息，并按需访问官方安装与认证服务。

| 数据 | 处理方式 |
| --- | --- |
| 首次登录密码 | 在内存中用于本次 SSH 登录，程序不主动写入文件 |
| 服务器地址、用户名、端口 | 保存在当前用户的 SSH 配置中，进度页也会显示 |
| SSH 私钥 | 保存在当前用户的 `.ssh` 目录；仅公钥写入远端 |
| 服务器指纹 | 保存在该连接的 `_known_hosts` 文件中 |
| 设备代码和日志 | 在本地进度页显示；分享截图前请打码 |
| 远端 Codex 凭据 | 由远端 Codex 管理；可选文件存储模式默认关闭 |

本地界面监听 `127.0.0.1`，操作接口使用随机会话令牌。详见 [隐私说明](PRIVACY.md)、[安全说明](SECURITY.md) 和 [发布检查](RELEASE_CHECK.md)。

## 常见问题

- [Host key verification failed：主机身份验证失败](FAQ.md#host-key-verification-failed)
- [安装完成但找不到 codex](FAQ.md#path)
- [认证页面卡住或浏览器成功但远端未登录](FAQ.md#authentication)
- [换电脑后重新配置](FAQ.md#new-pc)

## 从源码运行与构建

当前 Windows 工作流使用 Python 3.10。

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python app.py
```

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m PyInstaller --noconfirm --clean CodexRemoteSetup.spec
```

[Windows 检查工作流](https://github.com/keeperruner/codex-ssh-helper-windows/actions/workflows/windows.yml) 包含测试和 EXE 构建；运行结果以 Actions 页面为准。

## 反馈与参与

如果这个工具帮你省了时间，欢迎点一个 Star。也欢迎提交成功试用记录或改进建议；使用和下载不需要 Star。

欢迎通过 [Issues](https://github.com/keeperruner/codex-ssh-helper-windows/issues) 反馈问题。请附上版本、系统、操作步骤和打码后的报错；不要上传密码、私钥、设备代码或 `auth.json`。提交代码前请阅读 [贡献指南](CONTRIBUTING.md)。

[MIT License](LICENSE) · [更新记录](CHANGELOG.md) · [第三方声明](THIRD_PARTY_NOTICES.md)
