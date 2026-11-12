# CredentialUI

为 Windows PE 提供可正常显示的网络凭据输入窗口。

## 背景

部分 Windows PE 环境在通过资源管理器访问 SMB 网络共享时，系统凭据窗口会显示成黑框，无法正常输入用户名和密码。

CredentialUI 使用 Win32 / GDI 绘制凭据界面，接管资源管理器中的网络凭据提示，支持输入用户名、密码及选择记住凭据。网络认证仍由原系统流程完成，勾选保存后在认证成功时写入系统凭据管理器。

![凭据输入界面](docs/preview.png)

## 用法

1. 按 Windows PE 架构选择 x64 或 x86 版本，只需复制一个 `CredentialUI.exe`。
2. 双击运行，程序在后台启用接管，此时不会立即弹出凭据窗口。
3. 在资源管理器中访问需要认证的共享，例如 `\\服务器地址\共享名`，出现提示后输入凭据。
4. 需要停止接管时，运行 `CredentialUI.exe --stop`。

重复启动会保持已启用状态。若要随 Windows PE 启动，可将程序加入 Windows PE 的启动配置。

启用接管仅支持系统盘为 `X:`、启动选项包含 `MININT` 的 Windows PE。程序自动处理当前会话中同架构的系统资源管理器；临时目录须可写，运行组件会自动准备到 `%TEMP%\CredentialUI`。

已在 x64 Windows PE 验证接管；x86 已通过本机 WOW64 离线测试，原生 32 位 Windows PE 接管仍待验证。新建资源管理器后立即访问共享，可能先出现系统原提示，可稍后重试。

## 命令行

| 命令                                              | 说明                                               |
| ------------------------------------------------- | -------------------------------------------------- |
| `CredentialUI.exe`                                | 启用后台接管，仅限 WinPE                           |
| `CredentialUI.exe --stop`                         | 停止后台接管，取消正在显示的凭据窗口               |
| `CredentialUI.exe --status`                       | 查询状态：退出码 `0` 表示运行中，`1168` 表示未运行 |
| `CredentialUI.exe --preview`                      | 仅预览界面，可在普通 Windows 中运行，不提交凭据    |
| `CredentialUI.exe --attach PID`                   | 手动挂接指定的同架构进程，仅限 WinPE               |
| `CredentialUI.exe --detach PID`                   | 撤销指定进程的手动挂接                             |
| `CredentialUI.exe --log "X:\Logs\credential.log"` | 启用接管并记录日志，父目录须已存在                 |

`--log` 可与其他命令组合，路径须为绝对路径。默认不生成日志；日志不记录用户名、密码或凭据内容。

常见退出码：`50` 为不满足 WinPE 条件，`87` 为参数错误，`183` 为已有运行实例，`193` 为目标架构不匹配。程序使用退出码反馈状态，不显示控制台输出。

## 构建

需要 Windows、CMake 3.20+，以及 MinGW-w64 GCC 或带 Windows SDK 的 Visual Studio C 工具链。

```powershell
.\scripts\build.ps1 -Architecture x64
.\scripts\build.ps1 -Architecture x86
```

输出分别位于 `dist/x64/CredentialUI.exe` 和 `dist/x86/CredentialUI.exe`。

## 更多说明

- [运行、诊断与保存机制](docs/integration.md)
- [开发说明](docs/development.md)

## 许可证

[MIT License](LICENSE)
