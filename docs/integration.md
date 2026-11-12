# GUI 接管与系统保存

## 运行

按 Explorer 架构选择 dist/x64 或 dist/x86，只需复制其中的 CredentialUI.exe。内嵌桥接与 EXE 自动成套准备到可写临时目录，不再交付独立 DLL / Host / Injector。双击或无参数运行 CredentialUI.exe 自动启用后台接管，也可运行可选的 start.cmd；界面预览须显式使用 --preview：

~~~bat
CredentialUI.exe
CredentialUI.exe --log "X:\Logs\credential.log"
CredentialUI.exe --status
CredentialUI.exe --stop
CredentialUI.exe --preview
CredentialUI.exe --attach 1234
CredentialUI.exe --detach 1234
~~~

管理器按当前会话、当前架构单实例运行，使用退出码表示状态，无额外控制台窗口。重复双击保持现有管理器运行，新进程返回 183，不做启停切换。--run 已移除，使用时返回 87（ERROR_INVALID_PARAMETER）。默认不创建日志文件；需要诊断时追加 `--log "日志绝对路径"`。--status 返回 0 表示运行，显式开启日志时，status 的 code 为安装进程数、detail 为失败进程数；1168 表示未找到运行实例。--stop 等待撤销完成，失败返回非零。

无参数启动（包括仅使用 --log）和 --attach PID 在操作前检查 WinPE 环境。先用 GetSystemWindowsDirectoryW 确认系统 Windows 目录位于 `X:\`，再读取 `HKLM\SYSTEM\CurrentControlSet\Control` 下的 REG_SZ 值 SystemStartOptions，检查是否包含 MININT，匹配不区分大小写。任一条件不满足、注册表值不存在或读取失败均视为非 WinPE，弹出“此功能仅支持 WindowsPE 环境”，返回 50（ERROR_NOT_SUPPORTED）；拒绝发生在日志文件准备、组件释放和挂接之前。非法 PID 仍优先返回参数错误 87。--preview、--status、--stop、--detach 和内部 --ipc 不受环境限制，便于开发验收、查询和撤销。

启动后自动发现同会话、系统 Windows 目录中与自身架构一致的 Explorer，每轮扫描间隔 500ms，安装失败隔 5 秒重试。进程以 PID + 创建时间确认身份。注入需要有访问目标进程的权限，失败在开启日志时记录，不弹 UAC。x86 在 32 位 Windows 中处理 x86 Explorer；在 64 位 Windows 的 WOW64 环境中不会接管 x64 Explorer。跨架构手动挂接 / 撤销返回 193（ERROR_BAD_EXE_FORMAT），PID 必须是非零 DWORD 范围内的十进制数字。手动挂接不提供自动发现和自动重试；手动挂接的目标应对应使用 --detach 撤销。扫描和远程安装需要时间，刚创建的 Explorer 在安装完成前访问 UNC，仍可能先出现原系统提示；不要把常驻扫描描述为无竞争窗口的进程启动拦截。

CredentialUI.exe --preview 是供开发和验收使用的外观预览，不启用接管、不认证、不保存，确定按钮不向网络提交。实际认证界面由桥接以 --ipc 启动。

--stop 不卸载仍可能被回调引用的 DLL，也不关闭用户的 Explorer；已恢复入口的 DLL 在对应进程退出时释放。停止会取消在途 GUI；管理器异常退出会使在途请求取消，后续请求使用原实现。重新启动管理器可恢复安装。不要同时运行旧控制台演示与本组合。

## 请求与结果

include/credential_ui.h 定义 CredentialUiRequest、CredentialUiResult、credential_ui_prompt，保留 credential_ui_run 和状态接口。窗口呈现和原生 EDIT/按钮行为仍由原 UI 实现；接口不会调用 WNet 建立第二条连接。

请求包含父 HWND、父进程句柄、取消事件、期限、目标、标题/说明、错误、用户名提示及保存选项。返回 ERROR_SUCCESS / ERROR_CANCELLED / ERROR_TIMEOUT，并在成功时包含用户名、密码与保存选择。调用者拥有返回缓冲区，并负责用完清零。用户名不能为空；密码允许为空；缓冲区各为 512 个 UTF-16 单元，最多输入 511 单元，超限在界面上拒绝而非截断提交。

IPC v2 是两条匿名管道，每方向单写者、单消息；固定 8 字节对齐、固定宽度 owner/request_id，当前请求 2992 字节、响应 2080 字节，两者均小于新管道的 4096 字节容量。采用消息 magic、版本、长度、请求号、已知标志及 NUL 终止校验。旧控制台 v1 不兼容；GUI、桥接须成套部署。

命令行只传继承的句柄数值。STARTUPINFOEX 只允许继承两条管道子端及取消事件，用户名和密码不进入命令行、环境或诊断。GUI 后台线程读取请求，再在界面线程操作控件；父进程、父窗口和取消事件通过 UI 定时器监视。桥接从排队开始使用统一 10 分钟期限，等待过程轮询进程、取消和管道状态，不在没有可读字节时阻塞读取。每个响应小于空管道容量，只有一次写入。

取消、关闭、超时和停止不回退；GUI 启动失败、崩溃、坏协议、无法表示的身份、未知标志及非 Negotiate 提示调用原系统实现。故障回退每请求最多一次。初次拒绝匿名访问不直接显示密码错误；存在输入身份的重试才显示系统错误并尝试预填用户名，密码不预填。

## 保存语义

裸用户名用于实时认证时保留显式空域名；DOMAIN\user 拆分成域和用户名；UPN 保持原字符串。需要域账户时请明确输入 DOMAIN\user 或 UPN。返回对象由 SSPI 构造，原调用方按 SSPI 契约释放。

SSPI 的保存职责与单纯 pfSave 布尔值不同。当前目标 ntlanman 的 flags=0 路径不会仅因 pfSave=TRUE 自动替自定义提供方新增凭据。本组合按下列顺序适配：

1. 用户未勾选：不保留保存副本、不新增持久凭据。
2. 用户勾选且未设置 SSPIPFC_CREDPROV_DO_NOT_SAVE：保存一个短期、同进程加密的 SSPI 身份副本，并关联线程、目标和期限。
3. 在同一线程、同一目标的 NetUseAdd 返回成功后，调用 SspiPrepareForCredWrite 生成凭据，再调用系统 CredWriteW，持久性为 CRED_PERSIST_LOCAL_MACHINE。
4. 实时认证使用裸用户名时，保存账户限定为 目标主机\用户名，避免本次 PE 中无域用户名保存后出现 1312。显式域账户及 UPN 不改写。这个规则对应裸用户名按远端本地账户解释；域账户务必明确填写域。
5. 失败、过期、停止或进程退出不提交保存。未使用副本定时过期清理；Blob 用后清零。若调用方设置 DO_NOT_SAVE，只返回保存选择，由调用方负责保存；NO_CHECKBOX 时界面保留布局并禁用保存框。

没有自建磁盘凭据库，不改 Credential Provider / COM / MiniNT 配置。凭据属于当前登录身份的系统 Credential Manager；PE 重启后可丢失。写入失败不会伪装为网络认证失败，但在开启日志时会记录 save-after-connect 的非零错误；GUI 在网络完成前已返回，不会宣称“保存成功”。写入回执和后续连接才是保存验收证据。

部署 EXE 和 `%TEMP%\CredentialUI` 缓存目录应由与 Explorer 相同的受信身份控制写权限。运行组件每次准备时与内嵌 DLL / 当前 EXE 的完整内容比较；内容哈希和完整比较用于版本与损坏检查，不是文件签名或对抗同身份恶意写入的边界。仅使用当前 Windows API 的令牌/桌面行为，不改变凭据所属身份。

## 诊断与撤销

默认运行不创建日志文件，也不会向 EXE 同目录或组件缓存目录自动写入 credential.log。只有指定 `--log "日志绝对路径"` 才启用文件诊断，选项可放在动作前后，支持包含空格及中文的路径。路径必须包含盘符根目录（如 `X:\Logs\credential.log`）或完整 UNC 文件路径；不接受相对路径、仅根目录路径、设备路径、缺少值或重复的 --log，参数错误返回 87。当前路径长度限制为少于 MAX_PATH（260）个 UTF-16 单元。父目录须预先存在；指定文件无法打开时返回对应 Windows 错误码，不回退至其他路径。

管理器和由该管理器挂接的桥接共用启动时通过 --log 指定的文件，路径通过远程调用参数显式传递。--attach / --detach 的 --log 配置本次操作及目标桥接；不带 --log 的重新挂接或手动撤销会关闭该桥接的文件诊断。--status 的 --log 仅控制本次查询记录，--stop 的 --log 仅控制停止命令自身；已运行管理器及其撤销过程继续沿用启动时的配置。预览 / IPC 入口可接受 --log 并检查文件可写，但自身没有诊断事件。文件以 UTF-8 追加，不自动轮转或删除；后续写入失败不影响认证与撤销。

日志仅包含事件、进程 ID、数值结果和计数，不包含用户名、密码或凭据 Blob。result 的 detail 为保存选择；save-after-connect 的 code 为保存/连接结果、detail 为 NetUseAdd 返回码。system-save 为观察到的 ntlanman 原生写入结果。host-attach / host-detach 的 code 为安装/撤销错误。

未启用日志时，状态仍可由 --status 的退出码查询。注入超时可能留下待运行远程调用及其参数内存，因此本版不承诺所有不响应进程都能即时撤销；不强制终止远程线程，不卸载在用 DLL。

## 范围

原四组件版本实际验证 x64 WinPE 10.0.22631.7654，见原测试报告。后续两组件记录见 binary-consolidation-2026-11-06.md，当前单 EXE 的本机与 x64 WinPE 验收见 single-exe-2026-11-06.md。本轮实机只取消真实网络提示，未提交真实账户或新增网络凭据。x86 原生 32 位 WinPE 的 Explorer 挂接、网络认证和保存尚未实测，不能将 WOW64 下的离线回归视为该项通过。保存提交关联当前 ntlanman 的 NetUseAdd 路径；跨版本、DFS、WebDAV、智能卡/证书、其它认证包、低完整性、完整 Windows 的多令牌/安全桌面场景不宣称已通过。不同 Explorer 可独立提示，同进程串行排队；长时间压力、句柄/内存压力及跨补丁回归留待专门验证。

已有系统凭据和 SMB 会话可能让访问不再提示。不得据此推断钩子失效，也不得用活跃会话证明凭据已持久保存。测试报告记录了会话重建和新 Explorer 的独立对照。

## 统一入口与升级

`src/main.c` 统一分发命令；管理与注入代码保留在 bridge/host.c、bridge/injector.c 作为内部函数，均静态链接进 CredentialUI.exe。每架构 dist 与 CMake install 只交付一个 EXE，测试程序留在 build 目录。

启用 / 手动挂接时，`src/credential_bundle.c` 读取内嵌 RCDATA 201 中的桥接 DLL，以当前 EXE 全文加 DLL 内容计算 SHA-256，使用 `%TEMP%\CredentialUI\x64-哈希\` 或 `x86-哈希\` 缓存。它先在同目录独占创建临时文件、写入并刷新，再无覆盖地发布；并发准备可复用同一份完整文件。缓存中已有文件必须逐字节匹配，损坏返回 23（ERROR_CRC），不会加载或覆盖疑似在用组件；输出路径过长、临时目录不可写、资源缺失等均返回非零。

缓存内有 CredentialUIBridge.dll 和 CredentialUI.exe 的运行副本；桥接仍通过同目录 EXE --ipc 启动独立 GUI，协议与凭据返回路径不变。部署目录不释放 DLL；默认关闭文件日志；显式启用时管理器与桥接写到 --log 指定的绝对路径。预览 / IPC / 状态 / 停止不主动释放组件；手动 detach 为定位同版 DLL 会检查并准备缓存。TEMP/TMP 应在运行与手动操作期间保持一致。

停止不删除缓存，避免 Explorer 仍持有 DLL 或存在回调；WinPE 重启后由其临时盘生命周期处理。需要清理时，先停止管理器并退出所有加载该版 DLL 的进程，再删除明确对应的版本目录。缓存根目录或版本目录为重解析点时拒绝使用。这里只约束缓存自身，调用方仍需保证临时目录的上级路径受信。

本次会话控制对象名加入 x64 / x86，允许两个架构分别管理自己的目标。由旧四组件版升级时，先用旧 CredentialUIHost.exe --stop 停止旧管理器，关闭已加载旧 DLL 的 Explorer 后再替换文件；旧版与新版不要同时运行。新版 --stop 只控制新版同架构管理器。停止后仍可能被引用的 DLL 不立即卸载，沿用原生命周期约定。
