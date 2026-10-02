# 显式扫描与选中导入

`import-preview --current-env` 是用户主动执行的只读命令，输出排序后的 JSON 变量名数组，不打开账号状态、不联系后台或云端、不逐项调用取值。它只枚举当前 CLI 进程继承的环境，不读取其它用户/进程、注册表、shell 配置或系统服务环境。Go 的 `os.Environ` 本身会返回含值的进程 entry；实现只拆取名称并丢弃 entry 引用，不声称操作系统没有读取值。预览不会输出、持久化或上传这些值。

```sh
# 只显示当前 CLI 可获取的合法名称，无论是否已入网都不会联网。
harmonia import-preview --current-env
# 预览选中名称仍只输出名字，不输出对应值。
harmonia import-preview --current-env --select TOKEN,URL
# 用户明确选中后才取值，交给受保护后台在线加密签名提交。
harmonia import --local-directory "$LOCAL_DIR" --environment environment-id \
  --current-env --select TOKEN,URL --request-id explicit-import-id
```

扫描不会导入任何未选中的变量。选择名单先整体验证，再只对已选项调用取值；无选择、未知名称、重复选择、内部 `__HARMONIA_` 大小写变体、非法名称均拒绝。只接受协议支持的 ASCII 可移植名称，枚举最多 4096 项；导入最多 16 项，每值及合计最多 64 KiB，拒绝无效 UTF-8 和 NUL，保留空值、换行和其它合法字节。列名后已经消失的选中项也会拒绝，不默认为空值。名称预览不会因为变量值无效而读取它；只有实际选中导入时才检查值。

POSIX 的大小写不同名称保持独立。Windows 对合法 ASCII 名称按大小写无关语义匹配选择，保留来源的实际拼写；`Path,path` 等重复选择或来源中同名不同拼写的歧义会拒绝。Windows 的隐藏驱动器项等不符合协议名称的项不会成为候选。Windows 本轮只有注入式语义测试和默认构建验证，不能据此宣称已完成 Windows 原生扫描/服务验收。

`--current-env` 只接受 `import-preview` 和 `import`，与 `--from`、`--import-stdin`、`--value-stdin`、`--value` 等值来源互斥。原来的 `import --import-stdin --select ...` 和显式候选文件预览保持兼容。变量值只在选中后进入 CLI 内存与现有本机 IPC，不放进 argv、输出、日志或候选文件；错误也不回显值。daemon 不扫描进程环境，更不会把用户直接修改的系统环境自动上传。

导入仍要求已入网的受保护后台、在线当前 RW/Admin 授权和未暂停状态。扫描不建立信任、不修改本地权威状态、不乐观更新 provider：先经原来的 `writes-v1` 保存固定签名密文/请求 ID、提交服务器，再通过相同验签拉取流下发。LWW、部分接受、撤销/到期及密封重试语义沿用 [共享写入说明](README.md)。结果不明时用 `write-retry --request-id <原ID>`，不能再次扫描后换值猜测成功；`write-retry` 拒绝 `--current-env`。

本轮测试只使用注入的合成环境提供者，以及 Env 完全由测试指定的独立子进程。覆盖只列名时零取值/零网络、选中项字节保留、未选项不进入 IPC、选择与值上限、Windows 名称规则、原 stdin/文件兼容，以及真实未入网 daemon 的拒绝和零数据序号。测试没有扫描宿主真实环境、导入用户凭据或安装系统服务。在线服务器/暂停/RO 约束继续由已有 Writer 与端到端验收验证；名称扫描测试不能替代这些安全验证。

根任务另跑真实首次初始化→BoringSSL SPAKE2→无登录 session 的正式 daemon/CLI→HTTPS→TS/SQLite 验收，通过 2.787 秒（主项 2.65 秒）。独立 CLI 的 Env 完全为两个合成项，验证名称预览不含值、只选一项、已接受响应丢失后原 ID 重查仍为序号 9、未选项不进入云端/托管配置、暂停拒绝扫描导入；保留原 stdin 选中导入和其它共享写/撤销验收。宿主环境未扫描或修改。
