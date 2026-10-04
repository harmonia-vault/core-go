# Windows 标准 SCM 候选 v9 验证记录

本记录对应实验性源码，不是发布或生产可用声明。使用合成普通账号、隔离 VM；没有上传机器 SID、账号密码、私有路径、二进制、运行时 vault 或测试服务器数据。

## 改动与来源

v9 仅改变三个文件：`windowsaccount/config_windows.go`、`metadata_path.go`、`metadata_path_test.go`。祖先目录通过已依赖的 `x/sys/windows.NtCreateFile` 明确请求 `READ_CONTROL | FILE_READ_ATTRIBUTES`（0x20080），仅打开既有规范本地 DOS 路径。保持 owner/DACL、类型、reparse、加密属性、句柄持有和叶文件正文校验；不扩 ACL、账号组或服务权限。

标准 SCM 前置候选此前尚未公开，因此本分支同时收录已审的必要服务、安装、IPC、CLI 和逐键恢复实现。基于公开 `2aa0c48fbe2fdbfa5348e37d02c8ff69733a6b98` 整合，保留其后续恢复/DAG 功能和通知重试。唯一合并冲突为 Windows provider 字段块：同时保留 `notifyPending` 与 `reconcileTracked`。默认候选门槛继续关闭；不使用旧 Task Scheduler、S4U、token 复制或手动 profile 加载路径。

## 原 v9 实际证据（复用，不重复运行）

- 原源码清单 SHA256：`a37c4f04611aea99616bce4632d050c29bf2e710b97a5d0e27c60b27e3af0f15`。
- 原 Windows ARM64/CGO0 CLI SHA256：`8ebf0bf3c785d5aef2ad6cba96dedf973e7380e1ae015ecc50d720a8e652ad5e`。
- 路径合同测试：**PASS**，1.946022 秒；Windows vet：**PASS**，3.83843 秒；CLI 交叉编译：**PASS**，3.082093 秒。
- VM 一次性升级与启动步骤 01–06：**PASS**。标准 SCM 启动 7.609004 秒；读取 Running/Automatic、目标 SID、Session 0、固定映像和 profile hive 5.366293 秒。收据 pending 为空；没有修改 ACL 或身份。
- 上述实际意图/结果清单 SHA256：`fbb71629407713046a1d7df5e9a82f39f5f96fb984bb6199f3f59a1ddb34e5de`。
- v8 启动：**FAIL**，1066 / 0x48212005。OVERLAPPED 已存在仍失败，因此不把隐式 SYNCHRONIZE 单独认定为已证根因。
- 普通账号 DPAPI、槽绑定、服务身份和安装 ACL 的既有独立测试沿用原记录；不重跑整个矩阵。

## 整合边界

原 VM 使用上述 v9 固定二进制。本分支整合了较新公共主线，不能把原 VM 结果宣称为整合后全部代码的原生验证。新增整合检查仅验证恢复原值与通知重试的组合，并编译 Windows ARM64 候选；两项指定 Windows provider 测试 **PASS**（42.013 秒，含首次缓存编译），整合版 Windows ARM64/CGO0 候选编译 **PASS**（57.674 秒）。没有重跑原生矩阵；整合二进制尚未安装到 VM。

该次 VM 已有交互登录。无人登录重启与完整凭据入网 **UNRUN**。CGO0 不含原生 SPAKE2；真实 PAKE、设备 Boot/Pull、完整停服/恢复/卸载和 P7 均未完成。不能以服务 Running 代替这些结果。

API 依据：[NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)、[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)。读取 owner/DACL 需要 READ_CONTROL，仅属性权限不足。
