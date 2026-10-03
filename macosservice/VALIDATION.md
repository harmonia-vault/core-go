# macOS 安装器 v6 验证记录

本候选基于公开 core-go `6d8178ae3116e6eb9dc4c1a9197c885c6a7687b1` 与已冻结 v5 精确源码；未修改正式 CLI、provider、daemon、Windows 工作树或 v5 冻结。没有宿主安装、sudo、VM 操作、安装包、Release 或部署。当前不能称生产可用。

## 本轮真实结果

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| 两 Mac 包 `go test -race -count=1` | PASS，4.050 秒 | 243 个测试事件通过；216 个叶用例、73 个顶层，0 FAIL / 0 SKIP |
| 两 Mac 包 `go vet` | PASS，0.372 秒 | 安装协调器与有限命令解析 |
| Darwin arm64、CGO=0 构建 | PASS，0.608 秒 | 5,612,610 字节，未安装或执行服务 |
| 新普通用户 Darwin FD 原语 | PASS，4 个叶用例 | 同父 FD 缺失同步；exclusive rename 保原 inode、结果不明幂等复验、不同目标/阶段 inode 拒绝 |
| 继承 journal 正常进程崩溃 | PASS，10 个子用例 | 新建/替换各 5 个实际 os.Exit(86) 点，临时测试目录，不是断电/VM |
| 正式 launchctl、持久禁启动/重启、root 服务安装卸载 | 未跑 | 后续仅隔离 Mac VM，经源码与 runner 审查后执行 |

构建产物 SHA256：`dca85982eab9f45f435ee7ba05a3582cb266d006fca8931c2a918f91cde66f48`。二进制只保留于本地证据，不纳入公开源码。

## v6 窄边界

合成协调器覆盖未 Start 安装及 Stop 的持久禁启动模型；未知既有 disabled=true/false 冲突；claim、创建意图、rename、完成意图回应不明后普通 Install 恢复精确原 inode；未引用截断 stage 保留；部分普通卸载只清已记录本次 inode，未知 program/state 子项在任何删除前拒绝；部分取消当前缺失 fsync 失败不推进持久下标。

合法 preparing/cleanup-authorized 事务的同身份原 job 重新加载后，正 PID 或稳定 loaded/noPID 通过普通卸载 bootout/drain/owner 锁恢复；不执行冻结状态下的 IPC。starting、不明身份、仅 claim 没有完整创建权属或 owner 锁忙均保留。Start 授权先于 enable；enable 回应不明补偿禁启动；最后 removed-disabled 发布不明保留 journal，最终删除 Close 失败不能成功，永久权属与可信父 FD 缺失同步支持普通重试。

故障模型明确区分 volatile unlink 与已持久删除：unlink 后父 fsync 失败，模拟崩溃可恢复对象；缺失重试父 fsync/Close 失败不得推进 cursor。新建/替换 root 记录仍通过随机 stage 与原子 rename，不能因截断未知 stage 永久堵住固定权威记录。

## 保留失败与限制

删除持久性负例首次 3 FAIL 后修正，定向 5 PASS。草稿首次编译 FAIL 为替换 Stop 时遗漏已有 stateEntries/白名单，已恢复原实现；未安装任何服务。草稿旧故障预期与永久权属的新合同不符，以及晚期未知 job 的模型触发位置不准，原日志保留；按新的明确权属重试与合法 Stop 语义调整，未削弱未知材料检查。新增仅 claim 停服务负例先 FAIL，已增加完整创建权属门槛后 PASS；最后发现 start-authorized 回应不明时 loaded job 仅据运行状态重新 enable 的负例先 FAIL，已窄修为正常停/drain 后重新核成熟本地来源，定向 PASS，再作此处最终两包 race/vet/build；先前 242 PASS 的源码结果保留为历史。另一个负例的 os.IsNotExist 无法透过 errors.Join 属测试谓词问题，改用 errors.Is，原 FAIL 保留。

真实 launchctl 输出解析、启动/停止 PID 排空、loaded/noPID 行为、root 创建/ACL、并行管理员、完整断电与正式 installer VM 旅程未跑。合成 reboot 只是模型，不能作系统重启证据。普通用户实际 FD 原语只证明文件接口，不证明 root 服务生命周期。

用户可修改材料的读取在 state/ipc 原 inode 已冻结为 root 0700 后进行；冻结前只用 O_EVTONLY 元数据及目录接口。程序/CA/收据/创建 stage 的常规文件均由 root 持有且祖先不可由目标修改；本轮未发现用户可替换 FIFO 的阻塞 O_RDONLY 分支。此结论没有通过宿主材料或新大矩阵验证。
