# v7 macOS 输出适配与枚举界限

仅在 v6 冻结之上的独立六文件窄修；v6 manifest SHA256 为 `9e40dc302b22ae649e9d58489430b135365b567f74d845d1a4ef983cf1eae7d2`。v6 的 243 PASS 范围保留，不把本次发现改写成旧矩阵实际失败。未安装、启动、停止或卸载宿主服务；未执行 VM、提交、发布或修改全域控制配置。

## 修改

`commandBounded` 分别保留有界 stdout/stderr，只在进程内使用；超限、取消、读取或等待错误均返回未知。`observeJob` 仅在 exit 113、stdout 无冲突且 stderr 为固定目标 label 的完整官方不存在诊断时返回 absent；其他 label、错误码、非规范诊断或正常输出伴未知 stderr 都闭锁。成功 job 仍按原完整身份/PID/state 校验。print-disabled 的域输出仍仅有界 RAM 投影本 label，不输出或持久化其他配置。

`childrenCreated` 在已持有的可信父 FD 下打开并核原目录 inode，最多读取 128+1 个名字，超过 128 立即返回未知且不检查、删除或修改其中对象；有限集合继续原同 FD 元数据复验与 Close 错误传播。

## 实际结果

| 检查 | 结果与范围 |
| --- | --- |
| 修复前负例 | 两个实际叶负例 FAIL：真实子进程 stderr-only absence 丢失；自己的临时目录 129 项仍被接受。失败日志保留 |
| 定向 `go test -race` | 21 PASS，18 叶用例、8 顶层，0 FAIL / 0 SKIP，4.971 秒 |
| 真实子进程路径 | 9 个场景：正常完整 job、stderr-only absent、未知错误、其他 label、冲突 stdout、stdout/stderr 超限、取消及成功伴未知 stderr |
| 宿主官方只读探针 | 独立不存在合成 label；实际 exit 113、stdout 0 字节、stderr 124 字节；诊断为 Bad request 后接固定 label 不存在信息。修复后正式分流解析 PASS |
| 普通用户临时 FD | 128 项接受、129 项闭锁且原目录未改；继承 exclusive rename 三个原 inode 用例 PASS |
| 两 Mac 包 vet | PASS，0.452 秒 |
| Darwin arm64 CGO=0 构建 | PASS，0.681 秒；5,612,674 字节，SHA256 `466acd837405faf9cd676ce5fd779fd88458cb000c3cd7e1937d5025888ca90e` |

宿主探针只查询一个唯一合成服务名，不读取 print-disabled 数据库或其他服务；只保存长度、摘要和已识别的脱敏诊断。测试子进程输出全部合成，目录全部属于测试临时目录，不使用用户凭据或环境值。构建产物仅本地保留，不公开二进制。

正式 installer root 创建、disable/enable、loaded/noPID、VM 新装/入网/Start/Stop/重启/卸载仍未跑。本轮没有重复 v6 完整矩阵；这组结果不能称整体安装器或 App 生产可用。
