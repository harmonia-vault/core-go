# Windows 原生构建的存储与内存验证

## 结论

2026-10-04 已解决本候选的原生交叉编译阻塞。保持源码、Go1.26.4、固定 BoringSSL/LLVM-mingw、2 GiB 内存上限和禁止交换不变，把本任务工具链工作目录、缓存与编译临时文件从 tmpfs 改为现有磁盘后，含 SPAKE2 的 Windows ARM64/CGO1 CLI 构建通过。

这是构建通过，不是服务配对、设备 Boot/Pull 或 P7 通过。产物仅留在私有测试目录，没有发布安装包、Release 或部署服务。

## 原执行层与原因证据

宿主为 ARM64 macOS；构建在 OrbStack 的 Linux ARM64 LXC 测试机中执行，目标为 Windows ARM64，并未在 Windows 来宾中运行编译器。该容器独立限制为 2 GiB、2 CPU、`memory.swap.max=0`；底层 Linux 显示的可用内存和宿主总内存不能代替容器上限。

原 `/tmp` 是 tmpfs。构建结束后的静态检查中，cgroup `shmem` 为 1,989,500,928 字节（约 1.85 GiB），匿名内存仅约 21 MiB；当前使用已接近 2 GiB。已知任务目录中，原生工具链/源码/中间产物约 1.35 GiB，Go 缓存约 329 MiB。持久保留的内存文件使编译进程缺少余量，降低并发和 Go GC 软目标不能回收这些文件。

原两次失败均停在 Go `runtime` 包的编译进程，输出 `signal: killed`，分别耗时 259.37 秒和 349.018 秒。第二次使用 `-p 1`、`GOMAXPROCS=1`、`GOMEMLIMIT=512MiB`、`GOGC=50`，期间 cgroup `oom_kill` 从 8 升至 10。没有取得对应 PID 的内核日志，不能反推每次终止的完整内核事件；后续对照验证确认了当前存储/内存阻塞的可解决原因，未发现需要更换 Go 版本或密码原语的证据。

## 处理与实际验证

1. 只迁移两个已确定属于本任务的目录到同一容器已有的磁盘文件系统，先复制，再校验全部文件内容、类型、权限和链接；验证后保留原路径链接，再移除原 tmpfs 副本。共核验 17,698 和 4,933 项。没有删除唯一产物或无关文件。
2. `shmem` 降至 200,105,984 字节（约 191 MiB）；迁移期间 OOM kill 没有增加。保留原固定库、编译器与缓存，未下载或重建依赖。
3. 同一源码提交 `b29fad11ed1dee9cd1c745bfb9bfcb2134bb5f2c`、同一组低并发/软内存参数，使用磁盘上的 `TMPDIR`、`GOTMPDIR` 和输出目录。单次构建 **PASS**：111.744 秒、exit 0，编译日志为空，`oom=32`、`oom_kill=10` 前后不变。
4. 产物 21,534,208 字节，SHA256 `171e0accb99a7d3b3c03c714f2cba44341afcff0b58f8f4f0571f3600c2ff30a`；ARM64 PE 与系统 DLL 导入检查 **PASS**。尚未替换已安装服务或运行真实凭据链。

仓库修复让两个 Windows 构建入口遵循标准 `TMPDIR`，不再硬编码大工作目录到 `/tmp` 或将测试输出固定到源码缓存目录。调用示例在 [Windows 原生构建说明](../pairing/WINDOWS_NATIVE.md)。两个入口的 Python 解析与 `--help` 均通过；未因此重建原生库或重跑配对测试矩阵。

## 官方依据及上游检索

- [Linux tmpfs](https://docs.kernel.org/filesystems/tmpfs.html) 说明其文件在内存/交换中保存；[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) 定义 `shmem`、文件占用和 OOM 计数。这与上述实际挂载、限制及计数吻合。
- [Go 命令环境变量](https://pkg.go.dev/cmd/go#hdr-Environment_variables) 明确支持 `GOTMPDIR` 指定编译中间文件目录、`GOCACHE` 指定缓存；[Go GC 指南](https://go.dev/doc/gc-guide) 说明内存目标是软限制，不涵盖所有外部占用。
- 上游 [Go #25808](https://github.com/golang/go/issues/25808) 讨论 tmpfs 构建残留占用内存；[#58106](https://github.com/golang/go/issues/58106) 讨论软内存目标下仍可能发生容器 OOM。这些是相关机制与案例，不是本次 Go1.26.4 编译器缺陷的证明；没有据此升级工具链。
