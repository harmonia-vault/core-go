# Linux 安装器真实 VM 首轮续验

**整轮仍为 FAIL。** Ubuntu ARM64 内核10项测试全部通过，正式空安装/未入网启动拒绝/卸载流程通过；外层精确账号清理阶段返回 `FAILED_EXACT_GROUP_CLEANUP`。不能把分项通过改写成整轮成功。

此次从固定公开 core6d8178 加26候选构建，Go1.26.4、CGO0，来宾保持 `umask077`，内核6.8.0-142-generic。root批准的唯一 SSH 续验实际执行2.113秒；未重启、重建或修改 VM，未进行云端请求。三文件新建mode修复解决上一轮原native4PASS/5FAIL；上一轮原始失败完整保留。

| 实际范围 | 结果 |
| --- | --- |
| 10 native root临时目录/FD/kernel测试 | 10 PASS、0 FAIL、0 SKIP |
| 正式 installer install | installed-disabled complete:true，UID目录700且空，systemd disabled/inactive |
| 正式 installer start 空未入网目录 | 非零退出，固定fault linux_install_state_invalid，无材料/enablelink；未保留helper内部原因，不能称在线授权拒绝 |
| 正式 installer uninstall 与最终幂等cleanup | completed:true，exitCode0/cleanupExitCode0，固定目标资源缺失 |
| 账号/组最终实际查询 | name+UID及groupname+GID均缺失；原30001/30002/两unit公开metadata不变 |
| 外层wrapper | FAIL：FAILED_EXACT_GROUP_CLEANUP |

脚本在 `userdel` 成功后要求同名组仍存在才执行 `groupdel`。最终组name/GID均不存在，和系统一并删除私有主组相容；本轮没有分阶段返回记录，不能确认唯一原因，不再SSH/重跑来追改FAIL。旧root staging与失败日志、新staging、共享parent及固定管理lock保留用于审阅，未声称磁盘完全清空。

真实登录/PAKE后启服、guest完整重启无人登录Boot/Pull、活动SSH shell逐key恢复、停服后有材料离线卸载、真实中断/并发CLI均**UNRUN**。native协调器中的system-manager/helper回应包含fixture注入，不能代替这些产品联合验收，不宣称生产可用。

私有来源对照固定26候选与最新公开eef6713的合并注意：新路径均未被公开占用，386基础文件无改动，GoMod/GoSum和正式enrollment/logout/POSIX合同未变。此对照只是只读，不代表新base已构建或执行。机器结果与原始日志摘要由私有manifest绑定；任何后续harness修正应写新文件，不能覆盖本次已执行脚本或日志。
