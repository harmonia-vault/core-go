# Harmonia CLI

Harmonia 的命令行客户端，把手机授权的环境变量同步到电脑或运行环境，支持选择环境、调整优先级、本机覆盖和显式共享写入。

配合 [手机端](https://github.com/harmonia-vault/mobile)与 [自托管服务](https://github.com/harmonia-vault/server)使用。

## 使用前准备

准备好当前系统的可运行 CLI、HTTPS 服务地址，以及已初始化的可信手机。配对需要包含原生配对支持的客户端版本。

以下示例适用于 macOS 和 Linux 的当前用户模式。开机后台服务与 Windows 的使用方法见本页对应说明。

## 连接账号与配对

为当前用户选择一个私有状态目录。目录使用绝对路径，父目录应存在，路径中不要包含符号链接。登录与配对时，使用该目录的后台进程应处于停止状态。

```sh
LOCAL_DIR="$HOME/.harmonia"

harmonia login --local-directory "$LOCAL_DIR" \
  --server https://vault.example.com --email you@example.com

harmonia pair --local-directory "$LOCAL_DIR" \
  --approver "手机上的管理设备ID"
```

密码在终端提示中输入。将 CLI 显示的短码填入手机，核对环境、权限和期限后批准。配对结果未确定时按原操作继续，不要重复创建授权。

使用恢复后的管理手机时，按该手机的配对方式选择证书版本：恢复来源用 `--certificate-version 4`，连续恢复来源用 `--certificate-version 5`。

## 启动同步

```sh
harmonia daemon --local-directory "$LOCAL_DIR"
```

保持该进程运行，在另一个终端设置相同的 `LOCAL_DIR`，再执行日常命令。安装系统服务后，由服务负责运行后台进程。

```sh
harmonia status --local-directory "$LOCAL_DIR"
harmonia activate --local-directory "$LOCAL_DIR" --environment "环境ID" --priority 10
harmonia exec --local-directory "$LOCAL_DIR" -- your-command
```

`exec` 将当前有效变量提供给新启动的程序。已有进程不会被外部强制修改环境。

## 日常命令

| 命令 | 用途 |
| --- | --- |
| `activate` / `deactivate` | 启用或停用指定环境 |
| `priority` | 设置环境优先级，数值越大越优先 |
| `override-set` / `override-remove` | 设置或移除本机覆盖值 |
| `put` / `delete` | 修改共享变量，需要在线且具有写权限 |
| `pause` / `resume` | 暂停或恢复普通同步 |
| `export` | 显式输出当前有效变量，请避免将输出写入公共日志 |
| `logout` | 退出本机账号并恢复被接管的变量 |

变量值通过标准输入传入：

```sh
harmonia put --local-directory "$LOCAL_DIR" \
  --environment "环境ID" --name API_TOKEN --value-stdin < value.txt

harmonia override-set --local-directory "$LOCAL_DIR" \
  --environment "环境ID" --name API_TOKEN --value-stdin < local-value.txt

harmonia override-remove --local-directory "$LOCAL_DIR" \
  --environment "环境ID" --name API_TOKEN
```

请保护保存变量值的文件，并在不再需要时妥善处理。共享写入结果不明时，使用 CLI 返回的原请求 ID：

```sh
harmonia write-retry --local-directory "$LOCAL_DIR" --request-id "原请求ID"
```

## 导入已有变量

先列出当前 CLI 进程继承的变量名，再明确选择要导入的名称：

```sh
harmonia import-preview --current-env
harmonia import --local-directory "$LOCAL_DIR" \
  --environment "环境ID" --current-env --select API_TOKEN,API_URL
```

预览只输出名称；导入只读取选中的值，需要在线且具有写权限。一次最多选择 16 个变量、合计 64 KiB。各项分别提交，可能部分成功；结果不明时继续原请求。

## 开机后台服务

Linux 和 macOS 可以使用配套安装工具运行后台服务。准备好对应平台的原生 CLI、程序 SHA256 和目标用户信息；安装工具使用管理员权限，日常登录与配对由目标用户执行。

### Linux

需要使用 systemd。以下用户名、UID、路径和摘要均须替换为实际值：

```sh
sudo harmonia-linux-installer plan --user example --uid 10001 \
  --binary-source /path/to/harmonia --binary-sha256 "程序SHA256"
sudo harmonia-linux-installer install --user example --uid 10001 \
  --binary-source /path/to/harmonia --binary-sha256 "程序SHA256"
```

安装后服务保持停止。以目标用户使用 `/usr/local/lib/harmonia/<UID>/harmonia` 完成登录和配对；`--local-directory` 指定 `/var/lib/harmonia/<UID>`，`--local-user` 指定该 UID。之后启动服务：

```sh
sudo harmonia-linux-installer start --user example --uid 10001
```

卸载使用 `sudo harmonia-linux-installer uninstall --user example --uid 10001`。私有 CA 在计划和安装时同时通过 `--ca-source` 与 `--ca-sha256` 指定。

### macOS

需要核对目标用户名、UID 和主 GID。程序使用管理员保护的绝对路径；安装工具只处理新安装，不覆盖已有安装：

```sh
sudo harmonia-macos-service install --user example --uid 10001 --gid 20 \
  --binary /path/to/harmonia --sha256 "程序SHA256"
```

安装后服务保持禁启动。以目标用户使用 `/usr/local/lib/harmonia/<UID>/harmonia` 完成登录和配对；`--local-directory` 指定 `/Library/Application Support/Harmonia/<UID>`，`--local-user` 指定该 UID。之后启动服务：

```sh
sudo harmonia-macos-service start --user example --uid 10001 --gid 20
```

停止或卸载时，将命令中的 `start` 分别替换为 `stop` 或 `uninstall`。私有 CA 在安装时通过 `--ca-file` 指定。

停止服务保留配置；卸载会处理本机退出和托管变量恢复。已接入的终端在后续正常刷新时恢复原值，不影响无关变量。遇到身份、文件归属或清理错误时应先核对现场，不直接覆盖安装或删除状态目录。磁盘未解锁时服务无法启动。

## Windows 使用

先完成对应服务的安装，取得管理员保护的配置文件。用实际路径替换示例：

```powershell
harmonia login --windows-config "C:\Harmonia\config.json" --server https://vault.example.com --email you@example.com
harmonia pair --windows-config "C:\Harmonia\config.json" --approver "管理手机设备ID"
harmonia status --windows-config "C:\Harmonia\config.json"
```

Windows 命令不混用 `--local-directory` 或自定义 SID。配套配置需绑定本地 SAM 用户、同步服务、profile 服务及程序路径，并由管理员保护；域账号、Microsoft/Entra 账号和漫游 profile 不属于此用法。仓库中的隔离实验工具不是通用安装器。

使用私有 CA 的服务可通过 `--ca-file` 指定证书；Windows 的 CA 在本机后台服务启动时配置。

## 使用须知

本机覆盖值不会上传。停用所有来源或退出后，客户端恢复首次接管的原值；无关变量保持不变。暂停普通同步也不会延长授权期限。

当前为实验性软件，请先使用非生产数据。

## 许可证

[MIT](LICENSE)
