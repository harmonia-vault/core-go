> [!WARNING]
> 项目正处于开发阶段，仅供测试使用。

# Harmonia CLI

Harmonia（和弦）是一个自托管的环境变量同步工具：在手机上集中管理环境变量，按设备授权，同步到电脑和运行环境中使用。

本仓库是 Harmonia 的命令行客户端，运行在电脑或服务器上，负责同步本机获得授权的环境变量，并将其注入到启动的程序中。需配合 [手机端](https://github.com/harmonia-vault/mobile)与[服务端](https://github.com/harmonia-vault/server)使用。

## 功能

- 同步手机授权给本机的环境
- 同时启用多个环境，按优先级合并同名变量
- 设置仅在本机生效的覆盖值，不上传到其它设备
- 导入终端中已有的环境变量
- 支持 macOS、Linux 与 Windows，可安装为系统服务

## 准备

- 可访问的 Harmonia 服务地址
- 已完成账号初始化的手机端
- 对应系统的 `harmonia` 可执行文件

以下示例适用于 macOS 和 Linux。先指定本机数据目录（须为绝对路径）：

```sh
LOCAL_DIR="$HOME/.harmonia"
```

## 登录与配对

```sh
harmonia login --local-directory "$LOCAL_DIR" \
  --server https://vault.example.com --email you@example.com

harmonia pair --local-directory "$LOCAL_DIR" --approver "手机设备ID"
```

- 手机设备 ID 可在手机端的设备页面查看。
- 执行 `pair` 后，在手机上输入 CLI 显示的短码，选择授权的环境、权限和有效期并批准。
- 手机曾通过“恢复访问”恢复时，`pair` 需额外指定 `--certificate-version 4`。

## 使用

启动后台同步进程，并保持运行：

```sh
harmonia daemon --local-directory "$LOCAL_DIR"
```

在另一个终端中启用环境，并通过 `exec` 启动程序：

```sh
harmonia activate --local-directory "$LOCAL_DIR" --environment "环境ID" --priority 10
harmonia exec --local-directory "$LOCAL_DIR" -- your-command
```

启用多个环境时，同名变量以优先级数值较大者为准。已运行的程序不会获得新变量，需重新启动。

## 命令

以下命令均需指定 `--local-directory "$LOCAL_DIR"`。

| 命令 | 说明 |
| --- | --- |
| `status` | 查看同步状态和已启用的环境 |
| `activate` / `deactivate` | 启用或停用环境 |
| `priority` | 调整环境优先级，数值越大越优先 |
| `put` / `delete` | 修改共享变量，同步到所有授权设备 |
| `override-set` / `override-remove` | 设置或移除本机覆盖值 |
| `import-preview` / `import` | 导入当前终端中已有的变量 |
| `pause` / `resume` | 暂停或恢复同步 |
| `export` | 输出当前生效的变量 |
| `logout` | 退出账号，并恢复本机原有的变量 |

变量值通过标准输入传入，避免留在命令历史中：

```sh
harmonia put --local-directory "$LOCAL_DIR" \
  --environment "环境ID" --name API_TOKEN --value-stdin < value.txt
```

导入已有变量时，先预览变量名，再选择需要导入的项：

```sh
harmonia import-preview --current-env
harmonia import --local-directory "$LOCAL_DIR" \
  --environment "环境ID" --current-env --select API_TOKEN,API_URL
```

## 系统服务

可将后台同步安装为系统服务，开机后自动运行。示例中的用户名、UID、GID、路径和 SHA256 需替换为实际值。

**Linux**（systemd）：

```sh
sudo harmonia-linux-installer install --user example --uid 10001 \
  --binary-source /path/to/harmonia --binary-sha256 "程序SHA256"
```

**macOS**：

```sh
sudo harmonia-macos-service install --user example --uid 10001 --gid 20 \
  --binary /path/to/harmonia --sha256 "程序SHA256"
```

安装完成后，以目标用户身份使用 `/usr/local/lib/harmonia/<UID>/harmonia` 登录和配对，并改用服务的数据目录，同时指定 `--local-user <UID>`：

| 系统 | 数据目录 |
| --- | --- |
| Linux | `/var/lib/harmonia/<UID>` |
| macOS | `/Library/Application Support/Harmonia/<UID>` |

之后将安装命令中的 `install` 替换为 `start` 启动服务，替换为 `uninstall` 卸载服务；macOS 还可以用 `stop` 停止服务。

## Windows

Windows 使用 `--windows-config` 指定服务安装时生成的配置文件，替代 `--local-directory`：

```powershell
harmonia login --windows-config "C:\Harmonia\config.json" --server https://vault.example.com --email you@example.com
harmonia pair --windows-config "C:\Harmonia\config.json" --approver "手机设备ID"
```

目前仅支持本地 Windows 账号。

## 注意事项

- `export` 以明文输出变量，请勿写入日志或公开分享。

## 许可证

[MIT](LICENSE)
