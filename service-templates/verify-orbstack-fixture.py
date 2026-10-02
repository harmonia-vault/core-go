#!/usr/bin/env python3
"""只在已获授权的 OrbStack Linux 隔离机运行合成账号验收。

不重启机器，不连接外部 SSH，不导入真实环境；仅清理本次新建的资源。
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import pwd
import grp
import re
import secrets
import selectors
import shutil
import socket
import subprocess
import tempfile
import time


class CheckFailed(Exception):
    pass


def run(args, *, input=None, check=True, timeout=20):
    result = subprocess.run(args, input=input, text=True, capture_output=True,
                            timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if check and result.returncode != 0:
        # 参数中可能包含新建测试钥匙路径；公开报告仅记录静态阶段名。
        raise CheckFailed("子命令执行失败")
    return result


def create(path, text, mode=0o600, owner=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as output:
        output.write(text)
        output.flush()
        os.fsync(output.fileno())
    if owner:
        os.chown(path, *owner)


class SSHSession:
    def __init__(self, port, user, private_key, known_hosts, rcfile):
        self.number = 0
        self.buffer = b""
        self.process = subprocess.Popen([
            "ssh", "-F", "/dev/null", "-tt", "-p", str(port), "-i", str(private_key),
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=5",
            f"{user}@127.0.0.1", f"/bin/bash --noprofile --rcfile {rcfile} -i"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin", "HOME": str(private_key.parent), "LC_ALL": "C", "TERM": "dumb"})
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.command(":", timeout=10)

    def command(self, command, timeout=5):
        self.number += 1
        number = self.number
        # 记录合成断言的退出状态，不枚举或输出 SSH 会话的环境。
        self.process.stdin.write((command + f"; printf '\\036{number}:%d\\037' \"$?\"\n").encode())
        self.process.stdin.flush()
        pattern = re.compile(rb"\x1e" + str(number).encode() + rb":([0-9]+)\x1f")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = pattern.search(self.buffer)
            if found:
                self.buffer = self.buffer[found.end():]
                if int(found.group(1)) != 0:
                    raise CheckFailed("SSH 合成环境断言失败")
                return
            for key, _ in self.selector.select(0.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    raise CheckFailed("SSH 会话意外结束")
                self.buffer += chunk
        raise CheckFailed("SSH 合成环境断言超时")

    def refresh(self):
        # 空命令后的真实 PROMPT_COMMAND 刷新；下条命令读取刷新后的值。
        self.command(":")

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b"exit\n")
                self.process.stdin.flush()
                self.process.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
        self.selector.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-temporary-fixture-account", action="store_true")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--localkeys-test", required=True)
    parser.add_argument("--platform-test")
    args = parser.parse_args()
    if not args.allow_temporary_fixture_account or os.geteuid() != 0 or not Path("/opt/orbstack-guest").is_dir():
        parser.error("仅允许显式授权的 OrbStack 临时账号验收；必须在隔离机以 root 运行")
    for name in ("systemctl", "runuser", "useradd", "userdel", "ssh", "sshd", "ssh-keygen", "openssl", "setfacl"):
        if not shutil.which(name):
            parser.error(f"缺少官方测试工具：{name}")
    if not Path(args.binary).is_file() or not Path(args.localkeys_test).is_file():
        parser.error("需要预先构建的 Linux 本机架构 CLI 与 localkeys 测试二进制")

    tag = secrets.token_hex(5)
    unit = f"harmonia-fixture-{tag}.service"
    unit_path = Path("/run/systemd/system") / unit
    binaries = Path("/usr/local/lib") / f"harmonia-fixture-{tag}"
    account_names = []
    account_dirs = []
    sshd = None
    shell = None
    state_parent = Path("/var/lib/harmonia")
    created_parent = False
    created_binaries = False
    created_unit = False
    created_sshd_dir = False
    scratch = Path(tempfile.mkdtemp(prefix="harmonia-vm-fixture-"))
    stage = "初始化"
    report = {
        "schema": "harmonia/linux-vm-fixture-acceptance/v1",
        "environment": {"machine": "OrbStack Ubuntu", "architecture": run(["uname", "-m"]).stdout.strip(),
                        "virtualization": run(["systemd-detect-virt"], check=False).stdout.strip(),
                        "systemd": run(["systemctl", "--version"]).stdout.splitlines()[0]},
        "checks": {},
        "gates": ["未重启整机：真实 boot/start-before-login 尚未验收", "合成 fixture，不证明真实设备授权或云同步",
                  "Windows DPAPI/ACL/hive/Session 0 与 macOS LaunchDaemon 原生服务未跑", "VM 未安装 zsh，sh 无可移植自动 prompt hook"],
    }
    cleanup_errors = []
    try:
        if state_parent.exists():
            meta = state_parent.lstat()
            if state_parent.is_symlink() or meta.st_uid != 0 or meta.st_mode & 0o022:
                raise CheckFailed("拒绝使用非安全既有 VM 测试父目录")
        else:
            state_parent.mkdir(mode=0o755)
            created_parent = True
        binaries.mkdir(mode=0o755)
        created_binaries = True
        binary = binaries / "harmonia"
        test_binary = binaries / "localkeys.test"
        shutil.copyfile(args.binary, binary)
        shutil.copyfile(args.localkeys_test, test_binary)
        binary.chmod(0o755)
        test_binary.chmod(0o755)
        platform_test = None
        if args.platform_test:
            platform_test = binaries / "platform.test"
            shutil.copyfile(args.platform_test, platform_test)
            platform_test.chmod(0o755)

        stage = "临时账号创建"
        for suffix in ("a", "b"):
            username = f"hmf_{tag}{suffix}"
            try:
                pwd.getpwnam(username)
                raise CheckFailed("临时账号冲突")
            except KeyError:
                pass
            uid = None
            for _ in range(128):
                candidate = 30000 + secrets.randbelow(30000)
                try:
                    pwd.getpwuid(candidate)
                    continue
                except KeyError:
                    pass
                try:
                    grp.getgrgid(candidate)
                    continue
                except KeyError:
                    uid = candidate
                    break
            if uid is None:
                raise CheckFailed("找不到未占用的测试 UID")
            state = state_parent / str(uid)
            if state.exists() or state.is_symlink():
                raise CheckFailed("临时状态目录冲突")
            run(["useradd", "--uid", str(uid), "--user-group", "--no-create-home", "--home-dir", str(state / "home"), "--shell", "/bin/bash", username])
            account_names.append(username)
            account = pwd.getpwnam(username)
            state.mkdir(mode=0o700)
            account_dirs.append(state)
            os.chown(state, account.pw_uid, account.pw_gid)
            (state / "home").mkdir(mode=0o700)
            os.chown(state / "home", account.pw_uid, account.pw_gid)
        user, other = account_names
        account = pwd.getpwnam(user)
        state = account_dirs[0]
        owner = (account.pw_uid, account.pw_gid)
        home = state / "home"
        ipc = state / "ipc"
        fragment = state / "environment.sh"

        def as_user(arguments, *, check=True, timeout=20, who=user):
            target = pwd.getpwnam(who)
            return run(["runuser", "-u", who, "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"HOME={target.pw_dir}", "LC_ALL=C", *map(str, arguments)], check=check, timeout=timeout)

        def cli(command, *extra, check=True, who=user):
            return as_user([binary, command, "--fixture", "--ipc-dir", ipc, *extra], check=check, who=who)

        stage = "加密 Store 本机账号测试"
        store_tests = as_user([test_binary, "-test.v", "-test.count=1"], timeout=40)
        if "SKIP" in store_tests.stdout or not store_tests.stdout.rstrip().endswith("PASS"):
            raise CheckFailed("加密 Store 存在跳过或未通过测试")
        report["checks"]["localkeys_native_nonroot_with_acl"] = "通过"
        if platform_test:
            stage = "平台本机账号测试"
            platform_tests = as_user([platform_test, "-test.v", "-test.count=1"], timeout=40)
            skips = [line for line in platform_tests.stdout.splitlines() if "--- SKIP:" in line]
            if not platform_tests.stdout.rstrip().endswith("PASS") or any("/zsh " not in line for line in skips):
                raise CheckFailed("平台测试存在失败或预期外跳过")
            report["checks"]["platform_native_nonroot"] = "通过；zsh 缺失跳过" if skips else "通过"

        stage = "系统服务非交互启动"
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=35)
        snapshot = {"accountId": "synthetic-vm-account", "accountGeneration": 1, "sequence": 1,
                    "environments": {
                        "base": {"id": "base", "keyVersion": 1, "grantGeneration": 1, "role": "RW", "values": {"TEST_TOKEN": "synthetic-low", "TEST_ADDED": "synthetic-added"}},
                        "high": {"id": "high", "keyVersion": 1, "grantGeneration": 1, "role": "RW", "expiresAt": expires.isoformat().replace("+00:00", "Z"), "values": {"TEST_TOKEN": "synthetic-high"}}}}
        snapshot_path = state / "snapshot.json"
        create(snapshot_path, json.dumps(snapshot), owner=owner)
        as_user([binary, "fixture-load", "--fixture", "--state", state / "state.json", "--input", snapshot_path])
        create(unit_path, f"""[Unit]
Description=Harmonia 隔离合成账号验收
After=network.target
[Service]
Type=simple
User={user}
UMask=0077
ExecStart={binary} daemon --fixture --state {state}/state.json --local-user {account.pw_uid} --ipc-dir {ipc} --platform-fragment {fragment} --interval 100ms
Restart=on-failure
RestartSec=1s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={state}
WorkingDirectory={state}
""", mode=0o644)
        created_unit = True
        run(["systemd-analyze", "verify", str(unit_path)])
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "start", unit])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if cli("status", check=False).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise CheckFailed("系统服务 IPC 未就绪")
        pid = int(run(["systemctl", "show", unit, "--property=MainPID", "--value"]).stdout.strip())
        if pid < 1 or int(run(["ps", "-o", "uid=", "-p", str(pid)]).stdout.strip()) != account.pw_uid:
            raise CheckFailed("服务实际 UID 不符")
        protections = run(["systemctl", "show", unit, "--property=NoNewPrivileges,ProtectHome,ProtectSystem,CapabilityBoundingSet,AmbientCapabilities"]).stdout
        report["service_protection_fields"] = dict(line.split("=", 1) for line in protections.splitlines())
        fields = report["service_protection_fields"]
        if fields.get("CapabilityBoundingSet") != "" or fields.get("AmbientCapabilities") != "":
            raise CheckFailed("服务实际 capability 非空")
        report["checks"]["systemd_noninteractive_start_uid_and_no_capabilities"] = "通过"
        if fields.get("NoNewPrivileges") != "yes" or fields.get("ProtectHome") != "yes" or fields.get("ProtectSystem") != "strict":
            report["checks"]["systemd_sandbox_effective"] = "未验证：OrbStack LXC 全局 drop-in 关闭沙盒"
            report["gates"].append("systemd 沙盒被隔离机全局 zzz-lxc-service.conf 覆盖，未修改此配置；需完整 Linux VM 再验")
        else:
            report["checks"]["systemd_sandbox_effective"] = "通过"
        cli("activate", "--environment", "base", "--priority", "1")
        cli("activate", "--environment", "high", "--priority", "10")
        if cli("status", check=False, who=other).returncode == 0:
            raise CheckFailed("第二 UID 能够访问 IPC")
        if as_user(["test", "-r", state / "state.json"], who=other, check=False).returncode == 0:
            raise CheckFailed("第二 UID 能够读取状态")
        report["checks"]["current_user_cli_and_second_uid_denial"] = "通过"

        stage = "合成密钥回环 SSH 建立"
        # SSH 公钥登录需要未锁定账号；仅生成不可登录的随机测试密码哈希，关闭密码认证。
        password_hash = run(["openssl", "passwd", "-6", "-stdin"], input=secrets.token_urlsafe(48) + "\n").stdout.strip()
        run(["usermod", "--password", password_hash, user])
        host_key = scratch / "ssh-host"
        client_key = scratch / "ssh-client"
        for key in (host_key, client_key):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "harmonia-synthetic-vm-test", "-f", str(key)])
        sshdir = home / ".ssh"
        sshdir.mkdir(mode=0o700)
        os.chown(sshdir, *owner)
        create(sshdir / "authorized_keys", client_key.with_suffix(".pub").read_text(), owner=owner)
        hook = as_user([binary, "shell-hook", "--shell", "bash", "--platform-fragment", fragment]).stdout
        rcfile = home / "synthetic-bashrc"
        create(rcfile, "stty -echo\nexport TEST_TOKEN='shell-original'\nexport TEST_UNRELATED='synthetic-unrelated'\nPS1='hm-test> '\n" + hook, owner=owner)
        reserve = socket.socket()
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        reserve.close()
        ssh_config = scratch / "sshd_config"
        create(ssh_config, f"""Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {scratch}/sshd.pid
AuthorizedKeysFile {sshdir}/authorized_keys
AllowUsers {user}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
UsePAM no
StrictModes yes
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog no
LogLevel ERROR
""")
        if not Path("/run/sshd").exists():
            Path("/run/sshd").mkdir(mode=0o755)
            created_sshd_dir = True
        run(["/usr/sbin/sshd", "-t", "-f", str(ssh_config)])
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(ssh_config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        shell = SSHSession(port, user, client_key, scratch / "known_hosts", rcfile)
        shell.command('[ "$TEST_TOKEN" = synthetic-high ] && [ "$TEST_ADDED" = synthetic-added ] && [ "$TEST_UNRELATED" = synthetic-unrelated ]')
        report["checks"]["ssh_bash_merge_and_priority"] = "通过"

        stage = "CLI 本机 override 与运行中纠正"
        cli("override-set", "--environment", "high", "--name", "TEST_TOKEN", "--value", "synthetic-local-override")
        shell.refresh()
        shell.command('[ "$TEST_TOKEN" = synthetic-local-override ]')
        shell.command("export TEST_TOKEN='synthetic-external'; export TEST_UNRELATED='synthetic-external-unrelated'")
        shell.command('[ "$TEST_TOKEN" = synthetic-local-override ] && [ "$TEST_UNRELATED" = synthetic-external-unrelated ]')
        report["checks"]["local_override_and_prompt_correction_preserve_unrelated"] = "通过"

        stage = "暂停与服务重启"
        cli("pause")
        shell.refresh()
        shell.command("export TEST_TOKEN='synthetic-paused-external'")
        shell.command('[ "$TEST_TOKEN" = synthetic-paused-external ]')
        run(["systemctl", "restart", unit])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            status = cli("status", check=False)
            if status.returncode == 0 and json.loads(status.stdout)["paused"]:
                break
            time.sleep(0.1)
        else:
            raise CheckFailed("重启后暂停状态未恢复")
        shell.refresh()
        shell.command('[ "$TEST_TOKEN" = synthetic-paused-external ]')
        cli("resume")
        shell.refresh()
        shell.command('[ "$TEST_TOKEN" = synthetic-local-override ]')
        report["checks"]["pause_restart_and_resume_convergence"] = "通过"

        stage = "离线到期与暂停安全回退"
        cli("pause")
        # 没有真实网络同步；服务器授予的合成期限由运行中 daemon 本地识别。
        while datetime.datetime.now(datetime.timezone.utc) <= expires + datetime.timedelta(seconds=1):
            time.sleep(0.2)
        shell.refresh()
        shell.command('[ "$TEST_TOKEN" = synthetic-low ] && [ "$TEST_ADDED" = synthetic-added ]')
        cli("export")
        report["checks"]["offline_expiry_during_pause_fallback"] = "通过"

        stage = "退出与逐 key 原值恢复"
        cli("logout")
        shell.refresh()
        shell.command('[ "$TEST_TOKEN" = shell-original ] && [ "${TEST_ADDED+x}" != x ] && [ "$TEST_UNRELATED" = synthetic-external-unrelated ]')
        report["checks"]["logout_keywise_restore_preserve_unrelated"] = "通过"
        report["result"] = "通过"
    except (CheckFailed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as error:
        report["result"] = "失败"
        report["failure"] = {"stage": stage, "kind": type(error).__name__, "detail": str(error) if isinstance(error, CheckFailed) else "隔离测试执行失败"}
    finally:
        if shell:
            try:
                shell.close()
            except Exception:
                cleanup_errors.append("SSH 测试会话")
        if sshd:
            sshd.terminate()
            try:
                sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait()
        if created_unit and unit_path.exists():
            if run(["systemctl", "stop", unit], check=False).returncode != 0:
                cleanup_errors.append("临时系统服务停止")
            unit_path.unlink()
            run(["systemctl", "daemon-reload"], check=False)
            run(["systemctl", "reset-failed", unit], check=False)
        for username in reversed(account_names):
            if run(["userdel", username], check=False).returncode != 0:
                cleanup_errors.append("临时账号删除")
            try:
                grp.getgrnam(username)
                if run(["groupdel", username], check=False).returncode != 0:
                    cleanup_errors.append("临时用户组删除")
            except KeyError:
                pass
        for directory in reversed(account_dirs):
            if directory.exists():
                shutil.rmtree(directory)
        if created_binaries and binaries.exists():
            shutil.rmtree(binaries)
        shutil.rmtree(scratch)
        if created_parent:
            try:
                state_parent.rmdir()
            except OSError:
                cleanup_errors.append("本次新建状态父目录非空，已保留")
        if created_sshd_dir:
            try:
                Path("/run/sshd").rmdir()
            except OSError:
                cleanup_errors.append("本次新建 SSH 运行目录非空，已保留")
        report["cleanup"] = "通过" if not cleanup_errors else cleanup_errors
        if cleanup_errors:
            report["result"] = "失败"
        report["default_ssh"] = {
            "service": run(["systemctl", "is-active", "ssh.service"], check=False).stdout.strip(),
            "socket": run(["systemctl", "is-active", "ssh.socket"], check=False).stdout.strip(),
            "socket_enabled": run(["systemctl", "is-enabled", "ssh.socket"], check=False).stdout.strip()}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["result"] == "通过" else 1


if __name__ == "__main__":
    raise SystemExit(main())
