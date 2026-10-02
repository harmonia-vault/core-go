#!/bin/sh
# 在临时 fake root 中验证 unit；不执行安装、启动或 ExecStart。
set -eu
if [ "$#" -ne 1 ]; then
  printf '%s\n' '用法：sh service-templates/verify-linux.sh <systemd 样例文件>' >&2
  exit 2
fi
command -v systemd-analyze >/dev/null
fixture=$(mktemp -d /tmp/harmonia-systemd-verify.XXXXXX)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/root/etc/systemd/system" "$fixture/root/usr/local/bin"
cp "$1" "$fixture/root/etc/systemd/system/harmonia-test.service"
printf '#!/bin/sh\nexit 0\n' > "$fixture/root/usr/local/bin/harmonia"
chmod 0700 "$fixture/root/usr/local/bin/harmonia"
for target in network-online multi-user sysinit basic shutdown sockets local-fs; do
  printf '[Unit]\nDescription=合成验证目标\nDefaultDependencies=no\n' > "$fixture/root/etc/systemd/system/$target.target"
done
systemd-analyze --root="$fixture/root" --man=no --generators=no verify harmonia-test.service
