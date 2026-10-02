import sys
if sys.flags.optimize: raise SystemExit("测试脚本禁止关闭断言")
import os,pathlib,subprocess,pwd,grp,json
assert os.geteuid()==0 and pathlib.Path('/opt/orbstack-guest').exists()
assert pathlib.Path('/etc/hostname').read_text().strip().startswith('harmonia-boot-test-')
units=['harmonia-real-device.service','harmonia-synthetic-server.service']
for name in units:
 p=pathlib.Path('/etc/systemd/system')/name
 assert p.is_file() and 'isolated' in p.read_text() and 'harmonia' in p.read_text()
for name,uid in [('harmonia_boot_device',30001),('harmonia_boot_server',30002)]:assert pwd.getpwnam(name).pw_uid==uid
for name in units:
 subprocess.run(['systemctl','disable','--now',name],check=True,stdout=subprocess.DEVNULL)
 (pathlib.Path('/etc/systemd/system')/name).unlink()
subprocess.run(['systemctl','daemon-reload'],check=True)
# 专用用户停止后没有残留进程，才删除本轮创建的身份和数据。
for name,uid in [('harmonia_boot_device',30001),('harmonia_boot_server',30002)]:
 if subprocess.run(['pgrep','-u',str(uid)],stdout=subprocess.DEVNULL).returncode==0:raise RuntimeError('测试UID仍有进程，停止清理')
 subprocess.run(['userdel',name],check=True)
 try:grp.getgrnam(name)
 except KeyError:pass
 else:subprocess.run(['groupdel',name],check=True)
import shutil
for value in ['/var/lib/harmonia/30001','/var/lib/harmonia-test-server','/usr/local/share/harmonia-boot-test','/usr/local/lib/harmonia-boot-test']:
 p=pathlib.Path(value);assert p.is_dir() and not p.is_symlink();shutil.rmtree(p)
for value in ['/tmp/harmonia-native-boot','/tmp/harmonia-native-boot.test','/srv/harmonia-boot-src/acceptance/boot_prepare_test.go','/srv/harmonia-boot-src/server/tests/orbstack-boot-server.ts']:
 p=pathlib.Path(value)
 if p.exists():assert p.is_file() and not p.is_symlink();p.unlink()
for name in ['harmonia-boot-bootstrap.py','harmonia-boot-sources.tar.gz','harmonia-boot-refresh.tar.gz','harmonia-boot-setup.py','harmonia-boot-enable.py','harmonia-boot-probe.py','harmonia-boot-cleanup.py','linux-harmonia-user-10001.service']:
 p=pathlib.Path(pwd.getpwnam('harmonialab').pw_dir)/name
 if p.is_file() and not p.is_symlink():p.unlink()
assert not pathlib.Path('/var/lib/harmonia/30001').exists()
assert not pathlib.Path('/var/lib/harmonia-test-server').exists()
print(json.dumps({'cleanup':'PASS','only_this_run_users_units_keys_sqlite_state_removed':True,'official_toolchain_and_public_source_retained':True,'existing_vms_and_host_untouched':True}))
