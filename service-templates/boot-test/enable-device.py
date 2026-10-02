import sys
if sys.flags.optimize: raise SystemExit("测试脚本禁止关闭断言")
import os,pathlib,subprocess,json,time
assert os.geteuid()==0 and pathlib.Path('/opt/orbstack-guest').exists()
assert pathlib.Path('/etc/hostname').read_text().strip().startswith('harmonia-boot-test-')
assert not pathlib.Path('/mnt/mac').exists()
base=pathlib.Path('/var/lib/harmonia/30001')
assert (base/'protected/trust.v1.enc').is_file()
assert not (base/'protected/session.v1.enc').exists()
(base/'bootstrap.json').unlink()
unit='''[Unit]
Description=Harmonia real enrolled device isolated boot acceptance
After=network.target harmonia-synthetic-server.service
Requires=harmonia-synthetic-server.service
[Service]
Type=simple
User=harmonia_boot_device
Group=harmonia_boot_device
UMask=0077
WorkingDirectory=/var/lib/harmonia/30001/protected
ExecStart=/usr/local/lib/harmonia-boot-test/harmonia daemon --local-directory /var/lib/harmonia/30001/protected --local-user 30001 --ca-file /usr/local/share/harmonia-boot-test/ca.pem --interval 100ms --sync-interval 1s
Restart=on-failure
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/harmonia/30001/protected
[Install]
WantedBy=multi-user.target
'''
p=pathlib.Path('/etc/systemd/system/harmonia-real-device.service');assert not p.exists();p.write_text(unit);os.chmod(p,0o644)
subprocess.run(['/usr/bin/systemctl','stop','harmonia-synthetic-server.service'],check=True)
maintenance="import {nodeStore} from './src/node-store.ts';const {store,sql}=nodeStore('/var/lib/harmonia-test-server/accounts.sqlite');store.transaction('synthetic-account',a=>{a.sessions=[];});sql.close();"
subprocess.run(['/usr/sbin/runuser','-u','harmonia_boot_server','--','/usr/bin/env','-i','PATH=/opt/harmonia-test-tools/node-v24.16.0-linux-arm64/bin:/usr/bin:/bin','/opt/harmonia-test-tools/node-v24.16.0-linux-arm64/bin/node','--import','tsx','--input-type=module','-e',maintenance],cwd='/srv/harmonia-boot-src/server',check=True)
subprocess.run(['/usr/bin/systemctl','start','harmonia-synthetic-server.service'],check=True)
subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
subprocess.run(['/usr/bin/systemctl','enable','--now','harmonia-real-device.service'],check=True)
print(json.dumps({'no_local_login_session':True,'bootstrap_credential_file_removed':True,'old_server_sessions_removed':True,'formal_device_service_enabled':True}))
