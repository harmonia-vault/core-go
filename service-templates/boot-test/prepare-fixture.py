import sys
if sys.flags.optimize: raise SystemExit("测试脚本禁止关闭断言")
import pathlib,subprocess,os,json,tarfile,pwd,grp
assert os.geteuid()==0 and pathlib.Path('/opt/orbstack-guest').exists()
assert pathlib.Path('/etc/hostname').read_text().strip().startswith('harmonia-boot-test-')
assert not pathlib.Path('/mnt/mac').exists()
assert pathlib.Path('/srv/harmonia-boot-src').is_dir()
with tarfile.open('/var/tmp/harmonia-boot-input/source.tar.gz') as t:t.extractall('/srv/harmonia-boot-src',filter='data')
for uid,name in [(30001,'harmonia_boot_device'),(30002,'harmonia_boot_server')]:
 try: pwd.getpwnam(name); raise RuntimeError('已存在测试账号，拒绝覆盖')
 except KeyError: pass
 try: pwd.getpwuid(uid); raise RuntimeError('测试UID冲突，拒绝覆盖')
 except KeyError: pass
 subprocess.run(['/usr/sbin/useradd','--uid',str(uid),'--user-group','--no-create-home','--home-dir',f'/var/lib/harmonia-test-home/{uid}','--shell','/usr/sbin/nologin',name],check=True)
for p,uid in [('/var/lib/harmonia',0),('/var/lib/harmonia/30001',30001),('/var/lib/harmonia-test-server',30002),('/usr/local/share/harmonia-boot-test',0),('/usr/local/lib/harmonia-boot-test',0)]:
 path=pathlib.Path(p);path.mkdir(mode=0o755 if uid==0 else 0o700,exist_ok=False);os.chown(path,uid,uid)
ca=pathlib.Path('/var/lib/harmonia-test-server')
env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}
def openssl(args):subprocess.run(['/usr/bin/openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
openssl(['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','2','-subj','/CN=Harmonia Synthetic Boot Test CA','-keyout',str(ca/'ca.key'),'-out',str(ca/'ca.pem')])
openssl(['req','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(ca/'server.key'),'-out',str(ca/'server.csr')])
(ca/'extensions.conf').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
openssl(['x509','-req','-in',str(ca/'server.csr'),'-CA',str(ca/'ca.pem'),'-CAkey',str(ca/'ca.key'),'-CAcreateserial','-days','2','-sha256','-extfile',str(ca/'extensions.conf'),'-out',str(ca/'server.pem')])
for p in ca.iterdir():os.chmod(p,0o600);os.chown(p,30002,30002)
public=pathlib.Path('/usr/local/share/harmonia-boot-test/ca.pem');public.write_bytes((ca/'ca.pem').read_bytes());os.chmod(public,0o644)
p=pathlib.Path('/var/lib/harmonia/30001/bootstrap.json');p.write_text(json.dumps({'endpoint':'https://127.0.0.1:37654','accountId':'synthetic-account','accountGeneration':'1','email':'synthetic@example.invalid','credential':'ab'*32,'devices':{},'grants':[]}));os.chmod(p,0o600);os.chown(p,30001,30001)
serverunit='''[Unit]
Description=Harmonia isolated synthetic HTTPS boot test server
After=network.target
[Service]
Type=simple
User=harmonia_boot_server
Group=harmonia_boot_server
UMask=0077
WorkingDirectory=/srv/harmonia-boot-src/server
ExecStart=/opt/harmonia-test-tools/node-v24.16.0-linux-arm64/bin/node --import tsx tests/orbstack-boot-server.ts
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/harmonia-test-server
Restart=on-failure
[Install]
WantedBy=multi-user.target
'''
path=pathlib.Path('/etc/systemd/system/harmonia-synthetic-server.service');path.write_text(serverunit);os.chmod(path,0o644)
subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
subprocess.run(['/usr/bin/systemctl','enable','--now','harmonia-synthetic-server.service'],check=True)
print(json.dumps({'accounts_created':[30001,30002],'tls_ca_scope':'only-test-process-explicit-file','source_refreshed':True,'server_enabled':True}))
