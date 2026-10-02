import sys
if sys.flags.optimize: raise SystemExit("测试脚本禁止关闭断言")
import hashlib,json,os,pathlib,subprocess,tarfile,urllib.request
if os.geteuid()!=0 or not pathlib.Path('/opt/orbstack-guest').is_dir(): raise SystemExit('只允许已获准隔离OrbStack测试来宾')
if not pathlib.Path('/etc/hostname').read_text().strip().startswith('harmonia-boot-test-') or pathlib.Path('/mnt/mac').exists(): raise SystemExit('拒绝非本轮隔离测试机或宿主home挂载')
tools=pathlib.Path('/opt/harmonia-test-tools')
tools.mkdir(mode=0o755)
subprocess.run(['apt-get','update','-qq'],check=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
subprocess.run(['apt-get','install','-y','--no-install-recommends','ca-certificates','curl','git','build-essential','cmake','ninja-build','pkg-config','openssl','acl','ripgrep'],check=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
def fetch(url):
    with urllib.request.urlopen(url,timeout=30) as response: return response.read()
goversions=json.loads(fetch('https://go.dev/dl/?mode=json&include=all'))
goarchive=next(file for version in goversions if version['version']=='go1.26.4' for file in version['files'] if file['filename']=='go1.26.4.linux-arm64.tar.gz')
nodefile='node-v24.16.0-linux-arm64.tar.xz'
nodehash=next(line.split()[0] for line in fetch('https://nodejs.org/dist/v24.16.0/SHASUMS256.txt').decode().splitlines() if line.split()[-1]==nodefile)
for url,filename,digest in [('https://go.dev/dl/'+goarchive['filename'],goarchive['filename'],goarchive['sha256']),('https://nodejs.org/dist/v24.16.0/'+nodefile,nodefile,nodehash)]:
    data=fetch(url)
    if hashlib.sha256(data).hexdigest()!=digest: raise SystemExit('official distribution hash mismatch')
    archive=tools/filename
    archive.write_bytes(data)
    with tarfile.open(archive) as source: source.extractall(tools,filter='data')
    archive.unlink()
nodebin=tools/'node-v24.16.0-linux-arm64'/'bin'
for name in ('node','npm','npx'):
    (tools/name).symlink_to(nodebin/name)
subprocess.run([str(nodebin/'npm'),'install','--global','--prefix',str(tools),'pnpm@11.5.2'],check=True,env={'PATH':str(nodebin)+':/usr/bin:/bin','LC_ALL':'C','npm_config_cache':str(tools/'.npm-cache')})
print(json.dumps({'go':'1.26.4','node':'24.16.0','pnpm':'11.5.2','official_sha256_checked':True}))
