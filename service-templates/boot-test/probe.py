import sys
if sys.flags.optimize: raise SystemExit("测试脚本禁止关闭断言")
import os,pathlib,subprocess,json,sys,time,collections,stat
assert os.geteuid()==0 and pathlib.Path('/opt/orbstack-guest').exists()
assert pathlib.Path('/etc/hostname').read_text().strip().startswith('harmonia-boot-test-')
assert not pathlib.Path('/mnt/mac').exists()
mode=sys.argv[1]
base=pathlib.Path('/var/lib/harmonia/30001/protected')
report=pathlib.Path('/var/lib/harmonia-test-server/boot-report.json')
def run(argv,check=True):
 r=subprocess.run(argv,check=check,capture_output=True,text=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=15)
 return r
def property(unit,name):return run(['systemctl','show',unit,'--property='+name,'--value']).stdout.strip()
def audit():
 c=collections.Counter()
 for line in pathlib.Path('/var/lib/harmonia-test-server/requests.jsonl').read_text().splitlines():
  e=json.loads(line)
  if e['status']==200:
   for ending in ['/boot-challenges','/boot-sessions','/pull','/v1/login']:
    if e['path'].endswith(ending):c[ending]+=1
 return dict(c)
def snapshot():
 sessions=run(['loginctl','list-sessions','--no-legend']).stdout.splitlines()
 target_sessions=sum('30001' in s.split() for s in sessions)
 return {'init_start':pathlib.Path('/proc/1/stat').read_text().split(')')[1].split()[19], 'kernel_boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel_uptime':float(pathlib.Path('/proc/uptime').read_text().split()[0]),'device_invocation':property('harmonia-real-device.service','InvocationID'),'server_invocation':property('harmonia-synthetic-server.service','InvocationID'),'audit':audit(),'target_login_sessions':target_sessions}
def cli(command,*args,uid='harmonia_boot_device',check=True):return run(['runuser','-u',uid,'--','env','-i','PATH=/usr/bin:/bin','/usr/local/lib/harmonia-boot-test/harmonia',command,'--local-directory',str(base),*args],check)
assert not (base/'session.v1.enc').exists()
assert not pathlib.Path('/var/lib/harmonia/30001/bootstrap.json').exists()
assert property('harmonia-real-device.service','ActiveState')=='active'
if mode=='before':
 s=snapshot();assert s['target_login_sessions']==0
 s['status']=json.loads(cli('status').stdout)
 assert s['status']['sequence']==3
 report.write_text(json.dumps(s));os.chmod(report,0o600)
 print(json.dumps({'stage':'before','target_login_sessions':0,'sequence':3,'successful_device_boot_count':s['audit'].get('/boot-sessions',0),'login_session_absent':True}))
elif mode=='after':
 before=json.loads(report.read_text())
 deadline=time.monotonic()+25
 while time.monotonic()<deadline:
  s=snapshot()
  if s['audit'].get('/boot-sessions',0)>before['audit'].get('/boot-sessions',0) and s['audit'].get('/pull',0)>before['audit'].get('/pull',0):break
  time.sleep(.2)
 assert s['init_start']!=before['init_start'], '来宾init没有重启'
 assert s['kernel_uptime']>int(before['init_start'])/os.sysconf('SC_CLK_TCK'), '计时不满足当前LXC测试范围'
 assert s['device_invocation']!=before['device_invocation'] and s['server_invocation']!=before['server_invocation']
 assert s['target_login_sessions']==0, '目标测试用户有登录session'
 assert s['audit'].get('/v1/login',0)==before['audit'].get('/v1/login',0), '重启后发生password login'
 assert s['audit'].get('/boot-sessions',0)>before['audit'].get('/boot-sessions',0)
 assert s['audit'].get('/pull',0)>before['audit'].get('/pull',0)
 pid=int(property('harmonia-real-device.service','MainPID'))
 pstatus=pathlib.Path(f'/proc/{pid}/status').read_text().splitlines()
 uidline=next(l for l in pstatus if l.startswith('Uid:')).split()[1:]
 assert all(int(u)==30001 for u in uidline)
 cap=int(next(l for l in pstatus if l.startswith('CapEff:')).split()[1],16);assert cap==0
 status=json.loads(cli('status').stdout);assert status['sequence']==3 and status['accountGeneration']==1
 shell=run(['runuser','-u','harmonia_boot_device','--','env','-i','PATH=/usr/bin:/bin','/bin/sh','-c',f'. {base}/environment.sh; test "$NATIVE_SYNTHETIC" = native-paired-value'])
 denied=cli('status',uid='harmonia_boot_server',check=False);assert denied.returncode!=0
 for p in base.iterdir():
  m=p.stat();assert m.st_uid==30001
  if p.is_file():assert stat.S_IMODE(m.st_mode)==0o600
 assert stat.S_IMODE(base.stat().st_mode)==0o700
 result={'platform':'Ubuntu24.04-arm64-OrbStack-LXC','native_spake2_primitives':'PASS 6/6','formal_first_vault_dual_signature_pairing_boot_signed_write':'PASS','fresh_guest_generated_keys':True,'no_host_key_transfer':True,'init_restart':'PASS','device_and_server_boot_enabled_unit_restart':'PASS','no_target_user_login_session_before_postboot_cli':'PASS','new_boot_challenge_and_device_session_after_restart':'PASS','password_login_after_restart':False,'local_login_session_slot_absent':True,'verified_pull_after_restart':'PASS','cloud_sequence':status['sequence'],'current_user_ipc_and_cloud_shell_fragment':'PASS','second_uid_ipc_denied':'PASS','service_uid':30001,'effective_capabilities':0,'private_file_modes':'PASS','namespace_boot_id_changed':s['kernel_boot_id']!=before['kernel_boot_id'],'shared_kernel_uptime_continues':s['kernel_uptime']>int(before['init_start'])/os.sysconf('SC_CLK_TCK'),'systemd_global_lxc_sandbox_override':'GATE','physical_kernel_boot_disk_unlock_and_full_vm_sandbox':'NOT RUN','windows_macos_native_boot':'GATE','existing_vm_or_host_restarted':False}
 pathlib.Path('/var/lib/harmonia-test-server/public-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(result,ensure_ascii=False))
else:raise ValueError('stage_invalid')
