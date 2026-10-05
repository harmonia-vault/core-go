# 仅由管理员/SYSTEM 在已审阅的隔离 Windows 来宾执行；不自动运行。
param(
 [Parameter(Mandatory=$true)][string]$Stage,
 [Parameter(Mandatory=$true)][ValidatePattern('^harmonia-lab-[0-9a-f]{6}$')][string]$AccountName,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{12}$')][string]$Nonce,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ProfileSHA256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$SyncSHA256
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw '需经批准的 SYSTEM 来宾 provisioning'}
$install="C:\Program Files\HarmoniaNative-$Nonce"
$manifest=Join-Path $install 'lab-manifest.json'
if(Test-Path -LiteralPath $install){throw '独占目录已存在，拒绝覆盖'}
if(Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue){throw '测试账号已存在，拒绝覆盖'}
$profileSource=Join-Path $Stage 'harmonia-profile-arm64.exe'
$syncSource=Join-Path $Stage 'harmonia-native-sync-arm64.exe'
if((Get-FileHash -LiteralPath $profileSource -Algorithm SHA256).Hash -ne $ProfileSHA256 -or (Get-FileHash -LiteralPath $syncSource -Algorithm SHA256).Hash -ne $SyncSHA256){throw '二进制摘要不符'}
function Set-PrivatePath([string]$Path,[string]$SD,[bool]$Directory){
 if($Directory){$a=New-Object Security.AccessControl.DirectorySecurity}else{$a=New-Object Security.AccessControl.FileSecurity}
 $a.SetSecurityDescriptorSddlForm($SD);Set-Acl -LiteralPath $Path -AclObject $a
}
$adminDirectory='O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$null=New-Item -ItemType Directory -Path $install
Set-PrivatePath $install $adminDirectory $true
$m=[ordered]@{schema='harmonia/windows-native-lab/v1';nonce=$Nonce;accountName=$AccountName;install=$install;accountCreated=$false;profileCreated=$false;batchGranted=$false;services=@();rootCreated=$false;folderCreated=$false;taskRegistered=$false;targetSID='';syncSID='';brokerSID='';taskFolder='';phase='directory';profileSHA256=$ProfileSHA256;syncSHA256=$SyncSHA256}
function Save-Manifest{$m|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $manifest -Encoding UTF8}
Save-Manifest
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Security.Principal;
public static class HarmoniaLabNative {
 [StructLayout(LayoutKind.Sequential)] public struct LSA_OBJECT_ATTRIBUTES { public uint Length;public IntPtr RootDirectory,ObjectName;public uint Attributes;public IntPtr SecurityDescriptor,SecurityQualityOfService; }
 [StructLayout(LayoutKind.Sequential)] public struct LSA_UNICODE_STRING { public ushort Length,MaximumLength;public IntPtr Buffer; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct STARTUPINFO { public uint cb; public string reserved,desktop,title;public uint x,y,xsize,ysize,xchars,ychars,fill,flags;public ushort show,reserved2;public IntPtr reservedPtr,input,output,error; }
 [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr process,thread;public uint pid,tid; }
 [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr name,ref LSA_OBJECT_ATTRIBUTES attributes,uint access,out IntPtr policy);
 [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy,IntPtr sid,[In] LSA_UNICODE_STRING[] rights,uint count);
 [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUser(string user,string domain,string password,uint type,uint provider,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr token,string application,StringBuilder command,IntPtr processAttr,IntPtr threadAttr,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUPINFO startup,out PROCESS_INFORMATION info);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int CreateProfile(string sid,string name,StringBuilder path,uint count);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 public static void Batch(string sid){
  var o=new LSA_OBJECT_ATTRIBUTES();o.Length=(uint)Marshal.SizeOf(o);IntPtr policy;
  if(LsaOpenPolicy(IntPtr.Zero,ref o,0x810,out policy)!=0)throw new Exception("policy open rejected");
  IntPtr s=IntPtr.Zero,r=IntPtr.Zero;try{
   byte[] bytes=new byte[new SecurityIdentifier(sid).BinaryLength];new SecurityIdentifier(sid).GetBinaryForm(bytes,0);s=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,s,bytes.Length);
   string right="SeBatchLogonRight";r=Marshal.StringToHGlobalUni(right);var rights=new[]{new LSA_UNICODE_STRING{Length=(ushort)(right.Length*2),MaximumLength=(ushort)((right.Length+1)*2),Buffer=r}};
   if(LsaAddAccountRights(policy,s,rights,1)!=0)throw new Exception("batch grant rejected");
  }finally{if(s!=IntPtr.Zero)Marshal.FreeHGlobal(s);if(r!=IntPtr.Zero)Marshal.FreeHGlobal(r);LsaClose(policy);}
 }
 public static void Profile(string sid,string name){var path=new StringBuilder(32768);if(CreateProfile(sid,name,path,(uint)path.Capacity)!=0)throw new Exception("fresh profile rejected");}
 public static void SelfRegister(string user,string password,string sid,string exe,string config,string directory){
  IntPtr token;if(!LogonUser(user,".",password,4,0,out token))throw new Exception("synthetic batch logon rejected");
  try{
   if(new WindowsIdentity(token).User.Value!=sid)throw new Exception("fresh SID mismatch");
   // 独立固定环境；不继承 SYSTEM/真实用户的环境。
   string environment="Path=C:\\Windows\\System32\0SystemDrive=C:\0SystemRoot=C:\\Windows\0TEMP=C:\\Windows\\Temp\0TMP=C:\\Windows\\Temp\0\0";
   IntPtr env=Marshal.StringToHGlobalUni(environment);PROCESS_INFORMATION pi;
   try{
    var si=new STARTUPINFO();si.cb=(uint)Marshal.SizeOf(si);
    if(!CreateProcessAsUser(token,exe,new StringBuilder("\""+exe+"\" self-register --config \""+config+"\""),IntPtr.Zero,IntPtr.Zero,false,0x400,env,directory,ref si,out pi))throw new Exception("synthetic process rejected");
   }finally{Marshal.FreeHGlobal(env);}
   try{
    if(WaitForSingleObject(pi.process,25000)!=0){TerminateProcess(pi.process,2);WaitForSingleObject(pi.process,5000);throw new Exception("synthetic registration timeout");}
    uint result;if(!GetExitCodeProcess(pi.process,out result)||result!=0)throw new Exception("self registration rejected");
   }finally{CloseHandle(pi.thread);CloseHandle(pi.process);}
  }finally{CloseHandle(token);}
 }
}
'@
# 密码只在本 provisioning 进程 RAM 中出现；不写 manifest、参数、日志或文件。
$entropy=New-Object byte[] 32
$rng=[Security.Cryptography.RandomNumberGenerator]::Create();$rng.GetBytes($entropy);$rng.Dispose()
$password=[Convert]::ToBase64String($entropy)+'aA1!';[Array]::Clear($entropy,0,$entropy.Length)
$secure=ConvertTo-SecureString -String $password -AsPlainText -Force
try{
 $user=New-LocalUser -Name $AccountName -Password $secure -AccountNeverExpires -Description 'Harmonia 独立合成原生实验' -UserMayNotChangePassword
 $m.accountCreated=$true;$m.targetSID=$user.SID.Value;$m.phase='account';Save-Manifest
 $users=([Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
 Add-LocalGroupMember -Group $users -Member $AccountName
 [HarmoniaLabNative]::Profile($m.targetSID,$AccountName);$m.profileCreated=$true;Save-Manifest
 [HarmoniaLabNative]::Batch($m.targetSID);$m.batchGranted=$true;Save-Manifest
 $sha=[Security.Cryptography.SHA256]::Create();$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($m.targetSID));$sha.Dispose()
 $tag=([BitConverter]::ToString($digest[0..5])).Replace('-','').ToLowerInvariant()
 $syncName='Harmonia-'+$tag;$brokerName='HarmoniaProfile-'+$tag
 foreach($name in @($syncName,$brokerName)){if(Get-Service -Name $name -ErrorAction SilentlyContinue){throw '服务已存在，拒绝覆盖'}}
 $profileExe=Join-Path $install 'profile.exe';$syncExe=Join-Path $install 'sync.exe';$config=Join-Path $install 'profile.json'
 Copy-Item -LiteralPath $profileSource -Destination $profileExe
 Copy-Item -LiteralPath $syncSource -Destination $syncExe
 $sc='C:\Windows\System32\sc.exe'
 & $sc create $brokerName binPath= ('"'+$profileExe+'" broker --config "'+$config+'"') type= own start= demand obj= LocalSystem|Out-Null
 if($LASTEXITCODE -ne 0){throw 'broker 创建失败'};$m.services+=@($brokerName);Save-Manifest
 & $sc create $syncName binPath= ('"'+$syncExe+'" --config "'+$config+'"') type= own start= demand obj= ('NT SERVICE\'+$syncName)|Out-Null
 if($LASTEXITCODE -ne 0){throw 'sync 创建失败'};$m.services+=@($syncName);Save-Manifest
 & $sc sidtype $brokerName unrestricted|Out-Null;if($LASTEXITCODE -ne 0){throw 'broker SID 配置失败'}
 & $sc sidtype $syncName unrestricted|Out-Null;if($LASTEXITCODE -ne 0){throw 'sync SID 配置失败'}
 & $sc privs $brokerName SeChangeNotifyPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege|Out-Null;if($LASTEXITCODE -ne 0){throw 'broker privilege 限制失败'}
 & $sc privs $syncName SeChangeNotifyPrivilege|Out-Null;if($LASTEXITCODE -ne 0){throw 'sync privilege 限制失败'}
 $syncSID=(New-Object Security.Principal.NTAccount('NT SERVICE',$syncName)).Translate([Security.Principal.SecurityIdentifier]).Value
 $brokerSID=(New-Object Security.Principal.NTAccount('NT SERVICE',$brokerName)).Translate([Security.Principal.SecurityIdentifier]).Value
 $m.syncSID=$syncSID;$m.brokerSID=$brokerSID
 $cfg=[ordered]@{schema='harmonia/windows-profile/v1';targetSID=$m.targetSID;syncServiceSID=$syncSID;brokerServiceSID=$brokerSID;executable=$profileExe;syncExecutable=$syncExe;configurationFile=$config}
 $cfg|ConvertTo-Json -Compress|Set-Content -LiteralPath $config -Encoding ASCII
 $readers='(A;;GRGX;;;'+$m.targetSID+')(A;;GRGX;;;'+$syncSID+')'
 $fileSD='O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'+$readers
 foreach($path in @($config,$profileExe,$syncExe)){Set-PrivatePath $path $fileSD $false}
 Set-PrivatePath $install ('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'+$readers) $true
 $vault=Join-Path $install 'vault';$null=New-Item -ItemType Directory -Path $vault
 Set-PrivatePath $vault ('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$syncSID+')') $true
 $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$top=$scheduler.GetFolder('\')
 try{$root=$scheduler.GetFolder('\Harmonia')}catch{$root=$top.CreateFolder('Harmonia','O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)');$m.rootCreated=$true;Save-Manifest}
 # 不改既有 root 的 DACL；broker 会 independently 验证，实际不兼容则 fail closed。
 $folderName='Profile-'+$tag;$folderPath='\Harmonia\'+$folderName
 try{$existing=$scheduler.GetFolder($folderPath);throw 'SID task folder 已存在，拒绝覆盖'}catch{if($_.Exception.Message -eq 'SID task folder 已存在，拒绝覆盖'){throw}}
 $folder=$root.CreateFolder($folderName,('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGWGX;;;'+$m.targetSID+')'))
 $m.folderCreated=$true;$m.taskFolder=$folderPath;$m.phase='pre-register';Save-Manifest
 [HarmoniaLabNative]::SelfRegister($AccountName,$password,$m.targetSID,$profileExe,$config,$install)
 $m.taskRegistered=$true;Save-Manifest
 $task=$folder.GetTask('Token')
 if($folder.GetTasks(1).Count -ne 1 -or $folder.GetFolders(0).Count -ne 0){throw '非唯一任务，拒绝锁定/启动'}
 # 不自动添加额外 principal ACE；同时转换 owner，原 target owner 不再隐式可改 DACL。
 $task.SetSecurityDescriptor(('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;'+$m.targetSID+')'),16)
 $folder.SetSecurityDescriptor(('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;'+$m.targetSID+')'),0)
 $m.phase='ready-for-reviewed-start';Save-Manifest
 [Console]::Write('HARMONIA_SYNTHETIC_PROVISIONED')
}finally{
 if($secure){$secure.Dispose()};$password=$null;$user=$null
}
