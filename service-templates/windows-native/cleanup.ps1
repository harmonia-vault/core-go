# 只清理 provisioning manifest 明确记录的本轮合成资源；不卸载其它 hive/服务。
param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{12}$')][string]$Nonce)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw '需经批准的 SYSTEM 来宾 cleanup'}
$install="C:\Program Files\HarmoniaNative-$Nonce";$manifest=Join-Path $install 'lab-manifest.json'
$m=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json
if($m.schema -ne 'harmonia/windows-native-lab/v1' -or $m.nonce -ne $Nonce -or $m.install -ne $install -or $m.accountName -notmatch '^harmonia-lab-[0-9a-f]{6}$'){throw 'manifest 范围拒绝'}
$user=Get-LocalUser -Name $m.accountName -ErrorAction SilentlyContinue
if($m.accountCreated -and (!$user -or $user.SID.Value -ne $m.targetSID)){throw '新账号身份已改变，拒绝清理'}
$sha=[Security.Cryptography.SHA256]::Create();$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($m.targetSID));$sha.Dispose();$tag=([BitConverter]::ToString($digest[0..5])).Replace('-','').ToLowerInvariant()
$expected=@('Harmonia-'+$tag,'HarmoniaProfile-'+$tag)
foreach($name in $m.services){if($name -notin $expected){throw 'manifest 服务不匹配'}}
foreach($name in $expected){if($name -notin $m.services){continue};$service=Get-Service -Name $name -ErrorAction SilentlyContinue;if($service){if($service.Status -ne 'Stopped'){Stop-Service -Name $name;$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35))};if($service.Status -ne 'Stopped'){throw '服务未确认停止，保留资源'}}}
$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
if($m.folderCreated){
 if($m.taskFolder -ne ('\Harmonia\Profile-'+$tag)){throw 'manifest task folder 不匹配'}
 $folder=$scheduler.GetFolder($m.taskFolder)
 if($folder.GetTasks(1).Count -gt 1 -or $folder.GetFolders(0).Count -ne 0){throw '新增其它任务，保留资源'}
 if($folder.GetTasks(1).Count -eq 1){$task=$folder.GetTask('Token');$task.Stop(0);$folder.DeleteTask('Token',0)}
 $root=$scheduler.GetFolder('\Harmonia');$root.DeleteFolder('Profile-'+$tag,0)
 if($m.rootCreated -and $root.GetTasks(1).Count -eq 0 -and $root.GetFolders(0).Count -eq 0){$scheduler.GetFolder('\').DeleteFolder('Harmonia',0)}
}
foreach($name in $expected){if($name -in $m.services){& 'C:\Windows\System32\sc.exe' delete $name|Out-Null;if($LASTEXITCODE -ne 0){throw '服务删除未确认'}}}
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Security.Principal;
public static class HarmoniaLabCleanup {
 [StructLayout(LayoutKind.Sequential)] public struct OA{public uint Length;public IntPtr Root,Name;public uint Attributes;public IntPtr SD,QOS;}
 [StructLayout(LayoutKind.Sequential)] public struct US{public ushort Length,Max;public IntPtr Buffer;}
 [DllImport("advapi32.dll")]static extern uint LsaOpenPolicy(IntPtr name,ref OA attributes,uint access,out IntPtr policy);
 [DllImport("advapi32.dll")]static extern uint LsaRemoveAccountRights(IntPtr policy,IntPtr sid,[MarshalAs(UnmanagedType.U1)]bool all,[In]US[] rights,uint count);
 [DllImport("advapi32.dll")]static extern uint LsaClose(IntPtr policy);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool DeleteProfile(string sid,string path,string computer);
 public static void Batch(string sid){var oa=new OA();oa.Length=(uint)Marshal.SizeOf(oa);IntPtr p;if(LsaOpenPolicy(IntPtr.Zero,ref oa,0x810,out p)!=0)throw new Exception("policy open rejected");IntPtr s=IntPtr.Zero,r=IntPtr.Zero;try{var id=new SecurityIdentifier(sid);var b=new byte[id.BinaryLength];id.GetBinaryForm(b,0);s=Marshal.AllocHGlobal(b.Length);Marshal.Copy(b,0,s,b.Length);string name="SeBatchLogonRight";r=Marshal.StringToHGlobalUni(name);var rights=new[]{new US{Length=(ushort)(name.Length*2),Max=(ushort)((name.Length+1)*2),Buffer=r}};if(LsaRemoveAccountRights(p,s,false,rights,1)!=0)throw new Exception("batch removal rejected");}finally{if(s!=IntPtr.Zero)Marshal.FreeHGlobal(s);if(r!=IntPtr.Zero)Marshal.FreeHGlobal(r);LsaClose(p);}}
 public static void Profile(string sid){if(!DeleteProfile(sid,null,null))throw new Exception("new profile cleanup rejected");}
}
'@
if($m.batchGranted){[HarmoniaLabCleanup]::Batch($m.targetSID)}
if($m.profileCreated){[HarmoniaLabCleanup]::Profile($m.targetSID)}
if($m.accountCreated){Remove-LocalUser -Name $m.accountName}
if((Get-ChildItem -LiteralPath $install -Recurse -Force|Where-Object{ $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -ne 0){throw '发现 reparse，保留目录待审阅'}
Remove-Item -LiteralPath $install -Recurse -Force
[Console]::Write('HARMONIA_SYNTHETIC_CLEANED')
