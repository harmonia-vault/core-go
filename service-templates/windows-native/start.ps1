# 仅在 provision.ps1 的 concrete manifest 与权限动作获批后单独执行；不创建/授予资源。
param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{12}$')][string]$Nonce)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw '需经批准的 SYSTEM 来宾 native test'}
$install="C:\Program Files\HarmoniaNative-$Nonce"
$m=Get-Content -LiteralPath (Join-Path $install 'lab-manifest.json') -Raw|ConvertFrom-Json
if($m.schema -ne 'harmonia/windows-native-lab/v1' -or $m.nonce -ne $Nonce -or $m.install -ne $install -or $m.phase -ne 'ready-for-reviewed-start' -or $m.accountName -notmatch '^harmonia-lab-[0-9a-f]{6}$'){throw 'manifest 不完整/不匹配'}
$user=Get-LocalUser -Name $m.accountName
if($user.SID.Value -ne $m.targetSID){throw '新账号 SID 已改变'}
if((Get-FileHash -LiteralPath (Join-Path $install 'profile.exe') -Algorithm SHA256).Hash -ne $m.profileSHA256 -or (Get-FileHash -LiteralPath (Join-Path $install 'sync.exe') -Algorithm SHA256).Hash -ne $m.syncSHA256){throw 'native 二进制已改变'}
$sha=[Security.Cryptography.SHA256]::Create();$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($m.targetSID));$sha.Dispose();$tag=([BitConverter]::ToString($digest[0..5])).Replace('-','').ToLowerInvariant()
$broker='HarmoniaProfile-'+$tag;$sync='Harmonia-'+$tag
if($m.services.Count -ne 2 -or $broker -notin $m.services -or $sync -notin $m.services -or $m.taskFolder -ne ('\Harmonia\Profile-'+$tag)){throw '资源名不匹配'}
$result=Join-Path $install 'vault\result.json'
if(Test-Path -LiteralPath $result){throw '旧 native 结果存在，不重复计入本次验收'}
Start-Service -Name $broker
$b=Get-Service -Name $broker;$b.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
# 一次性 probe 会完成后停止；是否成功由 exact 新结果及 SCM exit code 判定。
& 'C:\Windows\System32\sc.exe' start $sync|Out-Null
if($LASTEXITCODE -ne 0){throw '新虚拟服务启动失败'}
$deadline=[DateTime]::UtcNow.AddSeconds(25)
while(!(Test-Path -LiteralPath $result) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
if(!(Test-Path -LiteralPath $result)){throw '新 probe 未返回结果'}
$r=Get-Content -LiteralPath $result -Raw|ConvertFrom-Json
if($r.scope -ne 'native-provider-only' -or !$r.pass -or $r.stage -ne 'complete'){throw ('native provider 未通过阶段：'+$r.stage)}
(Get-Service -Name $sync).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))
$scm=Get-CimInstance Win32_Service -Filter ("Name='"+$sync+"'")
if($scm.ExitCode -ne 0){throw '虚拟服务异常停止'}
$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$task=$scheduler.GetFolder($m.taskFolder).GetTask('Token')
if($task.LastTaskResult -ne 0){throw '新 S4U helper 未正常完成'}
if(!(Test-Path -LiteralPath ('Registry::HKEY_USERS\'+$m.targetSID))){throw '新 profile 未加载'}
Stop-Service -Name $broker
(Get-Service -Name $broker).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35))
$scm=Get-CimInstance Win32_Service -Filter ("Name='"+$broker+"'")
if($scm.ExitCode -ne 0){throw 'broker 异常停止，不能记为正常 unload'}
@{scope='native-S4U-profile-SCM-provider';pass=$true;taskResult=0;brokerNormalStop=$true;kernelReboot='UNRUN';formalCloudCLI='UNRUN'}|ConvertTo-Json -Compress
