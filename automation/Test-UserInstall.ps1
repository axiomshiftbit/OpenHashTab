[CmdletBinding()]
param([ValidateSet('x64', 'arm64')][string]$Architecture = 'x64')
$ErrorActionPreference = 'Stop'
if ($env:OHT_DISPOSABLE_VM -notlike 'windows-11-*' -and
    -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Standard-user tests are restricted to disposable test machines.'
}
$root = Split-Path $PSScriptRoot
$name = 'OhtTest' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$work = Join-Path $env:PUBLIC $name
$user = $null
$process = $null
$desktop = $null
try {
    # This credential exists only in memory for the disposable local test user.
    $password = ConvertTo-SecureString ([guid]::NewGuid().ToString('N') + '!aA7') -AsPlainText -Force
    $user = New-LocalUser -Name $name -Password $password -Description 'Temporary OpenHashTab installer test'
    $group = Get-LocalGroup -SID 'S-1-5-32-545'
    if (-not (Get-LocalGroupMember -Group $group | Where-Object SID -eq $user.SID)) {
        Add-LocalGroupMember -Group $group -Member $user
    }
    $null = New-Item -ItemType Directory $work
    & icacls.exe $work /grant "*$($user.SID.Value):(OI)(CI)M" /q | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant access to the isolated test directory.' }
    Copy-Item "$root\automation", "$root\binaries", "$root\installers", "$root\baseline" $work -Recurse
    Copy-Item "$root\VERSION" $work
    @'
param([string]$Architecture)
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The User installer test must run without administrator privileges.'
    }
    $profile = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($identity.User.Value)").ProfileImagePath
    if ($env:USERPROFILE -ne [Environment]::ExpandEnvironmentVariables($profile)) {
        throw 'The test process must use the standard user profile and environment.'
    }
    Write-Host 'PASS: User installer runs with a real standard-user token.'
    $env:OHT_DISPOSABLE_VM = 'windows-11-standard-user'
    & "$PSScriptRoot\automation\Test-Install.ps1" -Stage All -Architecture $Architecture -InstallScope User
    exit 0
} catch {
    Write-Host $_
    Write-Host $_.ScriptStackTrace
    exit 1
}
'@ | Set-Content "$work\Run.ps1" -Encoding utf8
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    $shell = (Get-Process -Id $PID).Path
    Add-Type -Path "$PSScriptRoot\TestDesktopAccess.cs"
    $desktop = [TestDesktopAccess]::new($user.SID.Value)
    # Before PowerShell 7.1 the switch had the opposite effect on the native
    # environment block. Pass null in both cases so Windows loads this user's
    # environment, rather than the administrator's profile variables.
    $newEnvironment = $PSVersionTable.PSVersion -ge [version]'7.1'
    $process = Start-Process $shell -Credential $credential -LoadUserProfile -UseNewEnvironment:$newEnvironment -WorkingDirectory $work -PassThru `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$work\Run.ps1`" -Architecture $Architecture" `
        -RedirectStandardOutput "$work\stdout.log" -RedirectStandardError "$work\stderr.log"
    # Retain the handle before waiting: Windows PowerShell can otherwise lose
    # ExitCode for a redirected process (PowerShell/PowerShell#20400).
    $null = $process.Handle
    if (-not $process.WaitForExit(600000)) {
        & taskkill.exe /PID $process.Id /T /F | Write-Host
        throw 'Standard-user installer tests timed out.'
    }
    if ($process.ExitCode -ne 0) { throw "Standard-user installer tests failed: $($process.ExitCode)" }
    Write-Host 'PASS: install, upgrade, repair, COM, GUI and uninstall without administrator privileges.'
} finally {
    if ($process) { $process.Dispose() }
    $desktopError = $null
    try { if ($desktop) { $desktop.Dispose() } } catch { $desktopError = $_ }
    foreach ($file in @('stdout.log', 'stderr.log')) {
        if (Test-Path "$work\$file") { Get-Content "$work\$file" | Write-Host }
    }
    if (Test-Path "$work\msi-logs") {
        $logs = Join-Path $root 'msi-logs\standard-user'
        $null = New-Item -ItemType Directory $logs -Force
        Copy-Item "$work\msi-logs\*.log" $logs -ErrorAction SilentlyContinue
    }
    if ($user) {
        Remove-LocalUser -SID $user.SID
        Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'" |
            Where-Object { -not $_.Loaded } | Remove-CimInstance
    }
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    if ($desktopError) { throw $desktopError }
}
