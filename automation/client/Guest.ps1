$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$share = '\\host.lan\Data'
for ($i = 0; $i -lt 60 -and -not (Test-Path "$share\platform.txt"); ++$i) { Start-Sleep 5 }
if (-not (Test-Path "$share\platform.txt")) { throw 'The test share is unavailable.' }
$platform = (Get-Content "$share\platform.txt" -Raw).Trim()
$root = 'C:\OpenHashTabTests'
$null = New-Item -ItemType Directory $root -Force
$null = Start-Transcript "$share\guest.log" -Append
$success = $false
$reboot = $false
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List
    $version | Select-Object DisplayVersion, CurrentBuild, UBR | Format-List
    $expectedBuild = if ($platform -eq 'windows-11-26h2') { 26300 } else { 26200 }
    if ($os.Caption -notmatch 'Windows 11' -or [int]$os.BuildNumber -ne $expectedBuild) { throw 'Unexpected Windows image.' }
    if (-not (Test-Path "$root\initialized")) {
        Copy-Item "$share\automation", "$share\binaries", "$share\installers", "$share\baseline" $root -Recurse -Force
        Copy-Item "$share\VERSION" $root
        Set-Content "$root\initialized" $platform
    }
    $env:OHT_DISPOSABLE_VM = $platform
    Set-Location $root
    if (Test-Path "$root\reboot-pending") {
        $previous = [datetime](Get-Content "$root\reboot-pending" -Raw)
        if ($os.LastBootUpTime.ToUniversalTime() -le $previous) { throw 'A real reboot was not observed.' }
        & "$root\automation\Test-Install.ps1" -Stage AfterReboot -Architecture x64
        & "$root\automation\Test-Behavior.ps1" -Stage Verify
        $success = $true
    } else {
        # Install the current cumulative update using Microsoft's Windows Update API.
        # Do not upgrade the feature version: each matrix entry must keep its identity.
        if ([int]$version.UBR -lt 9711) {
            $session = New-Object -ComObject Microsoft.Update.Session
            $search = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            $updates = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($update in $search.Updates) {
                if ($update.KBArticleIDs -contains '5127648') {
                    if (-not $update.EulaAccepted) { $update.AcceptEula() }
                    [void]$updates.Add($update)
                    Write-Host "Installing cumulative update: $($update.Title)"
                }
            }
            if ($updates.Count -eq 0) { throw 'The required October 2026 cumulative update was not offered.' }
            $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $updates
            $download = $downloader.Download()
            if ($download.ResultCode -ne 2) { throw "Windows Update download failed: $($download.ResultCode)" }
            $installer = $session.CreateUpdateInstaller(); $installer.Updates = $updates
            $installed = $installer.Install()
            if ($installed.ResultCode -ne 2) { throw "Windows Update installation failed: $($installed.ResultCode)" }
            Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'OpenHashTabTests' 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\Guest.ps1'
            $null = Stop-Transcript
            Restart-Computer -Force
            exit
        }
        & "$root\automation\Test-Behavior.ps1" -Stage Start
        foreach ($architecture in @('x86', 'x64')) {
            & "$root\binaries\oht-$architecture\Tests\CoreTests.exe"
            if ($LASTEXITCODE -ne 0) { throw "Core tests failed: $architecture" }
            foreach ($test in @('EncodingTests', 'ExtendedHashTests', 'ReportTests', 'BatchTests')) {
                & "$root\binaries\oht-$architecture\Tests\$test.exe"
                if ($LASTEXITCODE -ne 0) { throw "$test failed: $architecture" }
            }
            & "$root\automation\Test-CLI.ps1" -Executable "$root\binaries\oht-$architecture\OpenHashTabCLI.exe"
        }
        & "$root\automation\Test-Install.ps1" -Stage BeforeReboot -Architecture x64
        Set-Content "$root\reboot-pending" $os.LastBootUpTime.ToUniversalTime().ToString('o')
        Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'OpenHashTabTests' 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\Guest.ps1'
        $reboot = $true
    }
} catch {
    Write-Host $_
    Write-Host $_.ScriptStackTrace
} finally {
    $null = Stop-Transcript -ErrorAction SilentlyContinue
}
if ($reboot) { Restart-Computer -Force; exit }
@{ platform = $platform; success = $success; rebootVerified = $success } | ConvertTo-Json | Set-Content "$share\result.tmp" -Encoding ascii
Move-Item "$share\result.tmp" "$share\result.json" -Force
