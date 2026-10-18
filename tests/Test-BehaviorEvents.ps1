$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../automation/BehaviorEvents.ps1"
function New-BehaviorEvent([int]$Kind, [hashtable]$Data) {
    $xml = '<Event><EventData>'
    foreach ($key in $Data.Keys) {
        $xml += '<Data Name="' + $key + '">' + [Security.SecurityElement]::Escape([string]$Data[$key]) + '</Data>'
    }
    $event = [pscustomobject]@{Id=$Kind; Data=$Data; Xml=($xml + '</EventData></Event>')}
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    return $event
}
$baseline = @(
    foreach ($name in @('CoreTests.exe','EncodingTests.exe','ShellTests.exe','StandaloneStub.exe')) {
        New-BehaviorEvent 1 @{Image="C:\Test\$name"; ParentImage='C:\Windows\powershell.exe'}
    }
    New-BehaviorEvent 3 @{Image='C:\Windows\powershell.exe'; DestinationPort='443'}
    New-BehaviorEvent 22 @{Image='C:\Windows\powershell.exe'; QueryName='www.microsoft.com'}
    New-BehaviorEvent 13 @{Image='C:\Test\StandaloneStub.exe'; TargetObject='HKU\S-1-5-21-1-2-3-1000\Software\OpenHashTab\Setting'}
)
$control = @(
    New-BehaviorEvent 1 @{Image='C:\Test\WindowsShellControl.exe'}
    New-BehaviorEvent 7 @{Image='C:\Test\WindowsShellControl.exe'; ImageLoaded='C:\Windows\System32\shell32.dll'}
)
$cases = @(
    @{Events=$baseline; Error=''},
    @{Events=@(); Error='Missing process telemetry:'},
    @{Events=@($baseline | Where-Object Id -ne 3); Error='Network/DNS telemetry positive control failed.'},
    @{Events=@($baseline | Where-Object Id -ne 22); Error='Network/DNS telemetry positive control failed.'}
)
foreach ($name in @('CoreTests.exe','EncodingTests.exe','ShellTests.exe','StandaloneStub.exe')) {
    $cases += @{Events=@($baseline | Where-Object { $_.Id -ne 1 -or $_.Data.Image -ne "C:\Test\$name" }); Error='Missing process telemetry:'}
}
foreach ($kind in @(3,8,9,22)) {
    $data = if ($kind -eq 8) { @{SourceImage='C:\Test\CoreTests.exe'} } else { @{Image='C:\Test\CoreTests.exe'} }
    $cases += @{Events=@($baseline) + (New-BehaviorEvent $kind $data); Error='Unexpected application behavior detected.'}
}
foreach ($kind in @(12,13,14)) {
    foreach ($key in @('HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Test', 'HKCU\Software\OpenHashTabOther\Test')) {
        $cases += @{Events=@($baseline) + (New-BehaviorEvent $kind @{Image='C:\Test\ShellTests.exe'; TargetObject=$key}); Error='Unexpected application behavior detected.'}
    }
}
$cases += @{Events=@($baseline) + (New-BehaviorEvent 1 @{Image='C:\Windows\cmd.exe'; ParentImage='C:\Test\StandaloneStub.exe'}); Error='Unexpected application behavior detected.'}
$cases += @{Events=@($baseline) + (New-BehaviorEvent 13 @{Image='C:\Other.exe'; TargetObject='HKCU\Other'}); Error=''}
$cases += @{Events=@($baseline) + (New-BehaviorEvent 7 @{Image='C:\Test\CoreTests.exe'}); Error=''}
$cases += @{Events=@($baseline) + (New-BehaviorEvent 11 @{Image='C:\Test\CoreTests.exe'}); Error=''}
# Finite registry exceptions need the same operation/value family from the control.
$registryData = @(
    @{EventType='SetValue'; TargetObject='HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1000\\Device\HarddiskVolume3\Test\ShellTests.exe'; Details='Binary Data'}
    @{EventType='SetValue'; TargetObject='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC1C75'; Details='Binary Data'}
    @{EventType='SetValue'; TargetObject='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC2475'; Details='Binary Data'}
    @{EventType='CreateKey'; TargetObject='HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'; Details=''}
    foreach ($name in @('AutoDetect','UNCAsIntranet','IntranetName','ProxyBypass')) {
        @{EventType='SetValue'; TargetObject="HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\$name"; Details='DWORD (0x00000001)'}
    }
)
$allControls = @($control)
foreach ($data in $registryData) {
    $data.Image = 'C:\Test\ShellTests.exe'
    $kind = if ($data.EventType -eq 'CreateKey') { 12 } else { 13 }
    $app = New-BehaviorEvent $kind $data
    $other = $data.Clone()
    $other.Image = 'C:\Test\WindowsShellControl.exe'
    $other.TargetObject = $other.TargetObject.Replace('ShellTests.exe','WindowsShellControl.exe')
    $observed = @($control) + (New-BehaviorEvent $kind $other)
    $allControls += New-BehaviorEvent $kind $other
    $cases += @{Events=@($baseline) + $app; Control=$observed; Error=''}
    $cases += @{Events=@($baseline) + $app; Error='Unexpected application behavior detected.'}
    foreach ($change in @(@{EventType='DeleteKey'}, @{TargetObject=($data.TargetObject + 'Other')}, @{Details='DWORD (0x00000002)'})) {
        $bad = $data.Clone()
        foreach ($key in $change.Keys) { $bad[$key] = $change[$key] }
        $cases += @{Events=@($baseline) + (New-BehaviorEvent $kind $bad); Control=$observed; Error='Unexpected application behavior detected.'}
    }
    $cases += @{Events=@($baseline) + (New-BehaviorEvent 14 $data); Control=$observed; Error='Unexpected application behavior detected.'}
}
$cases += @{Events=$baseline; Control=@(); Error='Missing Windows-only control telemetry.'}
$cases += @{Events=$baseline; Control=@($control | Where-Object Id -ne 7); Error='Missing Windows-only control telemetry.'}
$cases += @{Events=$baseline; Control=@($control) + (New-BehaviorEvent 7 @{Image='C:\Test\WindowsShellControl.exe'; ImageLoaded='C:\Test\OpenHashTab.dll'}); Error='Control loaded a non-Windows DLL.'}
$cases += @{Events=$baseline; Control=@($control) + (New-BehaviorEvent 3 @{Image='C:\Test\WindowsShellControl.exe'}); Error='Unexpected control behavior.'}
$cases += @{Events=$baseline; Control=@($control) + (New-BehaviorEvent 1 @{Image='C:\Windows\cmd.exe'; ParentImage='C:\Test\WindowsShellControl.exe'}); Error='Unexpected control process.'}
$cases += @{Events=$baseline; Control=@($control | ConvertTo-Json -Depth 4 | ConvertFrom-Json); Error=''}
foreach ($data in @(
    @{Image='D:\Test\ShellTests.exe'; EventType='SetValue'; TargetObject=$registryData[0].TargetObject; Details='Binary Data'},
    @{Image='C:\Test\ShellTests.exe'; EventType='SetValue'; TargetObject=$registryData[0].TargetObject.Replace('HarddiskVolume3','HarddiskVolume4'); Details='Binary Data'},
    @{Image='C:\Other\ShellTests.exe'; EventType='SetValue'; TargetObject=$registryData[0].TargetObject; Details='Binary Data'},
    @{Image='C:\Test\CoreTests.exe'; EventType='SetValue'; TargetObject=$registryData[1].TargetObject; Details='Binary Data'},
    @{Image='C:\Test\ShellTests.exe'; EventType='SetValue'; TargetObject='HKCU\Unrelated\Software\OpenHashTab\Setting'; Details='Binary Data'}
)) {
    $cases += @{Events=@($baseline) + (New-BehaviorEvent 13 $data); Control=$allControls; Error='Unexpected application behavior detected.'}
}
$cases += @{Events=@($baseline) + (New-BehaviorEvent 14 @{Image='C:\Test\CoreTests.exe'; TargetObject='HKCU\Software\OpenHashTab\Setting'; NewName='HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bad'}); Error='Unexpected application behavior detected.'}
# Windows may choose different WIL device-usage buckets for successive GUI processes.
foreach ($pair in @(@(1,2), @(2,1))) {
    $app = $registryData[$pair[0]].Clone()
    $other = $registryData[$pair[1]].Clone()
    $other.Image = 'C:\Test\WindowsShellControl.exe'
    $observed = @($control) + (New-BehaviorEvent 13 $other)
    $cases += @{Events=@($baseline) + (New-BehaviorEvent 13 $app); Control=$observed; Error=''}
    foreach ($change in @(
        @{TargetObject=$app.TargetObject.Substring(0, $app.TargetObject.Length - 4) + '2C75'},
        @{Details='DWORD (0x00000001)'}, @{Image='C:\Test\StandaloneStub.exe'}
    )) {
        $bad = $app.Clone()
        foreach ($key in $change.Keys) { $bad[$key] = $change[$key] }
        $cases += @{Events=@($baseline) + (New-BehaviorEvent 13 $bad); Control=$observed; Error='Unexpected application behavior detected.'}
    }
    $other.Details = 'DWORD (0x00000001)'
    $cases += @{Events=@($baseline) + (New-BehaviorEvent 13 $app); Control=@($control) + (New-BehaviorEvent 13 $other); Error='Unexpected application behavior detected.'}
}
# Round-trip the on-disk JSONL format used across a VM reboot, including PS 5.1.
$snapshot = [IO.Path]::GetTempFileName()
try {
    $control | Select-Object Id,Xml | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress } |
        Set-Content $snapshot -Encoding utf8
    $restored = @(Read-BehaviorSnapshot $snapshot)
    if ($restored.Count -ne $control.Count) { throw 'Persisted snapshot changed its event count.' }
    $cases += @{Events=$baseline; Control=$restored; Error=''}
    foreach ($invalid in @('{"Id":1}', '{"Id":"1","Xml":"x"}', '[{"Id":1,"Xml":"x"},{"Id":7,"Xml":"x"}]')) {
        Set-Content $snapshot $invalid -Encoding utf8
        $failure = $null
        try { $null = Read-BehaviorSnapshot $snapshot } catch { $failure = $_.Exception.Message }
        if ($failure -ne 'Invalid control snapshot event.') { throw 'Malformed snapshot was not rejected.' }
    }
} finally { Remove-Item $snapshot }
foreach ($case in $cases) {
    $failure = $null
    try {
        $observed = if ($case.ContainsKey('Control')) { @($case.Control) } else { $control }
        $counts = Get-VerifiedBehaviorCounts -Events $case.Events -ControlEvents $observed
        foreach ($key in $counts.Keys) {
            if ($key -isnot [string]) { throw 'Event counts require string keys for Windows PowerShell JSON.' }
        }
        $json = $counts | ConvertTo-Json -Compress
        $decoded = $json | ConvertFrom-Json
        if ($decoded.'1' -ne 4 -or $decoded.'13' -ne @($case.Events | Where-Object { $_.Id -eq 13 -and $_.Data.Image -match '\\(CoreTests|EncodingTests|ShellTests|StandaloneStub)\.exe$' }).Count) { throw 'Event counts changed during JSON serialization.' }
    } catch { $failure = $_.Exception.Message }
    if ($case.Error) {
        if (-not $failure -or -not $failure.StartsWith($case.Error)) {
            throw "Expected '$($case.Error)', received '$failure'."
        }
    } elseif ($failure) { throw $failure }
}
Write-Host "PASS: $($cases.Count) Sysmon behavior and JSON serialization cases."
# Replay uses actual saved fields, without inventing process/network control events.
$savedControl = @{Id=13; Image='C:\Test\WindowsShellControl.exe'; Target=$registryData[1].TargetObject; Type='SetValue'; Details='Binary Data'}
$savedApp = @{Id=13; Image='C:\Test\ShellTests.exe'; Target=$registryData[2].TargetObject; Type='SetValue'; Details='Binary Data'}
$replays = @(
    @{control=@($savedControl); registry=@($savedApp)}
    @{control=@(); registry=@($savedApp)}
    @{control=@($savedControl); registry=@()}
)
foreach ($change in @(@{Target='HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bad'}, @{Id=14})) {
    $bad = $savedApp.Clone()
    foreach ($key in $change.Keys) { $bad[$key] = $change[$key] }
    $replays += @{control=@($savedControl); registry=@($bad)}
}
$snapshot = [IO.Path]::GetTempFileName()
try {
    for ($i = 0; $i -lt $replays.Count; $i++) {
        ConvertTo-Json -InputObject $replays[$i] -Depth 5 | Set-Content $snapshot -Encoding utf8
        $failed = $false
        try { & "$PSScriptRoot/../automation/Test-ReusedRegistry.ps1" -Evidence $snapshot } catch { $failed = $true }
        if ($failed -ne ($i -ne 0)) { throw "Incorrect saved-registry replay verdict: $i" }
    }
} finally { Remove-Item $snapshot }
Write-Host "PASS: $($replays.Count) saved-registry replay cases."
