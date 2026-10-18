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
    New-BehaviorEvent 13 @{Image='C:\Test\StandaloneStub.exe'; TargetObject='HKU\S-1-5-21\Software\OpenHashTab\Setting'}
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
foreach ($case in $cases) {
    $failure = $null
    try {
        $counts = Get-VerifiedBehaviorCounts -Events $case.Events
        foreach ($key in $counts.Keys) {
            if ($key -isnot [string]) { throw 'Event counts require string keys for Windows PowerShell JSON.' }
        }
        $json = $counts | ConvertTo-Json -Compress
        $decoded = $json | ConvertFrom-Json
        if ($decoded.'1' -ne 4 -or $decoded.'13' -ne 1) { throw 'Event counts changed during JSON serialization.' }
    } catch { $failure = $_.Exception.Message }
    if ($case.Error) {
        if (-not $failure -or -not $failure.StartsWith($case.Error)) {
            throw "Expected '$($case.Error)', received '$failure'."
        }
    } elseif ($failure) { throw $failure }
}
Write-Host "PASS: $($cases.Count) Sysmon behavior and JSON serialization cases."
