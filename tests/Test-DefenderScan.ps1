$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../automation/DefenderScan.ps1"
function New-Event($Record, $Kind, $ScanId, $Resources = '') {
    $event = [pscustomobject]@{RecordId=$Record; Id=$Kind; Xml="<Event><EventData><Data Name='Scan ID'>$ScanId</Data><Data Name='Scan Resources'>$Resources</Data></EventData></Event>"}
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    return $event
}
$start = New-Event 1 1000 A 'C:\Candidate\'
$end = New-Event 4 1001 A
$otherStart = New-Event 2 1000 B 'C:\Other'
$otherEnd = New-Event 3 1001 B
$cancel = New-Event 5 1002 A
$cases = @(
    @{Events=@(); Expected='Pending'},
    @{Events=@($start); Expected='Pending'},
    @{Events=@($end); Expected='Pending'},
    @{Events=@($start,$otherEnd); Expected='Pending'},
    @{Events=@($otherStart,$otherEnd); Expected='Pending'},
    @{Events=@($start,$end); Expected='Completed'},
    @{Events=@($end,$otherEnd,$otherStart,$start); Expected='Completed'},
    @{Events=@($start,$cancel); Expected='Cancelled'},
    @{Events=@($start,$end,$cancel); Expected='Cancelled'},
    @{Events=@((New-Event 1 1000 A),$end); Expected='Pending'},
    @{Events=@((New-Event 1 1000 '' 'C:\Candidate'),(New-Event 2 1001 '')); Expected='Pending'},
    @{Events=@((New-Event 1 1000 A 'folder:_C:\Candidate'),$end); Expected='Completed'},
    @{Events=@((New-Event 1 1000 A 'FOLDER:_c:\candidate\'),$end); Expected='Completed'},
    @{Events=@((New-Event 1 1000 A 'folder:_C:\Other'),$end); Expected='Pending'},
    @{Events=@((New-Event 1 1000 A 'folder:_C:\Candidate\Child'),$end); Expected='Pending'},
    @{Events=@((New-Event 1 1000 A 'file:_C:\Candidate'),$end); Expected='Pending'}
)
foreach ($case in $cases) {
    $state = Get-CandidateScanState -Events $case.Events -Directory 'C:\Candidate'
    if ($state -ne $case.Expected) { throw "Expected $($case.Expected), got $state" }
}
Write-Host "PASS: $($cases.Count) Defender scan event cases."
