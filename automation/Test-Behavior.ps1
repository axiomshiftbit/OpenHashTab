[CmdletBinding()]
param([ValidateSet('Start', 'Verify')][string]$Stage)
$ErrorActionPreference = 'Stop'
if ($env:OHT_DISPOSABLE_VM -notlike 'windows-11-*') { throw 'A disposable Windows VM is required.' }
$root = Split-Path $PSScriptRoot
$directory = Join-Path $root 'security-tools'
$log = 'Microsoft-Windows-Sysmon/Operational'
. "$PSScriptRoot\DefenderScan.ps1"
. "$PSScriptRoot\BehaviorEvents.ps1"
if ($Stage -eq 'Start') {
    $null = New-Item -ItemType Directory $directory -Force
    $zip = Join-Path $directory 'Sysmon.zip'
    Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne '00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54') {
        throw 'Sysmon download changed; review the new Microsoft release before updating its pin.'
    }
    Expand-Archive $zip $directory -Force
    $executable = Join-Path $directory 'Sysmon64.exe'
    $signature = Get-AuthenticodeSignature $executable
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'Sysmon must have a valid Microsoft signature.'
    }
    # Limit collection to the program/test processes and telemetry controls so
    # normal Windows background activity cannot rotate away the evidence.
    $rules = ''
    foreach ($eventName in @('ProcessCreate','NetworkConnect','ImageLoad','CreateRemoteThread','RawAccessRead','FileCreate','RegistryEvent','DnsQuery')) {
        $field = if ($eventName -eq 'CreateRemoteThread') { 'SourceImage' } else { 'Image' }
        $filters = ''
        foreach ($name in @('CoreTests.exe','EncodingTests.exe','ShellTests.exe','StandaloneStub.exe','WindowsShellControl.exe')) {
            $filters += "<$field condition=`"end with`">\$name</$field>"
            if ($eventName -eq 'ProcessCreate') { $filters += "<ParentImage condition=`"end with`">\$name</ParentImage>" }
        }
        if ($eventName -in @('NetworkConnect','DnsQuery')) { $filters += '<Image condition="end with">\powershell.exe</Image>' }
        $rules += "<RuleGroup groupRelation=`"or`"><$eventName onmatch=`"include`">$filters</$eventName></RuleGroup>"
    }
    "<Sysmon schemaversion=`"4.82`"><HashAlgorithms>sha256</HashAlgorithms><EventFiltering>$rules</EventFiltering></Sysmon>" |
        Set-Content "$directory\sysmon.xml" -Encoding utf8
    & $executable -accepteula -i "$directory\sysmon.xml"
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon installation failed.' }
    (Get-Service Sysmon64) | Format-Table Name, Status
    # Positive controls prove that network/DNS monitoring is actually active.
    Resolve-DnsName www.microsoft.com -DnsOnly | Out-Null
    $connection = New-Object Net.Sockets.TcpClient
    try { $connection.Connect('www.microsoft.com', 443) } finally { $connection.Dispose() }

    # Run a renamed test executable before any project DLL is installed. Its
    # separate mode only calls Windows APIs; freeze these events before the tests.
    $control = Join-Path $directory 'WindowsShellControl.exe'
    $controlSource = "$root\binaries\control\WindowsShellControl.exe"
    if (-not (Test-Path $controlSource)) { $controlSource = "$root\binaries\oht-x64\Tests\ShellTests.exe" }
    Copy-Item $controlSource $control
    & $control --windows-control
    if ($LASTEXITCODE -ne 0) { throw 'Windows-only shell control failed.' }
    Start-Sleep -Seconds 5
    $controlEvents = @(Get-WinEvent -LogName $log | Where-Object {
        $data = Get-BehaviorEventData $_
        $data.Image -like '*\WindowsShellControl.exe' -or $data.SourceImage -like '*\WindowsShellControl.exe' -or
            $data.ParentImage -like '*\WindowsShellControl.exe'
    } | ForEach-Object { [pscustomobject]@{ Id=$_.Id; Xml=$_.ToXml() } })
    $controlEvents | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 3 -Compress } |
        Set-Content "$directory\control-events.jsonl" -Encoding utf8
    # Check the actual persisted format now, before an expensive lifecycle/reboot.
    $restored = @(Read-BehaviorSnapshot "$directory\control-events.jsonl")
    if ($restored.Count -ne $controlEvents.Count) { throw 'Control snapshot lost events.' }
    $null = Get-WindowsControlSignatures $restored
    $controlRegistry = @($restored | Where-Object Id -in @(12,13,14) | ForEach-Object {
        $data = Get-BehaviorEventData $_
        [pscustomobject]@{ Id=$_.Id; Image=$data.Image; Target=$data.TargetObject; Type=$data.EventType; Details=$data.Details }
    })
    Write-Host "Frozen control registry: $(ConvertTo-Json -InputObject $controlRegistry -Compress)"
    Write-Host "Captured $($controlEvents.Count) events from the Windows-only control."

    Update-MpSignature
    $status = Get-MpComputerStatus
    $status | Select-Object AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AntivirusEnabled | Format-List
    if (-not $status.AntivirusEnabled -or $status.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-3)) {
        throw 'Defender must be enabled and have current signatures.'
    }
    $defenderLog = 'Microsoft-Windows-Windows Defender/Operational'
    $lastRecord = (Get-WinEvent -LogName $defenderLog -MaxEvents 1).RecordId
    Start-MpScan -ScanType CustomScan -ScanPath $root
    # Defender and its event log complete asynchronously. Require the start
    # event for this directory and a completion with the same Scan ID.
    $deadline = (Get-Date).AddMinutes(10)
    $completed = $false
    do {
        $events = @(Get-WinEvent -LogName $defenderLog -FilterXPath "*[System[(EventID=1000 or EventID=1001 or EventID=1002) and EventRecordID > $lastRecord]]" -ErrorAction SilentlyContinue |
            Sort-Object RecordId)
        $state = Get-CandidateScanState -Events $events -Directory $root
        if ($state -eq 'Cancelled') { throw 'Defender cancelled the candidate scan.' }
        $completed = $state -eq 'Completed'
        if (-not $completed) { Start-Sleep -Seconds 2 }
    } until ($completed -or (Get-Date) -ge $deadline)
    $events | Format-List Id, RecordId, Message
    if (-not $completed) { throw 'Defender did not record a completed scan of the candidate directory within ten minutes.' }
    if (@(Get-MpThreatDetection).Count -gt 0) { throw 'Defender reported a threat in this clean test VM.' }
    Write-Host 'PASS: Defender scanned the candidate files with current signatures.'
    return
}

Start-Sleep -Seconds 5
$events = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=1,3,7,8,9,11,12,13,14,22})
$controls = @(Read-BehaviorSnapshot "$directory\control-events.jsonl")
# Preserve reviewed registry operations and values in test output even if the
# admission check rejects one. Binary payload bytes are not exposed by Sysmon.
$registry = @(@($controls) + $events | Where-Object Id -in @(12,13,14) | ForEach-Object {
    $data = Get-BehaviorEventData $_
    [pscustomobject]@{ Id=$_.Id; Image=$data.Image; Target=$data.TargetObject; Type=$data.EventType; Details=$data.Details }
} | Sort-Object Image,Target,Id,Type,Details -Unique)
Write-Host "Registry telemetry: $(ConvertTo-Json -InputObject $registry -Depth 3 -Compress)"
$counts = Get-VerifiedBehaviorCounts -Events $events -ControlEvents $controls
Write-Host "Observed application event counts: $($counts | ConvertTo-Json -Compress)"
Write-Host 'PASS: tested offline hashing and installer lifecycle produced no application network, DNS, child-process, raw-disk or remote-thread events.'
& "$directory\Sysmon64.exe" -u
if ($LASTEXITCODE -ne 0) { throw 'Sysmon cleanup failed.' }
