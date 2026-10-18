# Validate captured Sysmon events separately from collection and VM setup.
function Read-BehaviorSnapshot([string]$Path) {
    # One object per line avoids Windows PowerShell 5.1's non-enumerating JSON arrays.
    Get-Content -LiteralPath $Path | ForEach-Object {
        $event = ConvertFrom-Json -InputObject $_
        if ($event.Xml -isnot [string] -or -not $event.Xml -or ($event.Id -isnot [int] -and $event.Id -isnot [long])) { throw 'Invalid control snapshot event.' }
        $event
    }
}

function Get-BehaviorEventData($Event) {
    [xml]$xml = if ($Event.PSObject.Properties['Xml']) { $Event.Xml } else { $Event.ToXml() }
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = [string]$item.'#text' }
    return $data
}

function Get-WindowsRegistrySignature([int]$Kind, [hashtable]$Data) {
    # Only these finite Windows side effects may be compared to the independent
    # control. No deletion/rename, arbitrary value or entire Windows subtree is exempt.
    $target = $Data.TargetObject
    $sid = 'S-1-5-21-\d+-\d+-\d+-\d+'
    if ($Kind -eq 13 -and $Data.EventType -eq 'SetValue' -and
        $target -match "^HKLM\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\$sid\\\\Device\\(?<volume>HarddiskVolume\d+)(?<path>\\.+)$") {
        $path = $Matches.path
        $volume = $Matches.volume
        if ($Data.Image -notmatch '^C:\\' -or $path -ne $Data.Image.Substring(2)) { return '' }
        $target = 'BAM:' + $volume + ':own-image'
    } elseif ($Data.Image -match '\\(ShellTests|WindowsShellControl)\.exe$' -and
        $Kind -eq 13 -and $Data.EventType -eq 'SetValue' -and
        $target -in @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC1C75',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC2475')) {
        # Windows notification state is accepted only if the control wrote this exact value.
    } elseif ($Data.Image -match '\\(ShellTests|WindowsShellControl)\.exe$' -and
        $target -match "^HKU\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap(?<value>\\(?:AutoDetect|UNCAsIntranet|IntranetName|ProxyBypass))?$") {
        $value = $Matches.value
        if (-not (($Kind -eq 12 -and $Data.EventType -eq 'CreateKey' -and -not $value) -or
            ($Kind -eq 13 -and $Data.EventType -eq 'SetValue' -and $value -and $Data.Details -match '^DWORD \(0x0000000[01]\)$'))) { return '' }
        $target = 'ZoneMap' + $value
    } else { return '' }
    # Sysmon exposes DWORD values, but reports binary values as 'Binary Data'.
    # Matching this signature does not prove equality of binary payload bytes.
    return "$Kind|$($Data.EventType)|$target|$($Data.Details)"
}

function Get-WindowsControlSignatures([object[]]$Events) {
    $controls = @{}
    $controlStarted = $false
    $controlLoaded = $false
    foreach ($event in $Events) {
        $data = Get-BehaviorEventData $event
        if ($data.Image -notmatch '\\WindowsShellControl\.exe$') { throw 'Unexpected control process.' }
        if ($event.Id -eq 1) { $controlStarted = $true }
        if ($event.Id -eq 7 -and $data.ImageLoaded -match '\.dll$') {
            if ($data.ImageLoaded -notmatch '^C:\\Windows\\') { throw 'Control loaded a non-Windows DLL.' }
            $controlLoaded = $true
        }
        if ($event.Id -in @(3,8,9,22)) { throw 'Unexpected control behavior.' }
        $signature = Get-WindowsRegistrySignature $event.Id $data
        if ($signature) { $controls[$signature] = $true }
    }
    if (-not $controlStarted -or -not $controlLoaded) { throw 'Missing Windows-only control telemetry.' }
    return $controls
}

function Get-VerifiedBehaviorCounts {
    param([object[]]$Events, [object[]]$ControlEvents)
    $images = '\\(CoreTests|EncodingTests|ShellTests|StandaloneStub)\.exe$'
    $controls = Get-WindowsControlSignatures $ControlEvents
    $ownRegistry = '^HK(U\\S-1-5-21-\d+-\d+-\d+-\d+|CU|LM)\\Software\\OpenHashTab(?:\\|$)'
    $counts = @{}
    $processes = @{}
    $networkControl = $false
    $dnsControl = $false
    $failures = [Collections.Generic.List[string]]::new()
    $matched = @{}
    foreach ($event in $events) {
        $data = Get-BehaviorEventData $event
        if ($data.Image -like '*\powershell.exe') {
            if ($event.Id -eq 3 -and $data.DestinationPort -eq '443') { $networkControl = $true }
            if ($event.Id -eq 22 -and $data.QueryName -eq 'www.microsoft.com') { $dnsControl = $true }
        }
        if ($event.Id -eq 1 -and $data.ParentImage -match $images) {
            $failures.Add("Unexpected child process: $($data.Image), parent $($data.ParentImage)")
        }
        $source = if ($event.Id -eq 8) { $data.SourceImage } else { $data.Image }
        if ($source -notmatch $images) { continue }
        # ConvertTo-Json requires string dictionary keys in Windows PowerShell.
        $counts[[string]$event.Id] = 1 + $counts[[string]$event.Id]
        # Sysmon paths use Windows separators even when unit tests run on Linux.
        if ($event.Id -eq 1) { $processes[$source.Substring($source.LastIndexOf('\') + 1)] = $true }
        if ($event.Id -in @(3,8,9,22)) { $failures.Add("Unexpected event $($event.Id) from $source") }
        $ownWrite = $data.TargetObject -match $ownRegistry
        if ($event.Id -eq 14) { $ownWrite = $ownWrite -and $data.NewName -match $ownRegistry }
        if ($event.Id -in @(12,13,14) -and -not $ownWrite) {
            $signature = Get-WindowsRegistrySignature $event.Id $data
            if ($signature -and $controls.ContainsKey($signature)) { $matched[$signature] = 1 + $matched[$signature] }
            else { $failures.Add("Unexpected registry write: $($data.TargetObject) from $source; $($data.EventType); $($data.Details)") }
        }
    }
    foreach ($name in @('CoreTests.exe', 'EncodingTests.exe', 'ShellTests.exe', 'StandaloneStub.exe')) {
        if (-not $processes.ContainsKey($name)) { throw "Missing process telemetry: $name" }
    }
    if (-not $networkControl -or -not $dnsControl) { throw 'Network/DNS telemetry positive control failed.' }
    Write-Host "Registry events matching the Windows-only control: $($matched | ConvertTo-Json -Compress)"
    if ($failures.Count) { $failures | Write-Host; throw 'Unexpected application behavior detected.' }
    return $counts
}
