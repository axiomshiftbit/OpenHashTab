# Validate captured Sysmon events separately from collection and VM setup.
function Get-VerifiedBehaviorCounts {
    param([object[]]$Events)
    $images = '\\(CoreTests|EncodingTests|ShellTests|StandaloneStub)\.exe$'
    $counts = @{}
    $processes = @{}
    $networkControl = $false
    $dnsControl = $false
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = [string]$item.'#text' }
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
        if ($event.Id -in @(12,13,14) -and $data.TargetObject -notmatch '\\Software\\OpenHashTab(?:\\|$)') {
            $failures.Add("Unexpected registry write: $($data.TargetObject) from $source")
        }
    }
    foreach ($name in @('CoreTests.exe', 'EncodingTests.exe', 'ShellTests.exe', 'StandaloneStub.exe')) {
        if (-not $processes.ContainsKey($name)) { throw "Missing process telemetry: $name" }
    }
    if (-not $networkControl -or -not $dnsControl) { throw 'Network/DNS telemetry positive control failed.' }
    if ($failures.Count) { $failures | Write-Host; throw 'Unexpected application behavior detected.' }
    return $counts
}
