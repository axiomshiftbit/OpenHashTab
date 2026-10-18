# Match documented Defender events by Scan ID, not a localized message.
# https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus
function Get-CandidateScanState {
    param([object[]]$Events, [string]$Directory)
    $ids = @{}
    $state = 'Pending'
    foreach ($event in ($Events | Sort-Object RecordId)) {
        [xml]$xml = $event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = [string]$item.'#text' }
        $id = $data['Scan ID']
        $resources = [string]$data['Scan Resources']
        # Current Defender identifies a custom directory scan as folder:_PATH.
        # Strip only that resource type; a file:_ scan does not cover a folder.
        if ($resources.StartsWith('folder:_', [StringComparison]::OrdinalIgnoreCase)) {
            $resources = $resources.Substring(8)
        }
        if ($event.Id -eq 1000 -and $id -and $resources.TrimEnd('\') -eq $Directory.TrimEnd('\')) {
            $ids[$id] = $true
        }
        if ($id -and $ids.ContainsKey($id)) {
            if ($event.Id -eq 1002) { return 'Cancelled' }
            if ($event.Id -eq 1001) { $state = 'Completed' }
        }
    }
    return $state
}
