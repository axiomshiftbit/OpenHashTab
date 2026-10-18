param([Parameter(Mandatory=$true)][string]$Evidence)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/BehaviorEvents.ps1"
$saved = Get-Content -Raw -LiteralPath $Evidence | ConvertFrom-Json
$controls = @{}
foreach ($event in $saved.control) {
    if ($event.Image -notmatch '\\WindowsShellControl\.exe$') { throw 'Unexpected saved control image.' }
    $signature = Get-WindowsRegistrySignature $event.Id @{
        Image=$event.Image; TargetObject=$event.Target; EventType=$event.Type; Details=$event.Details
    }
    if ($signature) { $controls[$signature] = $true }
}
$checked = 0
foreach ($event in $saved.registry) {
    if ($event.Image -notmatch '\\(CoreTests|EncodingTests|ExtendedHashTests|ReportTests|BatchTests|OpenHashTabCLI|ShellTests|StandaloneStub)\.exe$') { continue }
    $signature = Get-WindowsRegistrySignature $event.Id @{
        Image=$event.Image; TargetObject=$event.Target; EventType=$event.Type; Details=$event.Details
    }
    if (-not $signature -or -not $controls.ContainsKey($signature)) {
        throw "Saved application registry event failed the current classifier: $($event.Target)"
    }
    $checked++
}
if (-not $checked) { throw 'No saved application registry events.' }
Write-Host "PASS: $checked actual saved registry records match the current policy and their frozen control."
