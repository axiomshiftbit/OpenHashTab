param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
$directory = Join-Path ([IO.Path]::GetTempPath()) ('OpenHashTab-cli-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory $directory
$utf8 = New-Object Text.UTF8Encoding($false, $true)
function Invoke-CLI([string[]]$Arguments, [int]$ExpectedCode = 0) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    # These fixtures never contain a quote or a trailing backslash.
    $start.Arguments = ($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $start.WorkingDirectory = $directory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'CLI timed out.' }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne $ExpectedCode) {
            throw "CLI exit $($process.ExitCode), expected ${ExpectedCode}: $output $errorOutput"
        }
        return $output
    } finally { $process.Dispose() }
}
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
try {
    $names = @((Invoke-CLI @('algorithms')).Trim() -split '\r?\n')
    Assert ($names.Count -eq 61) 'Incomplete algorithm catalog.'
    $name = ([string][char]0x0444) + ' file.bin'
    $file = Join-Path $directory $name
    [IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes('abc'))
    $digest = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
    $hash = Invoke-CLI @('hash', '--progress', $file) | ConvertFrom-Json
    Assert ($hash.schema_version -eq 1 -and $hash.results.Count -eq 1) 'Invalid JSON schema.'
    $row = $hash.results[0]
    Assert ($row.path -ceq $file -and $row.algorithm -ceq 'SHA-256' -and $row.actual -ceq $digest -and $row.status -eq 'computed') 'Incorrect UTF-8 path or hash.'
    $manifest = Join-Path $directory 'check.sha256'
    [IO.File]::WriteAllText($manifest, "$digest *$name`n", $utf8)
    $verified = Invoke-CLI @('verify', $manifest) | ConvertFrom-Json
    Assert ($verified.results[0].status -eq 'match' -and $verified.results[0].expected -ceq $digest) 'Verification did not match.'
    [IO.File]::WriteAllText($manifest, (('0' * 64) + " *$name`n"), $utf8)
    $verified = Invoke-CLI @('verify', $manifest) 1 | ConvertFrom-Json
    Assert ($verified.results[0].status -eq 'mismatch') 'Mismatch did not propagate.'
    [IO.File]::WriteAllText($manifest, "$digest *absent.bin`n", $utf8)
    $verified = Invoke-CLI @('verify', $manifest) 3 | ConvertFrom-Json
    Assert ($verified.results[0].status -eq 'error' -and $verified.results[0].expected -ceq $digest -and -not $verified.results[0].actual -and $verified.results[0].error) 'Read error lost its expected hash.'
    $null = Invoke-CLI @('hash', '--algorithm', 'not-a-hash', $file) 2
    $left = Join-Path $directory 'left'; $right = Join-Path $directory 'right'
    $null = New-Item -ItemType Directory $left, $right
    foreach ($folder in @($left, $right)) {
        [IO.File]::WriteAllText((Join-Path $folder 'same.bin'), 'abc', $utf8)
        $null = New-Item -ItemType Directory (Join-Path $folder 'empty')
    }
    [IO.File]::WriteAllText((Join-Path $left 'different.bin'), 'a', $utf8)
    [IO.File]::WriteAllText((Join-Path $right 'different.bin'), 'b', $utf8)
    [IO.File]::WriteAllText((Join-Path $left '=formula.bin'), 'abc', $utf8)
    [IO.File]::WriteAllText((Join-Path $right 'right-only.bin'), 'abc', $utf8)
    $comparison = Invoke-CLI @('compare', $left, $right) 1 | ConvertFrom-Json
    foreach ($case in @(@('same.bin','match'), @('empty/','match'), @('different.bin','mismatch'), @('=formula.bin','missing_right'), @('right-only.bin','missing_left'))) {
        $rows = @($comparison.results | Where-Object path -CEQ $case[0])
        Assert ($rows.Count -eq 1 -and $rows[0].status -ceq $case[1]) "Comparison failed: $($case[0])"
    }
    $csv = @(Invoke-CLI @('compare', '--format', 'csv', $left, $right) 1 | ConvertFrom-Csv)
    Assert (@($csv | Where-Object path -CEQ "'=formula.bin").Count -eq 1) 'CSV formula protection is absent.'
    $same = Invoke-CLI @('compare', $file, $file) | ConvertFrom-Json
    Assert ($same.results[0].status -eq 'match' -and $same.results[0].expected -ceq $digest -and $same.results[0].actual -ceq $digest) 'File comparison failed.'
    Write-Host 'PASS: CLI Unicode, JSON/CSV, hashing, verification, file/folder comparison, errors and exit codes.'
} finally { Remove-Item -LiteralPath $directory -Recurse -Force }
