[CmdletBinding()]
param(
    [ValidateSet('BeforeReboot', 'AfterReboot', 'All')][string]$Stage = 'All',
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64'
)
$ErrorActionPreference = 'Stop'
if ($env:OHT_DISPOSABLE_VM -notlike 'windows-11-*' -and
    -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Installer tests are restricted to disposable test machines.'
}
$root = Split-Path $PSScriptRoot
$version = (Get-Content "$root\VERSION" -Raw).Trim()
$installer = New-Object -ComObject WindowsInstaller.Installer
$logDirectory = Join-Path $root 'msi-logs'
$null = New-Item -ItemType Directory $logDirectory -Force
$clsid = '{23B5BDD4-7669-42B8-9CDC-BEEBC8A5BAA9}'
function Read-MsiProperty([string]$Path, [string]$Name) {
    $db = $installer.OpenDatabase($Path, 0)
    $view = $db.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$Name'")
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw "Missing MSI property: $Name" }
    $value = $record.StringData(1)
    $view.Close()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
    return $value
}
function Run-Msi([string]$Arguments, [string]$Name, [int[]]$Expected = @(0, 3010)) {
    $log = Join-Path $logDirectory "$Name.log"
    $process = Start-Process msiexec.exe -ArgumentList "$Arguments /qn /norestart /l*v `"$log`"" -PassThru
    if (-not $process.WaitForExit(180000)) { $process.Kill(); throw "MSI timeout: $Name" }
    if ($process.ExitCode -notin $Expected) {
        Get-Content $log -Tail 70 | Write-Host
        throw "MSI $Name failed: $($process.ExitCode)"
    }
    Write-Host "PASS: MSI $Name ($($process.ExitCode))"
}
function Assert-Installed([string]$Scope, [string]$Product) {
    if ($installer.ProductState($Product) -ne 5) { throw "Product is not installed: $Scope" }
    $hive = if ($Scope -eq 'Machine') { 'Registry::HKEY_LOCAL_MACHINE' } else { 'Registry::HKEY_CURRENT_USER' }
    $key = "$hive\Software\Classes\CLSID\$clsid\InprocServer32"
    if (-not (Test-Path $key)) { throw "COM registration missing: $key" }
    $dll = (Get-Item $key).GetValue('')
    if (-not (Test-Path $dll)) { throw "Registered DLL missing: $dll" }
    if ((Get-Item $dll).VersionInfo.FileVersion -notlike "$version*") { throw 'Installed binary version differs from VERSION.' }
    $directory = Split-Path $dll
    Copy-Item "$root\binaries\oht-$Architecture\Tests\ShellTests.exe" "$logDirectory\ShellTests.exe" -Force
    & "$logDirectory\ShellTests.exe" "$dll"
    if ($LASTEXITCODE -ne 0) { throw 'Registered shell extension tests failed.' }
    $sample = Join-Path $logDirectory 'sample with spaces.txt'
    [IO.File]::WriteAllText($sample, 'abc')
    $process = Start-Process (Join-Path $directory 'StandaloneStub.exe') -ArgumentList "`"$sample`"" -PassThru
    $opened = $false
    for ($i = 0; $i -lt 100; ++$i) {
        if ($process.HasExited) { throw "Standalone exited before opening a window ($($process.ExitCode))." }
        $process.Refresh()
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) { $opened = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $opened) { $process.Kill(); throw 'Standalone did not create a window.' }
    Start-Sleep -Milliseconds 500
    [void]$process.CloseMainWindow()
    if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Standalone did not close cleanly.' }
    if ($process.ExitCode -ne 0) { throw "Standalone failed: $($process.ExitCode)" }
    Write-Host "PASS: $Scope registration and standalone launch"
    return $directory
}
function Assert-Removed([string]$Product) {
    if ($installer.ProductState($Product) -eq 5) { throw "Product remains installed: $Product" }
}
foreach ($scope in @('Machine', 'User')) {
    $package = (Get-Item "$root\installers\OpenHashTab_${scope}_${Architecture}.msi").FullName
    $product = Read-MsiProperty $package 'ProductCode'
    if ((Read-MsiProperty $package 'ProductVersion') -ne $version) { throw 'MSI version differs from VERSION.' }
    if ($Stage -eq 'AfterReboot') {
        if ($scope -eq 'Machine') {
            $null = Assert-Installed $scope $product
            Run-Msi "/x $product" 'machine-uninstall-after-reboot'
            Assert-Removed $product
        }
        continue
    }
    $oldPackage = (Get-Item "$root\baseline\OpenHashTab_${scope}_${Architecture}.msi").FullName
    $oldProduct = Read-MsiProperty $oldPackage 'ProductCode'
    Run-Msi "/i `"$oldPackage`"" "$scope-baseline"
    if ($installer.ProductState($oldProduct) -ne 5) { throw 'Previous MSI did not install.' }
    Run-Msi "/i `"$package`"" "$scope-upgrade"
    Assert-Removed $oldProduct
    $directory = Assert-Installed $scope $product
    Run-Msi "/i `"$package`"" "$scope-repeat"
    $null = Assert-Installed $scope $product
    $stub = Join-Path $directory 'StandaloneStub.exe'
    Remove-Item $stub
    Run-Msi "/fa $product" "$scope-repair"
    if (-not (Test-Path $stub)) { throw 'Repair did not restore the deleted executable.' }
    $null = Assert-Installed $scope $product
    Run-Msi "/i `"$oldPackage`"" "$scope-downgrade-rejected" @(1603)
    $null = Assert-Installed $scope $product
    Run-Msi "/x $product" "$scope-uninstall"
    Assert-Removed $product
    if (Test-Path $stub) { throw 'Uninstall left the application executable behind.' }
}
if ($Stage -eq 'BeforeReboot') {
    $package = (Get-Item "$root\installers\OpenHashTab_Machine_${Architecture}.msi").FullName
    Run-Msi "/i `"$package`"" 'install-for-reboot'
}
Write-Host "PASS: $Architecture installer lifecycle ($Stage)"
