# Copyright 2019-2025 namazso <admin@namazso.eu>
# This file is part of OpenHashTab.
#
# OpenHashTab is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OpenHashTab is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenHashTab.  If not, see <https://www.gnu.org/licenses/>.

[CmdletBinding()] param ([switch]$DisablePrecompiledHeaders)

$ErrorActionPreference = 'Stop'
# PowerShell 7.3+ propagates failures from cmake, dotnet and signing commands.
if ($PSVersionTable.PSVersion -lt [version]'7.3') {
    throw 'Build with PowerShell 7.3 or newer.'
}
$PSNativeCommandUseErrorActionPreference = $true


function Get-Environment {
    <#
    .SYNOPSIS
        Captures the current environment variables.
    .DESCRIPTION
        Returns a hashtable of all current environment variables.
    .EXAMPLE
        $SavedEnv = Get-Environment
    .OUTPUTS
        System.Collections.Hashtable
    #>
    $env = @{}
    Get-ChildItem Env: | ForEach-Object { $env[$_.Name] = $_.Value }
    return $env
}

function Set-Environment {
    <#
    .SYNOPSIS
        Restores environment variables from a saved state.
    .DESCRIPTION
        Clears current environment variables and sets them to the provided saved state.
    .PARAMETER Environment
        Hashtable of environment variables previously captured by Get-Environment.
    .EXAMPLE
        Set-Environment -Environment $SavedEnv
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$Environment
    )
    
    # Clear current environment variables
    Remove-Item -Path Env:* -ErrorAction SilentlyContinue
    
    # Restore saved environment variables
    foreach ($key in $Environment.Keys) {
        Set-Item "Env:$key" $Environment[$key]
    }
}

function Reset-Environment {
    <#
    .SYNOPSIS
        Resets the environment by keeping only default Windows environment variables.
    .DESCRIPTION
        Filters an environment hashtable to keep only default Windows environment variables.
        Returns a reset environment hashtable.
    .PARAMETER Environment
        Hashtable of environment variables to reset, as provided by Get-Environment.
    .PARAMETER AdditionalVariables
        Optional array of additional environment variable names to preserve.
    .EXAMPLE
        $ResetEnv = Reset-Environment -Environment $SavedEnv
    .EXAMPLE
        $ResetEnv = Reset-Environment -Environment (Get-Environment) -AdditionalVariables @("JAVA_HOME")
    .OUTPUTS
        System.Collections.Hashtable
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$Environment,
        
        [Parameter(Mandatory=$false)]
        [string[]]$AdditionalVariables = @()
    )
    
    # List of default Windows environment variables to preserve
    $defaultVars = @(
        "ALLUSERSPROFILE", "APPDATA", "CommonProgramFiles", "CommonProgramFiles(x86)",
        "CommonProgramW6432", "COMPUTERNAME", "ComSpec", "HOMEDRIVE", "HOMEPATH",
        "LOCALAPPDATA", "LOGONSERVER", "NUMBER_OF_PROCESSORS", "OS", "Path", "PATHEXT",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
        "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "PROMPT",
        "PSModulePath", "PUBLIC", "SystemDrive", "SystemRoot", "TEMP", "TMP",
        "USERDOMAIN", "USERDOMAIN_ROAMINGPROFILE", "USERNAME", "USERPROFILE", "windir"
    )
    
    # Combine default variables with additional ones
    $varsToKeep = $defaultVars + $AdditionalVariables
    
    # Create a new hashtable with only the variables to keep
    $resetEnvironment = @{}
    foreach ($key in $Environment.Keys) {
        # The manual CodeQL build tracer must survive compiler-environment resets.
        if ($varsToKeep -contains $key -or $varsToKeep -contains $key.ToUpper() -or
            $key -like 'CODEQL_*' -or $key -like 'SEMMLE_*') {
            $resetEnvironment[$key] = $Environment[$key]
        }
    }

    $SystemRoot = $resetEnvironment["SystemRoot"]
    $resetEnvironment["Path"] = "$SystemRoot\system32;$SystemRoot;$SystemRoot\System32\Wbem;$SystemRoot\System32\WindowsPowerShell\v1.0;"
    
    return $resetEnvironment
}
function Get-CmdEnvironment {
    <#
    .SYNOPSIS
        Captures environment variables from a cmd.exe script execution.
    .DESCRIPTION
        Executes a specified script/batch file using cmd.exe and returns all environment 
        variables after execution as a hashtable.
    .PARAMETER ScriptPath
        The path to the command, batch file, or script to execute.
    .PARAMETER Arguments
        Optional arguments to pass to the script.
    .EXAMPLE
        $VsEnv = Get-CmdEnvironment -ScriptPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    .OUTPUTS
        System.Collections.Hashtable
    #>
    param(
        [Parameter(Mandatory=$true)]
        [String]$ScriptPath,
        
        [Parameter(Mandatory=$false)]
        [String]$Arguments = ""
    )
    
    if (-not (Test-Path $ScriptPath)) {
        Write-Error "Script not found: $ScriptPath"
        return $null
    }
    
    # Use full path and proper quoting
    $scriptPathFull = (Resolve-Path $ScriptPath).Path
    $cmdLine = "`"$scriptPathFull`" $Arguments && set"
    
    Write-Verbose "Executing: cmd.exe /c $cmdLine"
    
    $env = @{}
    
    & cmd.exe /c "$cmdLine" | 
    Select-String '^([^=]*)=(.*)$' | ForEach-Object {
        $varName = $_.Matches[0].Groups[1].Value
        $varValue = $_.Matches[0].Groups[2].Value
        $env[$varName] = $varValue
    }
    
    return $env
}

$OriginalEnvironment = Get-Environment;
try {

$VSRoot = If ($Env:VSINSTALLDIR) {$Env:VSINSTALLDIR} Else { & vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath };

If (-not $VSRoot) {
    Throw "Visual Studio not found."
}

$WinSdkVer = If ($Env:WindowsTargetPlatformVersion) { $Env:WindowsTargetPlatformVersion } Else { $(Get-Item "hklm:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows").GetValue("CurrentVersion") };
$WinSdkDir = If ($Env:WindowsSdkDir) { $Env:WindowsSdkDir } Else { $(Get-Item "hklm:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows").GetValue("CurrentInstallFolder") };

$Cmake = Get-Command "cmake";
$Ctest = (Get-Command "ctest").Path;
$Dotnet = Get-Command "dotnet";
$Ninja = (Get-Command "ninja").Path;
$LlvmPath = (Get-Item (Get-Command "clang").Path).Directory.FullName;

# clang-cl accepts --target, but CodeQL 2.27.2 does not forward that option
# when probing the compiler. A target-prefixed driver has the same target even
# without arguments, so both compilation and extraction use the correct ABI.
# Keep these copies and the resource-directory junction inside the build tree.
$CompilerRoot = "$PSScriptRoot/build/compilers"
$CompilerBin = "$CompilerRoot/bin"
New-Item -Path $CompilerBin -ItemType Directory -Force | Out-Null
if (-not (Test-Path "$CompilerRoot/lib")) {
    New-Item -Path "$CompilerRoot/lib" -ItemType Junction -Value "$LlvmPath/../lib" | Out-Null
}
Get-ChildItem "$LlvmPath/*.dll" | Copy-Item -Destination $CompilerBin
Copy-Item "$LlvmPath/lld-link.exe" -Destination $CompilerBin
$Compilers = @{}
foreach ($Target in @('i686-pc-windows-msvc', 'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')) {
    $Compiler = "$CompilerBin/$Target-clang-cl.exe"
    Copy-Item "$LlvmPath/clang-cl.exe" -Destination $Compiler
    $CompilerVersion = (& $Compiler --version) -join "`n"
    if ($CompilerVersion -notmatch "(?m)^Target: $([regex]::Escape($Target))\r?$") {
        throw "Unexpected default compiler target for $Target."
    }
    $Compilers[$Target] = $Compiler
}

$OhtVersion = (Get-Content "$PSScriptRoot/VERSION" -Raw).Trim()
if ($OhtVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw 'VERSION must contain a numeric major.minor.patch version.'
}
$OhtVersionMajor = [int]$Matches[1]
$OhtVersionMinor = [int]$Matches[2]
$OhtVersionPatch = [int]$Matches[3]
if ($OhtVersionMajor -gt 255 -or $OhtVersionMinor -gt 255 -or $OhtVersionPatch -gt 65535) {
    throw 'VERSION exceeds Windows Installer version limits.'
}

$CleanEnv = Reset-Environment $OriginalEnvironment -AdditionalVariables @("AUTHENTICODE_SIGN");
Set-Environment -Environment $CleanEnv;

Write-Host "Using Visual Studio at: $VSRoot"

$x86_Environment = Get-CmdEnvironment -ScriptPath "$VSRoot\VC\Auxiliary\Build\vcvarsamd64_x86.bat";
$x86_Environment["CC"] = $Compilers['i686-pc-windows-msvc'];
$x86_Environment["CXX"] = $Compilers['i686-pc-windows-msvc'];
$x64_Environment = Get-CmdEnvironment -ScriptPath "$VSRoot\VC\Auxiliary\Build\vcvars64.bat";
$x64_Environment["CC"] = $Compilers['x86_64-pc-windows-msvc'];
$x64_Environment["CXX"] = $Compilers['x86_64-pc-windows-msvc'];
$ARM64_Environment = Get-CmdEnvironment -ScriptPath "$VSRoot\VC\Auxiliary\Build\vcvarsamd64_arm64.bat";
$ARM64_Environment["CC"] = $Compilers['aarch64-pc-windows-msvc'];
$ARM64_Environment["CXX"] = $Compilers['aarch64-pc-windows-msvc'];

foreach ($env in @($x86_Environment, $x64_Environment, $ARM64_Environment)) {
    $Platform = $env["Platform"];
    $env["INCLUDE"] += ";$WinSdkDir\Include\$WinSdkVer\shared;$WinSdkDir\Include\$WinSdkVer\ucrt;$WinSdkDir\Include\$WinSdkVer\um";
    $env["LIB"] += ";$WinSdkDir\Lib\$WinSdkVer\ucrt\$Platform;$WinSdkDir\Lib\$WinSdkVer\um\$Platform";
    $env["LIBPATH"] += ";$WinSdkDir\Lib\$WinSdkVer\ucrt\$Platform;$WinSdkDir\Lib\$WinSdkVer\um\$Platform";
    $env["RC"] = "$LlvmPath\llvm-rc.exe";
    $env["Path"] += ";$WinSdkDir\bin\$WinSdkVer\x64";
}

Write-Host "Building OpenHashTab $OhtVersion"

New-Item -Path "install" -ItemType Directory -Force
New-Item -Path "install\algorithms" -ItemType Directory -Force
$AlgorithmsInstallDir = (Get-Item "install\algorithms").FullName;

"x86", "SSE2", "AVX2", "AVX512", "ARM64" | ForEach-Object {
    If ($_ -eq "x86") {
        $Environment = $x86_Environment;
    } Elseif ($_ -eq "ARM64") {
        $Environment = $ARM64_Environment;
    } Else {
        $Environment = $x64_Environment;
    }

    $BuildDir = "build\algorithms-$_";

    Set-Environment $Environment;
    $Mt = (Get-Command "mt").Path;
    & $Cmake `
        -G Ninja `
        -S Algorithms `
        -B $BuildDir `
        --install-prefix $AlgorithmsInstallDir `
        "-DOHT_FLAVOR=$_" `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DCMAKE_MAKE_PROGRAM=$Ninja" `
        "-DCMAKE_MT=$Mt"
    & $Cmake --build $BuildDir
    & $Cmake --install $BuildDir

    If ($Env:AUTHENTICODE_SIGN) {
        & $Env:AUTHENTICODE_SIGN "$((Get-Item "$AlgorithmsInstallDir\AlgorithmsDll_$_.dll").FullName)"
    }
}

$OhtVersionNumeric = "$OhtVersionMajor.$OhtVersionMinor.$OhtVersionPatch";

"x86", "x64", "arm64" | ForEach-Object {
    If ($_ -eq "x86") {
        $Environment = $x86_Environment;
    } Elseif ($_ -eq "arm64") {
        $Environment = $ARM64_Environment;
    } Else {
        $Environment = $x64_Environment;
    }

    $Platform = $Environment["Platform"];

    $BuildDir = "build\oht-$_";

    Set-Environment $Environment;
    $Mt = (Get-Command "mt").Path;
    & $Cmake `
        -G Ninja `
        -S OpenHashTab `
        -B $BuildDir `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DCMAKE_MAKE_PROGRAM=$Ninja" `
        "-DCMAKE_MT=$Mt" `
        "-DOHT_ALGORITHMS_INSTALL_DIR=$AlgorithmsInstallDir" `
        "-DOHT_ALGORITHMS_INCLUDE_DIR=$((Get-Item .\Algorithms).FullName)" `
        "-DOHT_LOCALES_DIR=$((Get-Item .\Localization).FullName)" `
        "-DCI_VERSION=$OhtVersion" `
        "-DCI_VERSION_MAJOR=$OhtVersionMajor" `
        "-DCI_VERSION_MINOR=$OhtVersionMinor" `
        "-DCI_VERSION_PATCH=$OhtVersionPatch" `
        "-DCMAKE_DISABLE_PRECOMPILE_HEADERS=$DisablePrecompiledHeaders" `
        "-DBUILD_TESTING=ON"
    & $Cmake --build $BuildDir

    If ($Env:AUTHENTICODE_SIGN) {
        & $Env:AUTHENTICODE_SIGN "$((Get-Item "$BuildDir\OpenHashTab*.dll").FullName)"
        & $Env:AUTHENTICODE_SIGN "$((Get-Item "$BuildDir\StandaloneStub.exe").FullName)"
        & $Env:AUTHENTICODE_SIGN "$((Get-Item "$BuildDir\Benchmark.exe").FullName)"
    }
    
    if ($_ -ne "arm64") {
        & $Ctest --test-dir $BuildDir --output-on-failure --timeout 180
    }
    $BuildDir32 = "build\oht-x86";

    "User", "Machine" | ForEach-Object {
        & $Dotnet build `
            -c $_ `
            "-property:ProductVersion=$OhtVersionNumeric" `
            "-property:BuildDirectory32=$((Get-Item $BuildDir32).FullName)" `
            "-property:BuildDirectory=$((Get-Item $BuildDir).FullName)" `
            "-property:AlgorithmsDllsDirectory=$AlgorithmsInstallDir" `
    }
}

} finally {
    Set-Environment -Environment $OriginalEnvironment
}
