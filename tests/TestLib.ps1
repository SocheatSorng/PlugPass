# Shared helpers for PlugPass PowerShell tests. Dot-source this file.
# Tests drive bin\test\PlugPass.exe and only ever touch throwaway data under tests\out\.
# Later: PLUGPASS_HOME points PlugPass's own data at tests\out\home and --key-dir stands in for a
# USB drive, so the user's real drives, keys and Windows password are never read or changed.
$ErrorActionPreference = 'Stop'
$script:Exe = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\test\PlugPass.exe'
$script:RealExe = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\PlugPass.exe'
$script:Out = Join-Path $PSScriptRoot 'out'
$script:Failures = 0
$script:Passes = 0

if (-not (Test-Path $script:Exe)) { throw "Build first: $script:Exe not found (run .\build.ps1)" }

$script:PpHome = Join-Path $script:Out 'home'
if (Test-Path $script:PpHome) { Remove-Item -Recurse -Force $script:PpHome }
New-Item -ItemType Directory $script:PpHome -Force | Out-Null
$env:PLUGPASS_HOME = $script:PpHome

function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  PASS  $msg"; $script:Passes++ }
    else { Write-Host "  FAIL  $msg" -ForegroundColor Red; $script:Failures++ }
}

# Runs PlugPass to completion. Returns @{ Code; Out; Err }. $stdin is fed to standard input.
function Invoke-PlugPass([string[]]$argList, [string]$stdin = '', [string]$exe = $script:Exe) {
    $id = [Guid]::NewGuid().ToString('N')
    New-Item -ItemType Directory $script:Out -Force | Out-Null
    $i = Join-Path $script:Out "$id.in"; $o = Join-Path $script:Out "$id.out"; $e = Join-Path $script:Out "$id.err"
    [IO.File]::WriteAllText($i, $stdin)
    $p = Start-Process $exe -ArgumentList $argList `
        -RedirectStandardInput $i -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -NoNewWindow
    $null = $p.Handle  # keeps the handle so ExitCode is available after exit
    $p.WaitForExit()
    $r = @{ Code = $p.ExitCode; Out = (Get-Content $o -Raw); Err = (Get-Content $e -Raw) }
    Remove-Item $i, $o, $e -ErrorAction SilentlyContinue
    return $r
}
