# Builds PlugPass. The helper app uses the C# compiler that ships with Windows (.NET Framework 4.8):
# no SDK needed.
#   bin\PlugPass.exe        the real helper app (ship this one)
#   bin\test\PlugPass.exe   test build (TESTHOOKS): adds options only the tests may use, such as
#                           PLUGPASS_HOME and --key-dir (a folder standing in for a USB drive).
#                           Never install or ship it.
#   bin\extension\          the Chrome/Edge extension, ready for "Load unpacked"
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "C# compiler not found at $csc" }

$sources = Get-ChildItem (Join-Path $root 'host\src') -Filter *.cs | ForEach-Object { $_.FullName }
$refs = '/r:System.dll', '/r:System.Core.dll', '/r:System.Security.dll',
        '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll', '/r:System.Web.Extensions.dll'

foreach ($variant in @(@{ Dir = 'bin'; Define = $null }, @{ Dir = 'bin\test'; Define = '/define:TESTHOOKS' })) {
    $out = Join-Path $root $variant.Dir
    New-Item -ItemType Directory -Force $out | Out-Null
    $cscArgs = @('/nologo', '/target:winexe', '/optimize+', '/platform:anycpu', "/out:$out\PlugPass.exe") + $refs
    if ($variant.Define) { $cscArgs += $variant.Define }
    & $csc @cscArgs $sources
    if ($LASTEXITCODE -ne 0) { throw "Build failed ($($variant.Dir))." }
    Write-Host "Built $out\PlugPass.exe"
}

$ext = Join-Path $root 'bin\extension'
if (Test-Path $ext) { Remove-Item -Recurse -Force $ext }
Copy-Item (Join-Path $root 'extension') $ext -Recurse
Write-Host "Built $ext"
