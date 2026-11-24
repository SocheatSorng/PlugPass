# Builds PlugPass. The helper app uses the C# compiler that ships with Windows (.NET Framework 4.8):
# no SDK needed.
#   bin\PlugPass.exe        the real helper app (ship this one)
#   bin\test\PlugPass.exe   test build (TESTHOOKS): adds options only the tests may use, such as
#                           PLUGPASS_HOME and --key-dir (a folder standing in for a USB drive).
#                           Never install or ship it.
#   bin\extension\          the Chrome/Edge/Brave extension, ready for "Load unpacked"
#   dist\PlugPass-<version>.zip  what users download: PlugPass.exe + extension\
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

# Release zip: the real exe + the extension, nothing from the test build.
$version = (Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
$stage = Join-Path $root 'dist\PlugPass'
$zip = Join-Path $root "dist\PlugPass-$version.zip"
if (Test-Path (Join-Path $root 'dist')) { Remove-Item -Recurse -Force (Join-Path $root 'dist') }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item (Join-Path $root 'bin\PlugPass.exe') $stage
Copy-Item $ext (Join-Path $stage 'extension') -Recurse
# Entries named with '/' (the zip standard); Windows PowerShell's zip helpers write '\'.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
try {
    foreach ($f in Get-ChildItem $stage -Recurse -File) {
        $name = $f.FullName.Substring($stage.Length + 1).Replace('\', '/')
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $f.FullName, $name) | Out-Null
    }
} finally { $archive.Dispose() }
Remove-Item -Recurse -Force $stage
Write-Host "Built $zip"
