# DEVELOPMENT ONLY (phase 1): tells Chrome and Edge where the PlugPass helper app is, for the current
# Windows user only (HKCU). Changes your registry: run it only when you mean to test in your browser.
#   .\tools\dev-register.ps1              register bin\PlugPass.exe (the real build, with the consent window)
#   .\tools\dev-register.ps1 -Unregister  remove the registration again
# Then load bin\extension in chrome://extensions (Developer mode > Load unpacked).
param([switch]$Unregister)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$hostName = 'com.plugpass.host'
$extensionId = 'amppkfbnjicgeeakigkmafdllhknaigl'   # fixed by "key" in extension\manifest.json
$keys = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName"
)
$manifestPath = Join-Path $root "bin\$hostName.json"

if ($Unregister) {
    foreach ($k in $keys) { if (Test-Path $k) { Remove-Item $k; Write-Host "Removed $k" } }
    if (Test-Path $manifestPath) { Remove-Item $manifestPath }
    Write-Host 'PlugPass helper app unregistered.'
    return
}

$exe = Join-Path $root 'bin\PlugPass.exe'   # never the test build (bin\test): it can skip the consent step
if (-not (Test-Path $exe)) { throw "Build first: $exe not found (run .\build.ps1)" }

$manifest = [ordered]@{
    name            = $hostName
    description     = 'PlugPass helper app'
    path            = $exe
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$extensionId/")
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
foreach ($k in $keys) {
    New-Item -Path $k -Force | Out-Null
    Set-Item -Path $k -Value $manifestPath
    Write-Host "Registered $k"
}
Write-Host "Helper app: $exe"
Write-Host "Now load $(Join-Path $root 'bin\extension') in chrome://extensions or edge://extensions (Load unpacked)."
