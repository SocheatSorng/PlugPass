# Helper app basics: version and usage.
. (Join-Path $PSScriptRoot 'TestLib.ps1')

$version = (Get-Content (Join-Path $PSScriptRoot '..\package.json') -Raw | ConvertFrom-Json).version

$r = Invoke-PlugPass @('version')
Check ($r.Code -eq 0) 'version exits 0'
Check ($r.Out.Trim() -eq "PlugPass $version") 'version matches package.json'

$r = Invoke-PlugPass @('version') -exe $script:RealExe
Check ($r.Code -eq 0 -and $r.Out.Trim() -eq "PlugPass $version") 'real build reports the same version'

$r = Invoke-PlugPass @('no-such-command')
Check ($r.Code -eq 2) 'unknown command exits 2'
Check ($r.Err -match 'Usage') 'unknown command prints usage'
