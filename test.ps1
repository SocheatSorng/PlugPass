# Runs the test suite (build first with .\build.ps1):
#   1. JavaScript tests for the extension (node --test tests/)
#   2. PowerShell tests that drive bin\test\PlugPass.exe (tests\test_*.ps1)
# All scratch data goes to tests\out\ and is removed afterwards.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$failed = 0; $passed = 0

Write-Host '== JavaScript (node --test)' -ForegroundColor Cyan
Push-Location $root
try {
    & node --test 'tests/**/*.test.js'
    if ($LASTEXITCODE -ne 0) { $failed++ } else { $passed++ }
} finally { Pop-Location }

$tests = Get-ChildItem (Join-Path $root 'tests') -Filter 'test_*.ps1' | Sort-Object Name
foreach ($t in $tests) {
    Write-Host "== $($t.Name)" -ForegroundColor Cyan
    . $t.FullName
    $failed += $script:Failures; $passed += $script:Passes
}
$outDir = Join-Path $root 'tests\out'
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir -ErrorAction SilentlyContinue }

Write-Host ''
if ($failed -gt 0) { Write-Host "$passed passed, $failed FAILED (the JavaScript suite counts as one)" -ForegroundColor Red; exit 1 }
Write-Host "$passed passed, 0 failed (the JavaScript suite counts as one)" -ForegroundColor Green
