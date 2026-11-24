# Lint: C# with every warning as an error (real and test build), ESLint (+ eslint-plugin-security)
# and Prettier for the extension, then basic text checks (no tabs, no trailing whitespace, final
# newline, no garbled UTF-8). Usage: .\lint.ps1   (exit code 0 = clean; run `npm ci` once first)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$problems = 0

# 1. C# compiler warnings as errors; output discarded.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$sources = Get-ChildItem (Join-Path $root 'host\src') -Filter *.cs | ForEach-Object { $_.FullName }
foreach ($define in @($null, '/define:TESTHOOKS')) {
    $out = Join-Path ([IO.Path]::GetTempPath()) ('pp-lint-' + [Guid]::NewGuid().ToString('N') + '.exe')
    $cscArgs = @('/nologo', '/target:exe', '/warn:4', '/warnaserror+', "/out:$out",
        '/r:System.dll', '/r:System.Core.dll', '/r:System.Security.dll',
        '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll')
    if ($define) { $cscArgs += $define }
    & $csc @cscArgs $sources
    if ($LASTEXITCODE -ne 0) { Write-Host "lint: C# warnings/errors found $define" -ForegroundColor Red; $problems++ }
    Remove-Item $out -ErrorAction SilentlyContinue
}

# 2. JavaScript: ESLint + Prettier.
Push-Location $root
try {
    & npm.cmd run --silent lint
    if ($LASTEXITCODE -ne 0) { Write-Host 'lint: ESLint/Prettier problems' -ForegroundColor Red; $problems++ }
} finally { Pop-Location }

# 3. Text formatting.
$files = Get-ChildItem $root -Recurse -File -Include *.cs, *.ps1, *.md, *.yml, *.yaml, *.json, *.js |
    Where-Object { $_.FullName -notmatch '\\(bin|obj|\.git|node_modules|tests\\out)\\' -and $_.Name -ne 'package-lock.json' }
# UTF-8 text misread as Windows-1252, e.g. an arrow turning into three junk characters.
$mojibake = [string][char]0x00E2 + [char]0x20AC + '|' + [char]0x00C3 + '[\x80-\xBF]'
foreach ($f in $files) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    if ($bytes.Length -eq 0) { continue }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    $rel = $f.FullName.Substring($root.Length + 1)
    $lines = $text -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].TrimEnd("`r")
        if ($line -match "`t") { Write-Host "${rel}:$($i + 1): tab character"; $problems++ }
        if ($line -match '\s+$') { Write-Host "${rel}:$($i + 1): trailing whitespace"; $problems++ }
        if ($line -match $mojibake) { Write-Host "${rel}:$($i + 1): garbled characters (encoding problem)"; $problems++ }
    }
    if ($bytes[$bytes.Length - 1] -ne 10) { Write-Host "${rel}: missing final newline"; $problems++ }
}

if ($problems -gt 0) { Write-Host "lint: $problems problem(s)" -ForegroundColor Red; exit 1 }
Write-Host 'lint: clean' -ForegroundColor Green
