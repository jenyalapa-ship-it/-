$ErrorActionPreference = 'Stop'

$packageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$checksumPath = Join-Path $packageRoot 'SHA256SUMS.txt'

Write-Host 'NF DLP 2: package verification' -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $checksumPath)) {
    throw 'SHA256SUMS.txt was not found.'
}

$verified = 0
foreach ($line in Get-Content -LiteralPath $checksumPath -Encoding UTF8) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line -split '  ', 2
    if ($parts.Count -ne 2) { throw "Invalid checksum line: $line" }
    $expected = $parts[0].Trim().ToUpperInvariant()
    $relativePath = $parts[1].Trim()
    $filePath = Join-Path $packageRoot $relativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Missing file: $relativePath"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $filePath).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch: $relativePath"
    }
    $verified += 1
}

Write-Host "Checksums verified: $verified files" -ForegroundColor Green

$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
$nodeExecutable = if ($nodeCommand) { $nodeCommand.Source } else { $null }

if (-not $nodeExecutable) {
    $runtimeRoot = Join-Path $env:USERPROFILE '.cache\codex-runtimes'
    if (Test-Path -LiteralPath $runtimeRoot) {
        $nodeExecutable = Get-ChildItem -LiteralPath $runtimeRoot -Filter node.exe -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\node\\bin\\node\.exe$' } |
            Select-Object -First 1 -ExpandProperty FullName
    }
}

if (-not $nodeExecutable) {
    throw 'Node.js was not found. Open this folder in Codex/GPT and ask it to run verify-package.ps1 with its bundled Node.js.'
}

$testFiles = @(
    (Join-Path $packageRoot 'tests\nf-local-dlp.test.mjs'),
    (Join-Path $packageRoot 'tests\nf-dlp-five-scenarios.test.mjs'),
    (Join-Path $packageRoot 'tests\nf-dlp-thirty-scenarios.test.mjs'),
    (Join-Path $packageRoot 'tests\nf-dlp-vault.test.mjs'),
    (Join-Path $packageRoot 'tests\nf-local-dlp-browser-check.mjs')
)

Write-Host "Node.js: $nodeExecutable"
Write-Host 'Running 77 automated tests...' -ForegroundColor Cyan
& $nodeExecutable --test @testFiles
if ($LASTEXITCODE -ne 0) {
    throw "Tests failed with exit code $LASTEXITCODE. The package is not verified."
}

Write-Host 'Complete: checksums match and 77/77 tests passed.' -ForegroundColor Green
