[CmdletBinding()]
param(
    [string]$GoExe = 'go.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'This script builds and tests on Windows only.' }
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repoRoot 'build'
$version = (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+[-.a-zA-Z0-9]*$') { throw 'Invalid VERSION' }
$goCommand = (Get-Command $GoExe -ErrorAction Stop).Source
if (-not $goCommand) { throw 'Go executable not found' }

function Invoke-Go([string]$Module, [string[]]$GoArgs) {
    Push-Location (Join-Path $repoRoot $Module)
    try {
        & $goCommand @GoArgs
        if ($LASTEXITCODE -ne 0) { throw "Go command failed in $Module (exit $LASTEXITCODE)" }
    } finally { Pop-Location }
}

# Preserve caller environment, including their cache paths. Never disable module verification.
$savedEnv = @{}
foreach ($name in @('CGO_ENABLED', 'GOOS', 'GOARCH', 'GOFLAGS')) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOFLAGS = '-mod=readonly'
    foreach ($module in @('engine', 'desktop')) {
        Invoke-Go $module @('mod', 'download')
        Invoke-Go $module @('mod', 'verify')
    }
    Invoke-Go 'engine' @('test', './...', '-count=1')
    Invoke-Go 'desktop' @('test', '-tags', 'desktop,production', './...', '-count=1')
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    Invoke-Go 'engine' @('build', '-trimpath', '-ldflags', "-s -w -X main.zjuConnectVersion=$version", '-o', (Join-Path $buildDir 'fudan-connect.exe'), '.')
    Invoke-Go 'desktop' @('build', '-tags', 'desktop,production', '-trimpath', '-ldflags', '-s -w -H windowsgui', '-o', (Join-Path $buildDir 'fudan-vpn.exe'), '.')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'engine/router/default_rules.conf') -Destination (Join-Path $buildDir 'rules.conf')
    foreach ($doc in @('README.md', 'LICENSE', 'NOTICE.md', 'SECURITY.md', 'CHANGELOG.md', 'VERSION')) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $doc) -Destination $buildDir
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'engine/internal/ping/LICENSE') -Destination (Join-Path $buildDir 'PING-LICENSE.txt')
    foreach ($relative in @('examples/settings.example.json', 'examples/clash-campus.example.yaml', 'docs/testing.md')) {
        $destination = Join-Path $buildDir $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $repoRoot $relative) -Destination $destination
    }

    $moduleMap = @{}
    foreach ($module in @('engine', 'desktop')) {
        # Use tabs to delimit metadata; only module name/version enters public notices.
        $rows = Invoke-Go $module @('list', '-deps', '-test', '-tags', 'desktop,production', '-f', '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}{{"\t"}}{{.Module.Version}}{{if .Module.Replace}} => {{.Module.Replace.Path}}@{{.Module.Replace.Version}}{{end}}{{"\t"}}{{if .Module.Replace}}{{.Module.Replace.Dir}}{{else}}{{.Module.Dir}}{{end}}{{end}}{{end}}', './...')
        foreach ($row in $rows) {
            if (-not $row) { continue }
            $parts = $row -split "`t", 3
            if ($parts.Count -ne 3) { throw 'Unexpected module metadata' }
            if ($parts[0] -eq 'github.com/mythologyli/zju-connect') { continue } # source bundled here
            $moduleMap[$parts[0] + '@' + $parts[1]] = $parts[2]
        }
    }
    $notices = [System.Text.StringBuilder]::new()
    [void]$notices.AppendLine('Third-party module licenses and notices (including build/test graph).')
    [void]$notices.AppendLine('See NOTICE.md, LICENSE and PING-LICENSE.txt for bundled upstream source.')
    foreach ($key in ($moduleMap.Keys | Sort-Object)) {
        $dir = $moduleMap[$key]
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { throw "Missing downloaded module: $key" }
        $licenses = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([-._].*)?$' })
        $licenseDir = Join-Path $dir 'LICENSES'
        if (Test-Path -LiteralPath $licenseDir -PathType Container) {
            $licenses += @(Get-ChildItem -LiteralPath $licenseDir -File -Recurse)
        }
        if ($licenses.Count -eq 0) { throw "No license file found for $key; review dependency before distribution." }
        [void]$notices.AppendLine("`n===== $key =====")
        foreach ($file in $licenses) {
            [void]$notices.AppendLine("--- $($file.Name) ---")
            [void]$notices.AppendLine([System.IO.File]::ReadAllText($file.FullName))
        }
    }
    [System.IO.File]::WriteAllText((Join-Path $buildDir 'THIRD_PARTY_NOTICES.txt'), $notices.ToString(), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllLines((Join-Path $buildDir 'DEPENDENCIES.txt'), [string[]]($moduleMap.Keys | Sort-Object), [System.Text.UTF8Encoding]::new($false))
    $files = @('fudan-connect.exe', 'fudan-vpn.exe', 'rules.conf', 'README.md', 'LICENSE', 'NOTICE.md', 'SECURITY.md', 'CHANGELOG.md', 'VERSION', 'PING-LICENSE.txt', 'THIRD_PARTY_NOTICES.txt', 'DEPENDENCIES.txt', 'examples/settings.example.json', 'examples/clash-campus.example.yaml', 'docs/testing.md')
    $hashLines = foreach ($name in $files) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $buildDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    [System.IO.File]::WriteAllLines((Join-Path $buildDir 'SHA256SUMS'), [string[]]$hashLines, [System.Text.UTF8Encoding]::new($false))
    $zip = Join-Path $buildDir "FudanVPN-Windows-$version-amd64.zip"
    # Add an exact allowlist, preserving subdirectories and excluding stale files.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipStream = [System.IO.File]::Open($zip, [System.IO.FileMode]::Create)
    $archive = [System.IO.Compression.ZipArchive]::new($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in @($files + 'SHA256SUMS')) {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $buildDir $name), $name, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $archive.Dispose(); $zipStream.Dispose() }
    $checkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('FudanVPN-package-check-' + [guid]::NewGuid().ToString('N'))
    try {
        Expand-Archive -LiteralPath $zip -DestinationPath $checkDir
        foreach ($name in @($files + 'SHA256SUMS')) {
            $original = (Get-FileHash -LiteralPath (Join-Path $buildDir $name) -Algorithm SHA256).Hash
            $unpacked = (Get-FileHash -LiteralPath (Join-Path $checkDir $name) -Algorithm SHA256).Hash
            if ($original -ne $unpacked) { throw "Archive verification failed: $name" }
        }
    } finally {
        # Exact freshly-created child of TEMP, never a caller-provided cleanup path.
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        $resolvedCheck = [System.IO.Path]::GetFullPath($checkDir)
        if (-not $resolvedCheck.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolvedCheck) -notmatch '^FudanVPN-package-check-[0-9a-f]{32}$') { throw 'Unsafe temporary cleanup path' }
        if (Test-Path -LiteralPath $resolvedCheck) { Remove-Item -LiteralPath $resolvedCheck -Recurse -Force }
    }
    & (Join-Path $buildDir 'fudan-connect.exe') --version
    if ($LASTEXITCODE -ne 0) { throw 'Engine version smoke check failed' }
    Get-FileHash -LiteralPath $zip -Algorithm SHA256 | Format-List
} finally {
    foreach ($name in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
}
