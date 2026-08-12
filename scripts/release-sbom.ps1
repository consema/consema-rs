# Consema 0.13.0 gate M7: SBOM generation (gate plan §4 M7, roadmap §19.4
# "SBOM"; selection record in docs/release-process-0.13.0.md "SBOM 选型").
#
# Tool selection (recorded, with the rejected alternative):
#   chosen:       cargo-sbom 0.10.0  (crates.io, MIT, psastras/sbom-rs)
#   rejected:     cyclonedx-bom 0.8.1 (crates.io, Apache-2.0, CycloneDX org)
#   Reasons: cargo-sbom is a native cargo subcommand, matching the tool
#   chain this repo already uses (cargo-audit, cargo-deny, cargo-llvm-cov,
#   cargo-fuzz, cargo-nextest are all cargo install subcommands) and the
#   $env:CONSEMA_CARGO convention of the other scripts; it reads the
#   committed Cargo.lock via cargo metadata and emits SPDX 2.3 JSON
#   (default) or CycloneDX 1.4/1.6 JSON, so the license inventory the
#   dependency gate (§19.3, deny.toml: MIT/Apache-2.0/Unicode-3.0) audits
#   is attested in SPDX license expressions. cyclonedx-bom is CycloneDX-
#   only, carries a heavier dependency tree, and adds nothing that
#   cargo-sbom does not provide, since CycloneDX output is available as
#   --output-format cyclone_dx_json_1_6 when a consumer requires it.
#
# What the script does:
#   1. Precondition: the pinned cargo-sbom 0.10.0 must be installed (the
#      failure message names the exact install command). Cargo and a git
#      work tree are required for generation metadata.
#   2. Runs `cargo sbom --output-format spdx_json_2_3 --project-directory
#      <workspace root>` (the lockfile-driven default: every workspace
#      package plus the full transitive dependency graph).
#   3. Validates that stdout parses as JSON and writes the SBOM to
#      docs/release/sbom-<workspace version>.json (default) as BOM-less
#      UTF-8, printing the path, byte size, and package count.
#
# Reproducibility: the SBOM is regenerated from the committed Cargo.lock
# at the release record (same command, same lockfile); the document's
# creationInfo.created timestamp and documentNamespace differ per run,
# which is expected for SPDX documents -- the content that matters (the
# package/dependency/checksum facts) is a pure function of the lockfile
# and the pinned tool version.
#
# Exit codes: 0 = success (SBOM written); 1 = generation gate failure
# (invalid JSON output); 2 = precondition failure (missing tool, no git
# work tree); 3 = cargo sbom execution failure.
#
# Windows PowerShell 5.1 note: with $ErrorActionPreference = 'Stop', ANY
# stderr line from a native command becomes a terminating
# NativeCommandError regardless of redirection, so every native call in
# this script goes through Invoke-NativeCapture / Invoke-NativeQuiet,
# which lower the preference around the call and hand the exit code back
# to the caller (same pattern as scripts/release-sign.ps1; verified live
# on PS 5.1, 2026-08-07).
#
# Encoding note: this file is BOM-less UTF-8; non-ASCII text appears only
# in comments (Windows PowerShell 5.1 misreads BOM-less UTF-8 as ANSI,
# which is harmless for comments but not for string literals).

param(
    # Output file; default: docs\release\sbom-<workspace version>.json.
    [string]$OutputPath = '',
    # SBOM format accepted by cargo-sbom 0.10.0: spdx_json_2_3 (default),
    # cyclone_dx_json_1_4 or cyclone_dx_json_1_6.
    [string]$OutputFormat = 'spdx_json_2_3',
    # Optional repo root override (drills in scratch worktrees); default:
    # the parent directory of this script.
    [string]$RepoRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-NativeCapture {
    # Runs a native command, discards its stderr, and returns its stdout
    # as an array (kept an array even for one line via the unary comma).
    # $LASTEXITCODE is left at the native exit code. EAP is lowered around
    # the call: under Windows PowerShell 5.1 a native stderr line is a
    # terminating NativeCommandError even with 2>$null (verified live).
    param([string]$FilePath, [string[]]$Arguments)

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        $output = @(& $FilePath @Arguments 2>$null)
    } finally {
        $ErrorActionPreference = $previous
    }
    return ,$output
}

function Invoke-NativeQuiet {
    # Like Invoke-NativeCapture but discards stdout as well; returns the
    # native exit code.
    param([string]$FilePath, [string[]]$Arguments)

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        & $FilePath @Arguments 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $previous
    }
    return $LASTEXITCODE
}

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)

# --- Preconditions -----------------------------------------------------------

$pinnedSbomVersion = '0.10.0'
if (-not (Get-Command 'cargo' -ErrorAction SilentlyContinue)) {
    Write-Output 'error: cargo not found on PATH; cargo-sbom is a cargo'
    Write-Output '  subcommand and needs it to read the workspace lockfile.'
    exit 2
}
$sbomVersionOutput = Invoke-NativeCapture 'cargo' @('sbom', '--version')
if ($LASTEXITCODE -ne 0) {
    Write-Output 'error: cargo-sbom is not installed (no `cargo sbom` subcommand).'
    Write-Output "  Install the pinned version with:"
    Write-Output "    cargo install cargo-sbom --version $pinnedSbomVersion --locked"
    Write-Output '  The pin keeps the SBOM reproducible: the document content is'
    Write-Output '  a function of Cargo.lock and the tool version (selection'
    Write-Output '  rationale: docs/release-process-0.13.0.md, SBOM selection).'
    exit 2
}
$sbomVersion = ($sbomVersionOutput | Select-Object -First 1).Trim()
if ($sbomVersion -notmatch [regex]::Escape($pinnedSbomVersion)) {
    Write-Output "error: cargo-sbom version mismatch: found '$sbomVersion',"
    Write-Output "  expected '$pinnedSbomVersion' (the pinned release-tooling version)."
    Write-Output "  Install the pinned version with:"
    Write-Output "    cargo install cargo-sbom --version $pinnedSbomVersion --locked"
    exit 2
}

if (-not (Get-Command 'git' -ErrorAction SilentlyContinue)) {
    Write-Output 'error: git not found on PATH; the SBOM generation record'
    Write-Output '  must name the generating commit.'
    exit 2
}
$workTreeExit = Invoke-NativeQuiet 'git' @('-C', $RepoRoot, 'rev-parse', '--is-inside-work-tree')
if ($workTreeExit -ne 0) {
    Write-Output "error: $RepoRoot is not a git work tree; the SBOM generation"
    Write-Output '  record must name the generating commit.'
    exit 2
}

# --- Generation --------------------------------------------------------------

$commitLines = Invoke-NativeCapture 'git' @('-C', $RepoRoot, 'rev-parse', 'HEAD')
if ($LASTEXITCODE -ne 0 -or $commitLines.Count -eq 0) {
    throw 'git rev-parse HEAD failed'
}
$commitLong = $commitLines[0].Trim()
$runDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'

$metadataJson = Invoke-NativeCapture 'cargo' @('metadata', '--locked', '--offline', '--no-deps', '--format-version', '1')
if ($LASTEXITCODE -ne 0) {
    Write-Output 'error: cargo metadata failed; the output file name derives'
    Write-Output '  from the workspace version.'
    exit 3
}
$metadata = ($metadataJson -join "`n") | ConvertFrom-Json
$workspaceMembers = @{}
foreach ($id in $metadata.workspace_members) {
    $workspaceMembers[$id] = $true
}
$workspaceVersion = $null
$memberVersions = @{}
foreach ($package in $metadata.packages) {
    if (-not $workspaceMembers.ContainsKey($package.id)) { continue }
    $memberVersions[$package.version] = $true
}
# The root Cargo.toml is a virtual workspace manifest ([workspace.package]
# version); every member inherits that version, so a single shared version
# across all workspace members is the workspace version.
if ($memberVersions.Count -eq 1) {
    $workspaceVersion = @($memberVersions.Keys)[0]
}
if (-not $workspaceVersion) {
    Write-Output 'error: cannot resolve the workspace version from cargo metadata'
    Write-Output '  (workspace members must share one version).'
    exit 3
}

$sbomArguments = @('sbom', '--output-format', $OutputFormat, '--project-directory', $RepoRoot)
Write-Output "==> cargo $($sbomArguments -join ' ')"
$sbomOutput = Invoke-NativeCapture 'cargo' $sbomArguments
$sbomExit = $LASTEXITCODE
if ($sbomExit -ne 0) {
    Write-Output "error: cargo sbom failed with exit code $sbomExit"
    Write-Output '  (cargo-sbom runs cargo metadata internally; a warm offline'
    Write-Output '  dependency cache is required, cf. the CI package job which'
    Write-Output '  runs `cargo fetch --locked` first).'
    exit 3
}

try {
    $sbomDocument = ($sbomOutput -join "`n") | ConvertFrom-Json
} catch {
    Write-Output "error: cargo sbom output is not valid JSON ($($_.Exception.Message))"
    exit 1
}
if ($null -eq $sbomDocument) {
    Write-Output 'error: cargo sbom produced no output.'
    exit 1
}
$packageCount = 0
$packagesProperty = $sbomDocument.PSObject.Properties['packages']
if ($null -ne $packagesProperty -and $null -ne $packagesProperty.Value) {
    $packageCount = @($packagesProperty.Value).Count
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $RepoRoot "docs\release\sbom-$workspaceVersion.json"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$sbomText = $sbomOutput -join "`n"
[System.IO.File]::WriteAllText($OutputPath, $sbomText, [System.Text.UTF8Encoding]::new($false))
$sizeBytes = (Get-Item -LiteralPath $OutputPath).Length
Write-Output "SBOM written: $OutputPath"
Write-Output "  workspace version: $workspaceVersion"
Write-Output "  format: $OutputFormat"
Write-Output "  packages listed: $packageCount"
Write-Output "  bytes: $sizeBytes"
Write-Output "  tool: cargo-sbom $pinnedSbomVersion"
Write-Output "  commit: $commitLong"
Write-Output "  date: $runDate"
exit 0
