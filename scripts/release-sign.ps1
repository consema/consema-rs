# Consema 0.13.0 gate M7: release signing flow (gate plan §4 M7, roadmap
# §19.4 "signed tag 与 release artifact"). Covers the two signing paths of
# the release supply chain:
#
#   -SignTag v0.13.0
#       GPG-sign the release tag: git tag -s -a v0.13.0 -m "Consema 0.13.0"
#       and immediately verify it with git tag -v. A tag that already
#       exists is never re-signed (tags are content-addressed; a re-sign
#       would mint a new tag object and orphan the old one).
#
#   -SignArtifacts
#       Write the checksum manifest and sign it. The manifest reuses the
#       sha256 output format of scripts/verify-package-archives.ps1
#       ("<64 lowercase hex>  <name>.crate"), computed over the same
#       publishable-crate set (workspace members with publish != null,
#       sorted by name), so the artifact the release record ships and the
#       checksums the package gate printed are byte-identical. The
#       manifest file is then signed twice, both standard forms:
#         gpg --clearsign          -> <manifest>.asc  (text + signature)
#         gpg --detach-sign --armor -> <manifest>.sig (signature only)
#       and both signatures are verified with gpg --verify before the
#       script exits 0.
#
#   -VerifyArtifacts
#       The verification path used by the recovery drill and by consumers:
#       recompute the sha256 of every archive named in the manifest and
#       fail (exit 1) naming each mismatch, then gpg --verify the .asc and
#       .sig files when present.
#
# Documented prerequisites (each failure names the exact fix):
#   * git on PATH; the target repo is a git work tree (-RepoRoot default:
#     the workspace root, i.e. the parent of this script's directory).
#   * gpg on PATH, GnuPG 2.x (install on Windows:
#     `winget install GnuPG.GnuPG`, or https://www.gnupg.org/download/;
#     on macOS: `brew install gnupg`; on Debian/Ubuntu:
#     `sudo apt-get install gnupg`).
#   * at least one secret signing key in the effective keyring, or
#     -KeyId naming one. Create one with `gpg --full-generate-key`
#     (non-interactive: `gpg --batch --passphrase '' --quick-generate-key
#     "Your Name <you@example.com>" rsa4096 sign`). Release signing must
#     use a key that is backed up; a lost key makes every prior signature
#     unverifiable (see docs/release-process-0.13.0.md "丢失标签" drill).
#
# Isolation switch: -GpgHome <dir> sets $env:GNUPGHOME for the whole
# process, so the signing/verification runs against a scratch keyring
# instead of the user's default (~/.gnupg). Intended for drills, tests
# and CI; the user keyring is never touched when -GpgHome is given.
# When the gpg on PATH is an msys build (Git for Windows ships gpg under
# <git>\usr\bin\gpg.exe) the -GpgHome path is converted with cygpath so
# msys gpg reads it as a POSIX path, and MSYS2_ENV_CONV_EXCL=GNUPGHOME is
# set so git does not convert the variable back to a Windows-style path
# when it spawns gpg for `git tag -s` (both conversions verified live on
# gpg 2.4.9 / Git for Windows, 2026-08-07).
#
# Tag signing always passes -u <fingerprint> of the key detected in the
# effective keyring: without it git derives the signing key from
# user.name/user.email (or user.signingkey) and can silently pick a
# different key. -KeyId overrides the detected key. For release signing
# on the default keyring, configure `git config user.signingkey
# <fingerprint>` anyway so non-script tooling signs with the same key.
#
# Windows PowerShell 5.1 note: with $ErrorActionPreference = 'Stop', ANY
# stderr line from a native command becomes a terminating
# NativeCommandError regardless of redirection, so every native call in
# this script goes through Invoke-NativeCapture / Invoke-NativeQuiet,
# which lower the preference around the call and hand the exit code back
# to the caller (same reason scripts/verify-package-archives.ps1 avoids
# stderr-producing probes; verified live on PS 5.1, 2026-08-07).
#
# Exit codes: 0 = success; 1 = signing/verification gate failure (bad
# signature, checksum mismatch, tag already exists, verify failed);
# 2 = precondition failure (missing tool/key, invalid arguments, not a
# git work tree, no archives, manifest unreadable); 3 = gpg/git/cargo
# execution failure.
#
# Encoding note: this file is BOM-less UTF-8; non-ASCII text appears only
# in comments (Windows PowerShell 5.1 misreads BOM-less UTF-8 as ANSI,
# which is harmless for comments but not for string literals).

param(
    # Tag to GPG-sign, e.g. 'v0.13.0' (git tag -s -a; verified afterwards).
    [string]$SignTag = '',
    # Write the checksum manifest for the publishable package archives and
    # sign it (--clearsign and --detach-sign --armor), then verify both.
    [switch]$SignArtifacts,
    # Verify archives against an existing checksum manifest and verify the
    # manifest signatures with gpg --verify. The recovery-drill entry point.
    [switch]$VerifyArtifacts,
    # Directory containing the .crate archives; default: target\package
    # under the repo root (same default as verify-package-archives.ps1).
    [string]$ArchiveDirectory = '',
    # Manifest file to write (-SignArtifacts) or verify (-VerifyArtifacts);
    # default: docs\release\SHA256SUMS-<version>.txt (version from cargo
    # metadata; -VerifyArtifacts requires an explicit path).
    [string]$ManifestPath = '',
    # Optional key fingerprint / id to sign with (passed to gpg as -u and
    # to git tag as -u); default: the key git/gpg picks from the keyring.
    [string]$KeyId = '',
    # Optional isolated keyring directory (GNUPGHOME) for drills and CI.
    [string]$GpgHome = '',
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
    # native exit code. Used for commands whose stderr carries normal
    # status output (git tag -v, gpg --verify) and whose exit code is the
    # only fact that matters.
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

# --- Mode selection ----------------------------------------------------------

$modes = @()
if ($SignTag) { $modes += 'tag' }
if ($SignArtifacts) { $modes += 'sign' }
if ($VerifyArtifacts) { $modes += 'verify' }
if ($modes.Count -ne 1) {
    Write-Output 'error: exactly one mode must be given: -SignTag <version>,'
    Write-Output '  -SignArtifacts, or -VerifyArtifacts.'
    exit 2
}
$mode = $modes[0]

# --- Preconditions -----------------------------------------------------------

if (-not (Get-Command 'git' -ErrorAction SilentlyContinue)) {
    Write-Output 'error: git not found on PATH; tag signing and manifest'
    Write-Output '  verification need git.'
    exit 2
}
$workTreeExit = Invoke-NativeQuiet 'git' @('-C', $RepoRoot, 'rev-parse', '--is-inside-work-tree')
if ($workTreeExit -ne 0) {
    Write-Output "error: $RepoRoot is not a git work tree; release signing"
    Write-Output '  must run inside the repository (or pass -RepoRoot).'
    exit 2
}

$gpgCommand = Get-Command 'gpg' -ErrorAction SilentlyContinue
if ($null -eq $gpgCommand) {
    Write-Output 'error: gpg is not installed or not on PATH.'
    Write-Output '  Install GnuPG 2.x:'
    Write-Output '    Windows: winget install GnuPG.GnuPG   (https://www.gnupg.org/download/)'
    Write-Output '    macOS:   brew install gnupg'
    Write-Output '    Debian/Ubuntu: sudo apt-get install gnupg'
    Write-Output '  Verify with: gpg --version'
    exit 2
}

if ($GpgHome) {
    $GpgHome = [IO.Path]::GetFullPath($GpgHome)
    New-Item -ItemType Directory -Path $GpgHome -Force | Out-Null
    $gpgHomeValue = $GpgHome
    if ($gpgCommand.Source -match '[\\/](usr|mingw(?:32|64))[\\/]bin[\\/]gpg\.exe$') {
        # The gpg on PATH is an msys build (Git for Windows ships it under
        # <git>\usr\bin\gpg.exe). msys gpg reads GNUPGHOME as a POSIX path,
        # so a Windows-style value is treated as relative and fails
        # (verified live 2026-08-07). cygpath is part of Git for Windows.
        $cygpath = Get-Command 'cygpath' -ErrorAction SilentlyContinue
        if ($null -eq $cygpath) {
            Write-Output 'error: gpg is an msys build (Git for Windows) and -GpgHome'
            Write-Output '  was given, but cygpath is not on PATH; the Windows-style'
            Write-Output '  -GpgHome path would be misread as relative by msys gpg.'
            Write-Output '  Install Git for Windows (ships cygpath), or pass the'
            Write-Output '  msys POSIX form of the path.'
            exit 2
        }
        $converted = Invoke-NativeCapture 'cygpath' @('-u', $GpgHome)
        if ($LASTEXITCODE -eq 0 -and $converted.Count -gt 0 -and $converted[0]) {
            $gpgHomeValue = $converted[0].Trim()
        }
        # Git for Windows converts GNUPGHOME to a Windows-style path when
        # it spawns gpg, and msys gpg misreads that as a relative path
        # (verified live 2026-08-07). MSYS2_ENV_CONV_EXCL stops the
        # conversion for exactly this variable; it is a comma-separated
        # list, so an existing value is extended, not replaced.
        if ($env:MSYS2_ENV_CONV_EXCL) {
            $env:MSYS2_ENV_CONV_EXCL = $env:MSYS2_ENV_CONV_EXCL + ',GNUPGHOME'
        } else {
            $env:MSYS2_ENV_CONV_EXCL = 'GNUPGHOME'
        }
    }
    $env:GNUPGHOME = $gpgHomeValue
    Write-Output "isolated keyring (GNUPGHOME): $gpgHomeValue"
}

$gpgVersionLines = Invoke-NativeCapture 'gpg' @('--version')
$gpgVersionLine = ($gpgVersionLines | Select-Object -First 1)
$gpgVersionMatch = [regex]::Match([string]$gpgVersionLine, '\(GnuPG\) ([0-9]+)\.')
if (-not $gpgVersionMatch.Success) {
    Write-Output "error: cannot parse the gpg version at $($gpgCommand.Source):"
    Write-Output "  $gpgVersionLine"
    exit 2
}
$gpgMajor = [int]$gpgVersionMatch.Groups[1].Value
if ($gpgMajor -lt 2) {
    Write-Output "error: gpg is too old ($gpgVersionLine); release signing"
    Write-Output '  requires GnuPG 2.x (see install instructions above).'
    exit 2
}

function Test-UsableSigningKey {
    # Returns the fingerprint of a secret key usable for signing from the
    # effective keyring, or $null. With -KeyId the id must match (suffix,
    # case-insensitive); without it any 'sec' key with signing capability
    # qualifies (git/gpg then pick their default).
    #
    # gpg 2.x --with-colons layout: the 'sec:' line carries the key id in
    # field 4 and the usage flags in field 11 (e.g. 'scSC') but an EMPTY
    # field 9; the fingerprint is on the following 'fpr:' line (field 9).
    # So the fingerprint is captured from the fpr line that follows each
    # sec line (verified live against gpg 2.4.9, 2026-08-07).
    param([string]$RequestedId)

    $secretLines = Invoke-NativeCapture 'gpg' @('--list-secret-keys', '--with-colons')
    $pendingUsage = $null
    foreach ($line in $secretLines) {
        if ($line.StartsWith('sec:')) {
            $fields = $line.Split(':')
            $pendingUsage = ''
            if ($fields.Count -gt 11) { $pendingUsage = $fields[11] }
            continue
        }
        if ($null -eq $pendingUsage) { continue }
        if (-not $line.StartsWith('fpr:')) { continue }
        $fields = $line.Split(':')
        $fingerprint = ''
        if ($fields.Count -gt 9) { $fingerprint = $fields[9] }
        if (-not $fingerprint) { $pendingUsage = $null; continue }
        if ($pendingUsage -notmatch 'S') { $pendingUsage = $null; continue }
        $pendingUsage = $null
        if ($RequestedId) {
            if (-not $fingerprint.EndsWith($RequestedId, [StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }
        return $fingerprint
    }
    return $null
}

$signingKey = Test-UsableSigningKey $KeyId
if ($null -eq $signingKey) {
    Write-Output 'error: no usable secret signing key in the effective keyring.'
    if ($KeyId) {
        Write-Output "  No secret key matches -KeyId '$KeyId' (fingerprint suffix)."
    }
    Write-Output '  Create a signing key with:'
    Write-Output '    gpg --full-generate-key'
    Write-Output '  (non-interactive: gpg --batch --passphrase "" --quick-generate-key'
    Write-Output '   "Your Name <you@example.com>" rsa4096 sign)'
    Write-Output "  List keys with: gpg --list-secret-keys --with-colons"
    if ($GpgHome) {
        Write-Output "  (an isolated keyring is active via -GpgHome: $GpgHome;"
        Write-Output '   generate the key inside it with: gpg --homedir'
        Write-Output "   `"$GpgHome`" --full-generate-key)"
    }
    exit 2
}
Write-Output "signing key: $signingKey"

function Invoke-GpgVerify {
    # Runs gpg --verify and maps the outcome onto the gate: gpg prints its
    # status to stderr (discarded by Invoke-NativeQuiet) and the exit code
    # is the truth.
    param([string[]]$VerifyArguments, [string]$What)

    # Flat concatenation with +; a nested array would splat as one joined
    # argument (verified live on PS 5.1).
    $verifyExit = Invoke-NativeQuiet 'gpg' @(@('--batch', '--verify') + $VerifyArguments)
    if ($verifyExit -ne 0) {
        Write-Output "FAIL: gpg rejected the signature on $What"
        Write-Output "  command: gpg --batch --verify $($VerifyArguments -join ' ')"
        exit 1
    }
    Write-Output "ok: gpg --verify $What"
}

# --- Tag signing -------------------------------------------------------------

if ($mode -eq 'tag') {
    if ($SignTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+') {
        Write-Output "error: -SignTag must look like 'v0.13.0' (got '$SignTag')."
        exit 2
    }
    $existing = Invoke-NativeCapture 'git' @('-C', $RepoRoot, 'tag', '-l', $SignTag)
    if ($existing.Count -gt 0 -and $existing[0]) {
        Write-Output "error: tag $SignTag already exists in $RepoRoot."
        Write-Output '  Tags are content-addressed: re-signing mints a new tag object'
        Write-Output '  and orphans the previous signature. Delete the tag first with'
        Write-Output '  `git tag -d <tag>` only when you intend to replace it, then'
        Write-Output '  re-run the signing command.'
        exit 1
    }
    # The key is always pinned with -u: without it git derives the signing
    # key from user.name/user.email (or user.signingkey), which can silently
    # pick a different key than the one this script detected (verified live
    # 2026-08-07). -KeyId overrides the pin; the precondition already
    # validated that -KeyId names a usable secret key.
    $tagArguments = @('tag', '-s', '-a', $SignTag, '-u', $signingKey, '-m', "Consema $($SignTag.Substring(1))")
    Write-Output "==> git -C $RepoRoot $($tagArguments -join ' ')"
    # Note: a nested array would splat to a native command as ONE
    # space-joined argument (PS 5.1 verified live), so the base and the
    # tag arguments are concatenated into one flat array with +.
    $gitBase = @('-C', $RepoRoot)
    $tagExit = Invoke-NativeQuiet 'git' @($gitBase + $tagArguments)
    if ($tagExit -ne 0) {
        Write-Output "FAIL: git tag -s failed with exit code $tagExit"
        Write-Output "  (check that the signing key can sign: gpg --clearsign "
        Write-Output '   a scratch file; check git config user.signingkey and'
        Write-Output '   gpg.program if you configured them).'
        exit 3
    }
    $verifyTagExit = Invoke-NativeQuiet 'git' @('-C', $RepoRoot, 'tag', '-v', $SignTag)
    if ($verifyTagExit -ne 0) {
        Write-Output "FAIL: git tag -v rejected the signature on $SignTag"
        exit 1
    }
    $tagObjectLines = Invoke-NativeCapture 'git' @('-C', $RepoRoot, 'rev-parse', "$SignTag^{tag}")
    $tagObject = ''
    if ($tagObjectLines.Count -gt 0) { $tagObject = $tagObjectLines[0].Trim() }
    Write-Output "signed tag: $SignTag (object $tagObject, key $signingKey)"
    exit 0
}

# --- Archive/manifest plumbing ----------------------------------------------

if (-not $ArchiveDirectory) {
    $ArchiveDirectory = Join-Path $RepoRoot 'target\package'
}
$ArchiveDirectory = [IO.Path]::GetFullPath($ArchiveDirectory)
if (-not (Test-Path -LiteralPath $ArchiveDirectory -PathType Container)) {
    Write-Output "error: archive directory does not exist: $ArchiveDirectory"
    Write-Output '  Run scripts/verify-package-archives.ps1 first (it packages every'
    Write-Output '  publishable crate into target\package and prints the sha256'
    Write-Output '  lines this manifest reuses), or pass -ArchiveDirectory.'
    exit 2
}

function Get-ManifestEntries {
    # Parses a SHA256SUMS manifest: "<64 lowercase hex>  <file>" per line,
    # blank lines ignored. Entries with a path component are refused.
    # Returns entries with File and Sha256.
    param([string]$Path)

    $lines = @(Get-Content -LiteralPath $Path -Encoding Ascii)
    $entries = @()
    foreach ($line in $lines) {
        if (-not $line.Trim()) { continue }
        $match = [regex]::Match($line, '^([0-9a-f]{64})  (.+)$')
        if (-not $match.Success) {
            throw "unparseable manifest line in ${Path}: $line"
        }
        $fileName = $match.Groups[2].Value
        if ($fileName -match '[\\/]' -or $fileName -match '\.\.') {
            throw "refusing manifest entry with a path component: $fileName"
        }
        $entries += [PSCustomObject]@{
            File = $fileName
            Sha256 = $match.Groups[1].Value
        }
    }
    return @($entries)
}

if ($mode -eq 'verify') {
    if (-not $ManifestPath) {
        Write-Output 'error: -VerifyArtifacts needs -ManifestPath (the manifest'
        Write-Output '  to verify against the archives).'
        exit 2
    }
    $ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        Write-Output "error: manifest file not found: $ManifestPath"
        exit 2
    }

    $failures = @()
    try {
        $entries = @(Get-ManifestEntries $ManifestPath)
    } catch {
        Write-Output "error: $_"
        exit 2
    }
    if ($entries.Count -eq 0) {
        Write-Output "error: manifest is empty: $ManifestPath"
        exit 2
    }

    foreach ($entry in $entries) {
        $archivePath = Join-Path $ArchiveDirectory $entry.File
        if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            $failures += "missing archive for manifest entry: $($entry.File)"
            continue
        }
        $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $entry.Sha256) {
            $failures += (
                "checksum mismatch: $($entry.File)`n" +
                "  manifest: $($entry.Sha256)`n" +
                "  actual:   $actual"
            )
        } else {
            Write-Output "ok: $($entry.File) matches the manifest"
        }
    }

    if ($failures.Count -gt 0) {
        Write-Output "FAIL: $($failures.Count) archive verification failure(s):"
        foreach ($failure in $failures) { Write-Output "  $failure" }
        Write-Output '  Recovery: see docs/release-process-0.13.0.md (recovery'
        Write-Output '  drill section: corrupted archive / checksum mismatch);'
        Write-Output '  never ship a manifest edited by hand to match a'
        Write-Output '  corrupted archive.'
        exit 1
    }

    foreach ($signaturePath in @("$ManifestPath.asc", "$ManifestPath.sig")) {
        if (Test-Path -LiteralPath $signaturePath -PathType Leaf) {
            $verifyArguments = @($signaturePath)
            if ($signaturePath.EndsWith('.sig', [StringComparison]::OrdinalIgnoreCase)) {
                $verifyArguments += $ManifestPath
            }
            Invoke-GpgVerify $verifyArguments ([IO.Path]::GetFileName($signaturePath))
        } else {
            Write-Output "note: no signature file present: $([IO.Path]::GetFileName($signaturePath))"
        }
    }

    Write-Output "verified $($entries.Count) archive checksums and manifest signatures"
    exit 0
}

# --- Manifest writing + artifact signing -------------------------------------

$metadataJson = Invoke-NativeCapture 'cargo' @('metadata', '--locked', '--offline', '--no-deps', '--format-version', '1')
if ($LASTEXITCODE -ne 0) {
    Write-Output 'error: cargo metadata failed; -SignArtifacts resolves the'
    Write-Output '  publishable crate set and workspace version from it.'
    Write-Output '  (Run inside the workspace; cargo must be on PATH.)'
    exit 3
}
$metadata = ($metadataJson -join "`n") | ConvertFrom-Json
$workspaceMembers = @{}
foreach ($id in $metadata.workspace_members) {
    $workspaceMembers[$id] = $true
}
$publishablePackages = @(
    $metadata.packages |
        Where-Object { $workspaceMembers.ContainsKey($_.id) -and $null -eq $_.publish } |
        Sort-Object name
)
if ($publishablePackages.Count -eq 0) {
    Write-Output 'error: workspace contains no publishable packages; nothing to sign.'
    exit 2
}
$workspaceVersion = $null
$memberVersions = @{}
foreach ($package in $metadata.packages) {
    if (-not $workspaceMembers.ContainsKey($package.id)) { continue }
    $memberVersions[$package.version] = $true
}
# The root Cargo.toml is a virtual workspace manifest ([workspace.package]
# version); every member inherits that version, so a single shared version
# across all workspace members is the workspace version. Mixed versions
# (future state) must be handled explicitly, not guessed.
if ($memberVersions.Count -eq 1) {
    $workspaceVersion = @($memberVersions.Keys)[0]
}
if (-not $workspaceVersion) {
    Write-Output 'error: cannot resolve the workspace version from cargo metadata'
    Write-Output '  (workspace members must share one version).'
    exit 3
}

$artifacts = @()
foreach ($package in $publishablePackages) {
    $fileName = "$($package.name)-$($package.version).crate"
    $archivePath = Join-Path $ArchiveDirectory $fileName
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        Write-Output "error: missing package archive: $archivePath"
        Write-Output '  Run scripts/verify-package-archives.ps1 first so every'
        Write-Output '  publishable crate exists in the archive directory.'
        exit 2
    }
    $artifacts += [PSCustomObject]@{
        File = $fileName
        Sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

if (-not $ManifestPath) {
    $ManifestPath = Join-Path $RepoRoot "docs\release\SHA256SUMS-$workspaceVersion.txt"
}
$ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
$manifestDirectory = Split-Path -Parent $ManifestPath
New-Item -ItemType Directory -Path $manifestDirectory -Force | Out-Null

$manifestLines = @(foreach ($artifact in $artifacts) {
    "$($artifact.Sha256)  $($artifact.File)"
})
Set-Content -LiteralPath $ManifestPath -Value $manifestLines -Encoding Ascii
Write-Output "manifest written: $ManifestPath"
foreach ($line in $manifestLines) {
    Write-Output "  $line"
}

$signArguments = @('--batch', '--yes', '--armor')
if ($KeyId) { $signArguments += @('-u', $KeyId) }

# Output names are explicit: gpg 2.4.9 defaults `--armor --detach-sign` to
# <input>.asc, which would collide with the clearsign output and overwrite
# it (verified live 2026-08-07). Flat concatenation with + (a nested
# array would splat as one joined argument, also verified live).
$clearsignExit = Invoke-NativeQuiet 'gpg' @($signArguments + '--clearsign' + '--output' + ($ManifestPath + '.asc') + $ManifestPath)
if ($clearsignExit -ne 0) {
    Write-Output "FAIL: gpg --clearsign failed with exit code $clearsignExit"
    exit 3
}
Write-Output "ok: gpg --clearsign -> $ManifestPath.asc"

$detachExit = Invoke-NativeQuiet 'gpg' @($signArguments + '--detach-sign' + '--output' + ($ManifestPath + '.sig') + $ManifestPath)
if ($detachExit -ne 0) {
    Write-Output "FAIL: gpg --detach-sign failed with exit code $detachExit"
    exit 3
}
Write-Output "ok: gpg --detach-sign --armor -> $ManifestPath.sig"

Invoke-GpgVerify @($ManifestPath + '.asc') 'clearsigned manifest'
# Parentheses are load-bearing: the comma operator binds tighter than +,
# so @($ManifestPath + '.sig', ...) would parse as $ManifestPath +
# ('.sig', ...) and join the two paths into one argument (verified live).
Invoke-GpgVerify @(($ManifestPath + '.sig'), $ManifestPath) 'detached signature'
Write-Output "signed $($artifacts.Count) archives via manifest $([IO.Path]::GetFileName($ManifestPath))"
exit 0
