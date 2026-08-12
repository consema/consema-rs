param(
    [string]$ArchiveDirectory = '',
    [switch]$SkipPackaging,
    [switch]$AllowDirty,
    [switch]$SkipMsrv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$cargo = if ($env:CONSEMA_CARGO) { $env:CONSEMA_CARGO } else { 'cargo' }
$targetDirectory = if ($env:CARGO_TARGET_DIR) {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
} else {
    Join-Path $workspaceRoot 'target'
}

function Invoke-Cargo {
    param([string[]]$Arguments)

    & $cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-DirtyEntries {
    # Returns the porcelain status entries of the workspace worktree as an
    # array (empty when clean or when cleanliness cannot be verified: no
    # git, not a git work tree). cargo package refuses a dirty worktree, so
    # the package gate documents a clean-tree precondition and names the
    # offending files; -AllowDirty opts into cargo package --allow-dirty.
    # Note: the result is built with @() at the call site so it stays an
    # array even for a single entry (PowerShell function output would
    # unwrap it, and .Count on a scalar string throws under StrictMode).
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Output 'warning: git not found on PATH; clean-tree precondition cannot be verified'
        return @()
    }
    & git -C $workspaceRoot rev-parse --is-inside-work-tree 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Output 'warning: workspace is not a git work tree; clean-tree precondition cannot be verified'
        return @()
    }
    $statusLines = @(& git -C $workspaceRoot status --porcelain)
    if ($LASTEXITCODE -ne 0) {
        throw "git status failed with exit code $LASTEXITCODE; cannot verify the clean-tree precondition"
    }
    return @($statusLines)
}

function New-LocalPatchConfig {
    # Writes the [patch.crates-io] config that redirects one unpacked
    # crate's local dependencies to the extracted sibling archives.
    param([PSCustomObject]$Artifact)

    $patchConfig = Join-Path $temporaryRoot "$($Artifact.Name)-patches.toml"
    $patchLines = @('[patch.crates-io]')
    foreach ($dependency in $Artifact.LocalDependencies) {
        $sourcePath = (
            Join-Path $temporaryRoot $dependency.Root
        ).Replace('\', '/')
        $patchLines += "$($dependency.Name) = { path = `"$sourcePath`" }"
    }
    Set-Content -LiteralPath $patchConfig -Value $patchLines -Encoding UTF8
    return $patchConfig
}

function Get-CrateVerifyArguments {
    # Builds the cargo arguments that verify one unpacked crate offline;
    # the first element is the subcommand (check or build).
    param(
        [string]$Subcommand,
        [string]$ManifestPath,
        [PSCustomObject]$Artifact
    )

    $arguments = @(
        $Subcommand,
        '--manifest-path',
        $ManifestPath,
        '--offline',
        '--all-targets',
        '--all-features'
    )
    if ($Artifact.LocalDependencies.Count -gt 0) {
        $arguments += @('--config', (New-LocalPatchConfig $Artifact))
    }
    return $arguments
}

function Get-InstalledMsrvToolchain {
    # Resolves the declared MSRV prefix (e.g. "1.85" from the workspace
    # rust-version) to the exact installed toolchain version (e.g. "1.85.0"),
    # or returns $null when no rustup toolchain satisfies it. Probing with
    # `cargo +<prefix>` instead would make rustup sync the channel (network,
    # stderr), and any stderr line becomes a terminating NativeCommandError
    # under Windows PowerShell 5.1 with $ErrorActionPreference = 'Stop'.
    param([string]$VersionPrefix)

    $rustup = Get-Command rustup -ErrorAction SilentlyContinue
    if ($null -eq $rustup) {
        return $null
    }
    $toolchainLines = @(& rustup toolchain list)
    if ($LASTEXITCODE -ne 0) {
        throw "rustup toolchain list failed with exit code $LASTEXITCODE"
    }
    $prefixPattern = '^(?:' + [regex]::Escape($VersionPrefix) + ')(?:\.[0-9]+)*'
    foreach ($line in $toolchainLines) {
        if ($line -match $prefixPattern) {
            if ($line -match '^([0-9]+\.[0-9]+\.[0-9]+)') {
                return $Matches[1]
            }
        }
    }
    return $null
}

$metadataJson = & $cargo metadata --locked --offline --no-deps --format-version 1
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed with exit code $LASTEXITCODE"
}
$metadata = $metadataJson | ConvertFrom-Json
$workspaceMembers = @{}
foreach ($id in $metadata.workspace_members) {
    $workspaceMembers[$id] = $true
}

$workspacePackages = @(
    $metadata.packages |
        Where-Object { $workspaceMembers.ContainsKey($_.id) } |
        Sort-Object name
)
$publishablePackages = @(
    $workspacePackages | Where-Object { $null -eq $_.publish }
)
$repositoryOnlyPackages = @(
    $workspacePackages | Where-Object { $null -ne $_.publish }
)

if ($publishablePackages.Count -eq 0) {
    throw 'workspace contains no publishable packages'
}

if (-not $SkipPackaging) {
    $packageArguments = @(
        'package',
        '--locked',
        '--offline',
        '--workspace',
        '--no-verify'
    )
    foreach ($package in $repositoryOnlyPackages) {
        $packageArguments += @('--exclude', $package.name)
    }
    # @() at the call site keeps the result an array even for a single
    # dirty entry (function output unwraps single-element arrays, and .Count
    # on a scalar string throws under Set-StrictMode).
    $dirtyEntries = @(Get-DirtyEntries)
    if ($dirtyEntries.Count -gt 0) {
        if (-not $AllowDirty) {
            $listed = ($dirtyEntries | ForEach-Object { "  $_" }) -join "`n"
            throw "workspace has uncommitted changes; the package gate requires a clean tree (cargo package refuses dirty workspaces). Commit or stash the changes, or pass -AllowDirty to package anyway (adds cargo package --allow-dirty). Offending entries:`n$listed"
        }
        $packageArguments += '--allow-dirty'
    }
    Invoke-Cargo $packageArguments
}

if (-not $ArchiveDirectory) {
    $ArchiveDirectory = Join-Path $targetDirectory 'package'
}
$ArchiveDirectory = [IO.Path]::GetFullPath($ArchiveDirectory)
if (-not (Test-Path -LiteralPath $ArchiveDirectory -PathType Container)) {
    throw "package archive directory does not exist: $ArchiveDirectory"
}

$artifacts = @()
foreach ($package in $publishablePackages) {
    $fileName = "$($package.name)-$($package.version).crate"
    $archivePath = Join-Path $ArchiveDirectory $fileName
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "missing package archive: $archivePath"
    }
    $artifacts += [PSCustomObject]@{
        Name = $package.name
        Version = $package.version
        Root = "$($package.name)-$($package.version)"
        Archive = $archivePath
        Sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$temporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) ('consema-package-verify-' + [Guid]::NewGuid().ToString('N'))
$temporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
$systemTemporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (
    -not $temporaryRoot.StartsWith($systemTemporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not (Split-Path -Leaf $temporaryRoot).StartsWith('consema-package-verify-')
) {
    throw "refusing unsafe verification directory: $temporaryRoot"
}

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

    foreach ($artifact in $artifacts) {
        $entries = @(& tar -tf $artifact.Archive)
        if ($LASTEXITCODE -ne 0) {
            throw "cannot list package archive: $($artifact.Archive)"
        }
        if ($entries.Count -eq 0) {
            throw "empty package archive: $($artifact.Archive)"
        }
        $rootPrefix = "$($artifact.Root)/"
        foreach ($entry in $entries) {
            if (
                -not $entry.StartsWith($rootPrefix, [StringComparison]::Ordinal) -or
                $entry.Split('/') -contains '..'
            ) {
                throw "unsafe or unexpected archive entry '$entry' in $($artifact.Archive)"
            }
        }

        & tar -xzf $artifact.Archive -C $temporaryRoot
        if ($LASTEXITCODE -ne 0) {
            throw "cannot extract package archive: $($artifact.Archive)"
        }
        $manifestPath = Join-Path $temporaryRoot "$($artifact.Root)\Cargo.toml"
        $lockPath = Join-Path $temporaryRoot "$($artifact.Root)\Cargo.lock"
        if (
            -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $lockPath -PathType Leaf)
        ) {
            throw "package archive lacks Cargo.toml or Cargo.lock: $($artifact.Archive)"
        }
    }

    foreach ($artifact in $artifacts) {
        $lockPath = Join-Path $temporaryRoot "$($artifact.Root)\Cargo.lock"
        $lockBlocks = [Regex]::Split(
            (Get-Content -LiteralPath $lockPath -Raw),
            '(?m)^\[\[package\]\]\s*$'
        )
        $localDependencies = @()
        foreach ($dependency in $artifacts) {
            if ($dependency.Name -eq $artifact.Name) { continue }
            $namePattern = '(?m)^name = "' + [Regex]::Escape($dependency.Name) + '"$'
            $versionPattern = '(?m)^version = "' + [Regex]::Escape($dependency.Version) + '"$'
            $block = @(
                $lockBlocks | Where-Object {
                    $_ -match $namePattern -and $_ -match $versionPattern
                }
            )
            if ($block.Count -eq 0) { continue }
            if ($block.Count -ne 1) {
                throw "ambiguous lock entry for $($dependency.Name) in $($artifact.Name)"
            }
            $checksumMatch = [Regex]::Match(
                $block[0],
                '(?m)^checksum = "([0-9a-f]{64})"$'
            )
            if (-not $checksumMatch.Success) {
                throw "missing checksum for $($dependency.Name) in $($artifact.Name)"
            }
            if ($checksumMatch.Groups[1].Value -ne $dependency.Sha256) {
                throw "checksum mismatch for $($dependency.Name) in $($artifact.Name)"
            }
            $localDependencies += $dependency
        }
        $artifact | Add-Member -NotePropertyName LocalDependencies -NotePropertyValue $localDependencies
    }

    foreach ($artifact in $artifacts) {
        $manifestPath = Join-Path $temporaryRoot "$($artifact.Root)\Cargo.toml"
        Invoke-Cargo (Get-CrateVerifyArguments 'check' $manifestPath $artifact)
    }

    if (-not $SkipMsrv) {
        # MSRV leg (0.13.0 gate, roadmap §15.6 "MSRV 在 manifest 中声明并在
        # CI 真正验证"): every publishable crate must build on the rust-version
        # declared by the workspace (Cargo.toml rust-version). Absence of the
        # toolchain fails the gate with a clear message instead of a cryptic
        # cargo error; -SkipMsrv is the documented local escape hatch.
        $msrvToolchain = $null
        foreach ($package in $metadata.packages) {
            $versionProperty = $package.PSObject.Properties['rust_version']
            if ($null -ne $versionProperty -and $versionProperty.Value) {
                $msrvToolchain = [string]$versionProperty.Value
                break
            }
        }
        if (-not $msrvToolchain) {
            throw 'workspace rust-version is not declared; the MSRV gate cannot run'
        }
        $exactMsrvToolchain = Get-InstalledMsrvToolchain $msrvToolchain
        if (-not $exactMsrvToolchain) {
            throw "MSRV toolchain '$msrvToolchain' is not installed (no rustup toolchain matching the declared rust-version; 'rustup toolchain list' must show an installed $msrvToolchain.x). The 0.13.0 package gate requires the MSRV build; install it with 'rustup toolchain install $msrvToolchain', or pass -SkipMsrv to skip the MSRV leg for local runs."
        }
        foreach ($artifact in $artifacts) {
            $manifestPath = Join-Path $temporaryRoot "$($artifact.Root)\Cargo.toml"
            $msrvArguments = @("+$exactMsrvToolchain") +
                (Get-CrateVerifyArguments 'build' $manifestPath $artifact)
            Invoke-Cargo $msrvArguments
        }
        Write-Output "MSRV build leg: rustc $exactMsrvToolchain for all $($artifacts.Count) crates"
    }

    Write-Output "verified $($artifacts.Count) publishable package archives"
    foreach ($artifact in $artifacts) {
        Write-Output "$($artifact.Sha256)  $([IO.Path]::GetFileName($artifact.Archive))"
    }
    if ($repositoryOnlyPackages.Count -gt 0) {
        Write-Output (
            'repository-only packages: ' +
            (($repositoryOnlyPackages | ForEach-Object { $_.name }) -join ', ')
        )
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
