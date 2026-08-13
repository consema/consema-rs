# run_waves.ps1 — 0.13.0 gate plan M8: accumulation-protocol driver (agent H)
#
# Runs the in-process deterministic fuzz batteries (parse_fuzz, operation_fuzz,
# protocol_fuzz long tests, #[ignore]d) in per-process, per-core processes and
# appends real measured durations to the evidence ledger
# (runs.csv in the ledger directory). This is the executable form of the
# accumulation protocol documented in docs/fuzz-evidence-0.13.0.md; see that
# file for the protocol, the honest-accounting rules and the classification
# table.
#
# Driver location (2026-08-12 six-repo split): this driver now runs from the
# consema-rs checkout (C:\Users\franck\Documents\consema-rs; 15 crates at the
# repository root, no crates/ directory). The evidence ledger stays the
# authoritative copy in the consema repository:
#   C:\Users\franck\Documents\consema\docs\fuzz-evidence-0.13.0-logs\
# (runs.csv, waves.log and the per-process .out.log/.err.log files, all
# referenced by fc-manifest). -LedgerDir overrides; otherwise the
# CONSEMA_LEDGER_DIR environment variable wins; when that is unset too, the
# hard-coded default path in the param block below applies. That default is
# machine-specific (the original machine's consema repository checkout), so
# set CONSEMA_LEDGER_DIR or pass -LedgerDir on any other machine; the
# original pre-split run_waves.ps1 is preserved untouched in the consema repo
# as evidence of the frozen protocol.
#
# Usage (from the consema-rs repository root):
#   powershell -ExecutionPolicy Bypass -File run_waves.ps1 -Waves 16 -Copies 2
#   powershell -ExecutionPolicy Bypass -File run_waves.ps1 -Waves 4 -Copies 2 -LedgerDir C:\path\to\ledger
#
# Behavior per wave:
#   * tree-hash check (git HEAD + porcelain status): if the working tree
#     changed since the last build (e.g. fix agents landing), rebuild the
#     consema-conformance test binaries first, so every wave runs the current
#     release candidate; git is resolved once per session, PATH first then
#     known absolute installs (codex runtime git, Git for Windows; the machine
#     git was removed 2026-08-11 with the hermes bundle). If no git exists
#     anywhere, the check degrades loudly instead of silently: an INCIDENT
#     NOTE is logged once and the tree-hash is salted per call, forcing a
#     rebuild every wave (a needless rebuild beats a false "unchanged");
#   * start <Copies> concurrent copies of every long fuzz test, each in its own
#     process (`--test-threads=1`, one core per process);
#   * sample per-process CPU time (real, via .NET Process) until exit; a wave
#     safety timeout (default 1800 s) kills stragglers and records exit code
#     -1000 (a hang would surface as this, a P1 event);
#   * append one row per process to runs.csv: wave, copy, target, iterations,
#     wall seconds, CPU seconds (last pre-exit sample, a conservative lower
#     bound), exit code;
#   * append wave summaries and any failure line to waves.log (the tail-feed
#     monitored during a session).
#
# Nothing here ever mutates format crates or the corpus; findings are recorded
# by the operator per conformance/corpora/README.md (regressions workflow).
#
# Machine facts (session 2026-08-07): 13th Gen Intel i9-13900HX, 24 physical /
# 32 logical cores, Windows 11 Pro 10.0.26200, rustc 1.97.1 stable-msvc,
# no clang (MSVC toolchain only), so the in-process harness is the fuzz engine
# (consema-conformance/src/fuzz.rs; cargo-fuzz targets are the clang-host
# completion path, see docs/fuzz-evidence-0.13.0.md).

param(
    [int]$Waves = 16,
    [int]$Copies = 2,
    [int]$WaveTimeoutSec = 1800,
    # -LedgerDir: the evidence ledger directory. When omitted, the
    # CONSEMA_LEDGER_DIR environment variable wins; when that is unset too,
    # the hard-coded default below applies (machine-specific; see the
    # header comment).
    [string]$LedgerDir = $env:CONSEMA_LEDGER_DIR
)

$ErrorActionPreference = 'Continue'

# --- paths ------------------------------------------------------------------
$scriptDir = $PSScriptRoot
# Post-split (2026-08-12): this driver lives at the consema-rs repository root,
# so the workspace root is the script directory itself (pre-split the script
# lived in docs\fuzz-evidence-0.13.0-logs and climbed two levels).
# LedgerDir resolution: explicit -LedgerDir > $env:CONSEMA_LEDGER_DIR > the
# hard-coded default (the original machine's consema repository path).
if (-not $LedgerDir) {
    $LedgerDir = 'C:\Users\franck\Documents\consema\docs\fuzz-evidence-0.13.0-logs'
}
$root = $scriptDir
$logs = $LedgerDir
$runsCsv = Join-Path $logs 'runs.csv'
$wavesLog = Join-Path $logs 'waves.log'

# --- targets: (name, test filter, iterations per long run) ------------------
# Iterations are the committed driver constants (single-source of truth in
# consema-conformance/tests/*_fuzz.rs): parse_fuzz 100_000 iters x 4 bases =
# 400_000 mutations per target; operation_fuzz 25_000 x 3 bases = 75_000;
# protocol_fuzz 100_000 x 4 bases x 2 seeds = 800_000.
$parseTargets = @(
    @{ n = 'json-parse';         t = 'json_parse_fuzz_long_run';              it = 400000 },
    @{ n = 'toml-parse';         t = 'toml_parse_fuzz_long_run';              it = 400000 },
    @{ n = 'yaml-parse';         t = 'yaml_parse_fuzz_long_run';              it = 400000 },
    @{ n = 'ini-parse';          t = 'ini_parse_fuzz_long_run';               it = 400000 },
    @{ n = 'properties-parse';   t = 'properties_parse_fuzz_long_run';        it = 400000 },
    @{ n = 'xml-parse';          t = 'xml_parse_fuzz_long_run';               it = 400000 },
    @{ n = 'plist-parse';        t = 'plist_parse_fuzz_long_run';             it = 400000 },
    @{ n = 'hcl-parse';          t = 'hcl_parse_fuzz_long_run';               it = 400000 }
)
$opsTargets = @(
    @{ n = 'json-ops';           t = 'json_operation_fuzz_long_run';          it = 75000 },
    @{ n = 'toml-ops';           t = 'toml_operation_fuzz_long_run';          it = 75000 },
    @{ n = 'yaml-ops';           t = 'yaml_operation_fuzz_long_run';          it = 75000 },
    @{ n = 'ini-ops';            t = 'ini_operation_fuzz_long_run';           it = 75000 },
    @{ n = 'properties-ops';     t = 'properties_operation_fuzz_long_run';    it = 75000 },
    @{ n = 'xml-ops';            t = 'xml_operation_fuzz_long_run';           it = 75000 },
    @{ n = 'plist-ops';          t = 'plist_operation_fuzz_long_run';         it = 75000 },
    @{ n = 'hcl-ops';            t = 'hcl_operation_fuzz_long_run';           it = 75000 }
)
$protocolTargets = @(
    @{ n = 'protocol-decode';    t = 'protocol_decode_fuzz_long_run';         it = 800000 }
)
$targets = $parseTargets + $opsTargets + $protocolTargets

function Get-LatestExe([string]$pattern) {
    # Returns the newest matching FileInfo (or $null); the freshness check
    # needs LastWriteTime, the launcher needs .FullName.
    $candidates = Get-ChildItem (Join-Path $root "target\debug\deps\$pattern") -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($candidates) { return $candidates[0] }
    return $null
}

function Get-GitExe {
    # Resolves a working git: PATH first, then known absolute installs (the
    # machine's system git was removed 2026-08-11 with the hermes bundle, so
    # PATH may come up empty; the codex runtime ships its own git). Re-probes
    # every call so a git appearing or disappearing mid-session is noticed
    # (a cached path that vanished is dropped and probed again). Returns ''
    # when no git exists anywhere.
    if ($script:gitExe -and -not (Test-Path -LiteralPath $script:gitExe)) {
        $script:gitExe = $null  # cached path vanished (e.g. runtime deleted)
    }
    if ($null -eq $script:gitExe) {
        $script:gitExe = @(
            (Get-Command git -ErrorAction SilentlyContinue).Source,
            'C:\Users\franck\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe',
            'C:\Program Files\Git\cmd\git.exe',
            "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    }
    if (-not $script:gitExe) { return '' }
    return $script:gitExe
}

function Get-TreeHash {
    # Only code inputs change what the fuzz binaries contain: the crate
    # sources (all 15 crates at the consema-rs root, matched by the consema*
    # pathspec, post-split), the lockfile, the conformance corpus and the test
    # drivers. Docs and this evidence directory never trigger a rebuild.
    $git = Get-GitExe
    if (-not $git) {
        # No git anywhere: never silently degrade the code-state guard (a
        # bare `& git` failing under 2>$null returned "|" and skipped real
        # rebuilds). One loud note per session, then a clock-salted hash so
        # the tree always looks changed and every wave rebuilds: conservative
        # and honest - a needless rebuild beats a false "unchanged".
        if (-not $script:gitIncidentLogged) {
            $script:gitIncidentLogged = $true
            Write-Log 'INCIDENT NOTE: git unavailable; tree-hash check degraded, waves cannot verify code-state guard; treating tree as changed'
        }
        return "$((Get-Date).Ticks)|"
    }
    $head = & $git -C $root rev-parse HEAD 2>$null
    $status = (& $git -C $root status --porcelain -- Cargo.toml Cargo.lock conformance 'consema*' 2>$null | Out-String)
    return "$head|$status"
}

function Write-Log([string]$line) {
    $stamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    $full = "[$stamp] $line"
    Add-Content -Path $wavesLog -Value $full -Encoding utf8
    Write-Host $full
}

# --- session header ---------------------------------------------------------
# Session numbering: each driver invocation is one session; the ledger's
# `session` column disambiguates the per-session wave numbering.
$sessionNum = 1
if (Test-Path $wavesLog) {
    $sessionNum = (@(Get-Content $wavesLog -ErrorAction SilentlyContinue | Select-String 'session start').Count) + 1
}
if (-not (Test-Path $runsCsv)) {
    Add-Content -Path $runsCsv -Value 'session,wave,copy,target,iterations,wall_s,cpu_s,exit_code' -Encoding utf8
}
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$osInfo = Get-CimInstance Win32_OperatingSystem
Write-Log "session start: session=$sessionNum waves=$Waves copies=$Copies wave_timeout=${WaveTimeoutSec}s"
Write-Log "machine: $($cpuInfo.Name); $($cpuInfo.NumberOfCores) physical / $($cpuInfo.NumberOfLogicalProcessors) logical cores; $($osInfo.Caption) $($osInfo.Version)"
$headVal = ''; $g = Get-GitExe; if ($g) { $headVal = (& $g -C $root rev-parse HEAD 2>$null) }; Write-Log "toolchain: $(rustc --version) | HEAD=$headVal"

# --- waves ------------------------------------------------------------------
$prevTree = ''
$waveFailures = 0
for ($w = 1; $w -le $Waves; $w++) {
    # 1. Sync build: rebuild whenever the working tree changed since the last
    #    build (fix agents land concurrently), so the wave runs current code.
    $treeHash = Get-TreeHash
    if ($treeHash -ne $prevTree) {
        Write-Log "wave ${w}: tree changed since last build; rebuilding (cargo test -p consema-conformance --no-run --locked)"
        Push-Location $root
        & cargo test -p consema-conformance --no-run --locked 2>&1 | Out-Host
        $cargoExit = $LASTEXITCODE
        Pop-Location
        $fresh = Get-LatestExe 'parse_fuzz-*.exe'
        $freshOps = Get-LatestExe 'operation_fuzz-*.exe'
        $freshProto = Get-LatestExe 'protocol_fuzz-*.exe'
        if ($cargoExit -ne 0 -or -not $fresh -or -not $freshOps -or -not $freshProto) {
            Write-Log "wave ${w}: cargo build failed (exit $cargoExit) or binaries missing; aborting (exit 2)"
            exit 2
        }
        $prevTree = $treeHash
        Write-Log "wave ${w}: build ok (cargo exit 0; newest parse_fuzz exe: $([System.IO.Path]::GetFileName($fresh.FullName)) mtime $($fresh.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))"
    } else {
        Write-Log "wave ${w}: tree unchanged, reusing binaries (deterministic schedule, same code state)"
    }

    # 2. Launch <Copies> copies of every target, one process per target.
    $exeParse = (Get-LatestExe 'parse_fuzz-*.exe').FullName
    $exeOps = (Get-LatestExe 'operation_fuzz-*.exe').FullName
    $exeProto = (Get-LatestExe 'protocol_fuzz-*.exe').FullName

    $items = @()
    foreach ($copy in 1..$Copies) {
        foreach ($t in $targets) {
            $exe = if ($t.n -like '*-parse') { $exeParse } elseif ($t.n -like '*-ops') { $exeOps } else { $exeProto }
            $outLog = Join-Path $logs "wave-$w-copy$copy-$($t.n).out.log"
            $errLog = Join-Path $logs "wave-$w-copy$copy-$($t.n).err.log"
            # Windows PowerShell 5.1 / .NET Framework host: Start-Process
            # -PassThru with or without stream redirection corrupts
            # Process.CPU/ExitCode/HasExited after the child exits (blank
            # values, "null-valued expression" throws; verified 2026-08-07).
            # The direct .NET ProcessStartInfo pattern (UseShellExecute=false,
            # RedirectStandardOutput/Error=true) measures real
            # TotalProcessorTime, HasExited polling and ExitCode correctly
            # (verified on the protocol_decode long run, 2026-08-07).
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $exe
            $psi.Arguments = "--ignored $($t.t) --test-threads=1 --nocapture"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $psi
            [void]$p.Start()
            $items += [pscustomobject]@{
                P = $p; Name = $t.n; Copy = $copy; Iterations = $t.it;
                WallStart = Get-Date; WallEnd = $null; LastCpuS = 0.0;
                Exited = $false; ExitCode = -1; OutLog = $outLog; ErrLog = $errLog
            }
        }
    }
    Write-Log "wave $w start: $($items.Count) processes ($Copies copies x $($targets.Count) targets)"

    # 3. Sample real CPU time until every process exits (or the safety
    #    timeout kills stragglers; a killed process is a hang candidate).
    $deadline = (Get-Date).AddSeconds($WaveTimeoutSec)
    $timedOut = $false
    while ($true) {
        $anyRunning = $false
        foreach ($item in $items) {
            if ($item.Exited) { continue }
            try {
                if ($item.P.HasExited) {
                    $item.Exited = $true
                    $item.ExitCode = $item.P.ExitCode
                    $item.WallEnd = Get-Date
                    # Output volumes are small (test-result lines, at most a
                    # few KB of panic text), so post-exit synchronous stream
                    # reads cannot deadlock on the pipe buffer.
                    $outText = $item.P.StandardOutput.ReadToEnd()
                    $errText = $item.P.StandardError.ReadToEnd()
                    [System.IO.File]::WriteAllText($item.OutLog, $outText)
                    [System.IO.File]::WriteAllText($item.ErrLog, $errText)
                } else {
                    $item.LastCpuS = $item.P.TotalProcessorTime.TotalSeconds
                    $anyRunning = $true
                }
            } catch {
                # Observation race (handle teardown): fall back to a fresh
                # Get-Process snapshot; never silently skip the exit code.
                $proc = Get-Process -Id $item.P.Id -ErrorAction SilentlyContinue
                if ($proc) {
                    $item.LastCpuS = [double]$proc.CPU
                    $anyRunning = $true
                } else {
                    $item.Exited = $true
                    $item.ExitCode = -998
                    $item.WallEnd = Get-Date
                }
            }
        }
        if (-not $anyRunning) { break }
        if ((Get-Date) -gt $deadline) {
            $timedOut = $true
            foreach ($item in $items) {
                if (-not $item.Exited) {
                    try { $item.P.Kill() } catch { }
                    $item.Exited = $true
                    $item.ExitCode = -1000
                    $item.WallEnd = Get-Date
                }
            }
            break
        }
        Start-Sleep -Milliseconds 500
    }

    # 4. Append the ledger rows and the wave summary.
    $wallMax = 0.0; $cpuTotal = 0.0; $failCount = 0
    foreach ($item in $items) {
        if ($null -eq $item.WallEnd) { $item.WallEnd = Get-Date } # safety net
        $wall = ($item.WallEnd - $item.WallStart).TotalSeconds
        if ($wall -gt $wallMax) { $wallMax = $wall }
        $cpuTotal += $item.LastCpuS
        $row = "$sessionNum,$w,$($item.Copy),$($item.Name),$($item.Iterations)," +
               [Math]::Round($wall, 1) + ',' + [Math]::Round($item.LastCpuS, 1) + ",$($item.ExitCode)"
        Add-Content -Path $runsCsv -Value $row -Encoding utf8
        if ($item.ExitCode -ne 0) {
            $failCount++
            $waveFailures++
            Write-Log "FAIL session=$sessionNum wave=$w copy=$($item.Copy) target=$($item.Name) exit=$($item.ExitCode) wall=${wall}s cpu=$([Math]::Round($item.LastCpuS,1))s errlog=$([System.IO.Path]::GetFileName($item.ErrLog))"
        }
    }
    $cpuHours = [Math]::Round($cpuTotal / 3600.0, 3)
    $tag = if ($timedOut) { ' (wave timeout hit)' } else { '' }
    Write-Log "wave $w done: procs=$($items.Count) wall_max=$([Math]::Round($wallMax,1))s cpu_total_s=$([Math]::Round($cpuTotal,1)) cpu_hours=$cpuHours failures=$failCount$tag"
}

# --- final summary ----------------------------------------------------------
$rows = Import-Csv $runsCsv
$totalCpu = 0.0
foreach ($row in $rows) { $totalCpu += [double]$row.cpu_s }
Write-Log "session done: $($rows.Count) ledger rows; total CPU-hours=$([Math]::Round($totalCpu / 3600.0, 3)) failures=$waveFailures"
Write-Log "FINAL"
