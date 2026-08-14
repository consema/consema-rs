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
#   * ledger pre-flight (G037): the ledger directory must exist and be
#     writable before any wave runs; otherwise the driver exits 3 instead of
#     producing zero evidence with exit 0;
#   * tree-hash check (git HEAD + porcelain status): if the working tree
#     changed since the last build (e.g. fix agents landing), rebuild the
#     consema-conformance test binaries first, so every wave runs the current
#     release candidate; git is resolved once per session, PATH first, then
#     the $env:CONSEMA_GIT_EXE override (lets operators point at their own
#     pinned git without editing this script; G038), then known absolute
#     installs (codex runtime git, Git for Windows; the machine git was
#     removed 2026-08-11 with the hermes bundle). If no git exists anywhere,
#     or a git command fails mid-session (G038: exit codes are checked), the
#     check degrades loudly instead of silently: an INCIDENT NOTE is logged
#     once and the tree-hash is salted per call, forcing a rebuild every wave
#     (a needless rebuild beats a false "unchanged");
#   * start <Copies> concurrent copies of every long fuzz test, each in its own
#     process (`--test-threads=1`, one core per process); per-process logs are
#     named with the session number (G037: no cross-session overwrite) and the
#     output is drained asynchronously (G037: no pipe-buffer deadlock);
#   * sample per-process CPU time (real, via .NET Process) until exit; a wave
#     safety timeout (default 1800 s) first takes one final exit poll, then
#     kills only the genuinely still-running processes (G037: a process that
#     merely finished late keeps its real exit code) and records exit code
#     -1000 for the killed ones (a hang would surface as this, a P1 event);
#     killed processes still get their per-process .out/.err.log written
#     (G037);
#   * each exit-0 process is verified to have actually run the expected test
#     (libtest exits 0 on a zero-match filter; G037): a missing
#     "test result: ok. 1 passed" line is recorded as exit code -997
#     (driver-detected no-test-match, counted as a FAIL);
#   * append one row per process to runs.csv: wave, copy, target, iterations,
#     wall seconds, CPU seconds (last pre-exit sample, a conservative lower
#     bound), exit code;
#   * append wave summaries and any failure line to waves.log (the tail-feed
#     monitored during a session);
#   * FAIL propagation (protocol §4.2 "任何 FAIL 行（exit ≠ 0）都是事件：立即
#     停止追加"): the first wave with any non-zero exit stops further
#     accumulation (no more waves append) and the driver exits 1 (G037:
#     failures are never swallowed by an unconditional exit 0).
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

# Ledger pre-flight (G037): zero evidence with exit 0 is never acceptable —
# fail loudly before any wave runs when the ledger is missing or not writable.
if (-not (Test-Path -LiteralPath $logs -PathType Container)) {
    Write-Error "LedgerDir does not exist: $logs (pass -LedgerDir or set CONSEMA_LEDGER_DIR)"
    exit 3
}
$probeFile = Join-Path $logs ".write-probe-$(Get-Date -Format 'yyyyMMddHHmmssfff')"
try {
    [System.IO.File]::WriteAllText($probeFile, 'probe')
    Remove-Item -LiteralPath $probeFile -Force -ErrorAction Stop
} catch {
    Write-Error "LedgerDir is not writable: $logs ($_)"
    exit 3
}

# --- targets: (name, test filter, source file, base-array const) ------------
# Iteration counts are derived from the committed test sources at startup
# (consema-conformance/tests/*_fuzz.rs) — no hand-copied constants (G038):
# LONG_RUN_ITERATIONS x the named *_BASES array element count (x seeds per
# base for protocol). A parse failure throws before any wave runs, so the
# runs.csv `iterations` column can never silently drift from the code.
$testDir = Join-Path $root 'consema-conformance\tests'
function Get-TargetIterations([string]$file, [string]$baseConst, [int]$seedFactor) {
    $src = Get-Content -LiteralPath (Join-Path $testDir $file) -Raw
    $iters = 0
    if ($src -match 'const LONG_RUN_ITERATIONS\s*:\s*u64\s*=\s*(\d[\d_]*)\s*;') {
        $iters = [int64](($Matches[1]) -replace '_', '')
    }
    $bases = 0
    if ($src -match "(?s)const $baseConst\s*:\s*&\[&\[u8\]\]\s*=\s*&\[(.*?)\s*\];") {
        # Count the base literals themselves (wave-2 audit): the previous
        # `\n\];` anchor required the closing `];` on its own line and
        # overscanned past single-line arrays (operation_fuzz.rs
        # PROPERTIES_BASES) into the next const, counting its elements too
        # (25,000 x 4 = 100,000 instead of 25,000 x 3 = 75,000 for
        # properties-ops). Match each byte-string literal and require the
        # whole array body to be consumed by literals and separators, so
        # any unexpected array layout fails loudly before a wave runs
        # instead of silently deriving a wrong iteration count.
        $body = $Matches[1]
        $literalRe = 'br#"[\s\S]*?"#|b"(?:[^"\\]|\\.)*"'
        $rest = $body -replace $literalRe, ''
        if ($rest -notmatch '^[\s,]*$') {
            throw "cannot derive base elements from $file ($baseConst): unexpected array layout in the base list"
        }
        $bases = @([regex]::Matches($body, $literalRe)).Count
    }
    if ($iters -le 0 -or $bases -le 0) {
        throw "cannot derive iterations from $file ($baseConst): LONG_RUN_ITERATIONS=$iters bases=$bases"
    }
    return $iters * $bases * $seedFactor
}
$parseTargets = @(
    @{ n = 'json-parse';         t = 'json_parse_fuzz_long_run';              file = 'parse_fuzz.rs';      bc = 'JSON_BASES' },
    @{ n = 'toml-parse';         t = 'toml_parse_fuzz_long_run';              file = 'parse_fuzz.rs';      bc = 'TOML_BASES' },
    @{ n = 'yaml-parse';         t = 'yaml_parse_fuzz_long_run';              file = 'parse_fuzz.rs';      bc = 'YAML_BASES' },
    @{ n = 'ini-parse';          t = 'ini_parse_fuzz_long_run';               file = 'parse_fuzz.rs';      bc = 'INI_BASES' },
    @{ n = 'properties-parse';   t = 'properties_parse_fuzz_long_run';        file = 'parse_fuzz.rs';      bc = 'PROPERTIES_BASES' },
    @{ n = 'xml-parse';          t = 'xml_parse_fuzz_long_run';               file = 'parse_fuzz.rs';      bc = 'XML_BASES' },
    @{ n = 'plist-parse';        t = 'plist_parse_fuzz_long_run';             file = 'parse_fuzz.rs';      bc = 'PLIST_BASES' },
    @{ n = 'hcl-parse';          t = 'hcl_parse_fuzz_long_run';               file = 'parse_fuzz.rs';      bc = 'HCL_BASES' }
)
$opsTargets = @(
    @{ n = 'json-ops';           t = 'json_operation_fuzz_long_run';          file = 'operation_fuzz.rs';   bc = 'JSON_BASES' },
    @{ n = 'toml-ops';           t = 'toml_operation_fuzz_long_run';          file = 'operation_fuzz.rs';   bc = 'TOML_BASES' },
    @{ n = 'yaml-ops';           t = 'yaml_operation_fuzz_long_run';          file = 'operation_fuzz.rs';   bc = 'YAML_BASES' },
    @{ n = 'ini-ops';            t = 'ini_operation_fuzz_long_run';           file = 'operation_fuzz.rs';   bc = 'INI_BASES' },
    @{ n = 'properties-ops';     t = 'properties_operation_fuzz_long_run';    file = 'operation_fuzz.rs';   bc = 'PROPERTIES_BASES' },
    @{ n = 'xml-ops';            t = 'xml_operation_fuzz_long_run';           file = 'operation_fuzz.rs';   bc = 'XML_BASES' },
    @{ n = 'plist-ops';          t = 'plist_operation_fuzz_long_run';         file = 'operation_fuzz.rs';   bc = 'PLIST_BASES' },
    @{ n = 'hcl-ops';            t = 'hcl_operation_fuzz_long_run';           file = 'operation_fuzz.rs';   bc = 'HCL_BASES' }
)
$protocolTargets = @(
    @{ n = 'protocol-decode';    t = 'protocol_decode_fuzz_long_run';         file = 'protocol_fuzz.rs';    bc = 'DECODE_BASES'; seeds = 2 }
)
$targets = $parseTargets + $opsTargets + $protocolTargets
$iterationsFor = @{}
foreach ($t in $targets) {
    $seedFactor = if ($t.ContainsKey('seeds')) { $t.seeds } else { 1 }
    $iterationsFor[$t.n] = Get-TargetIterations $t.file $t.bc $seedFactor
}

function Get-LatestExe([string]$pattern) {
    # Returns the newest matching FileInfo (or $null); the freshness check
    # needs LastWriteTime, the launcher needs .FullName.
    $candidates = Get-ChildItem (Join-Path $root "target\debug\deps\$pattern") -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($candidates) { return $candidates[0] }
    return $null
}

function Get-GitExe {
    # Resolves a working git: PATH first (documented), then the
    # $env:CONSEMA_GIT_EXE override (lets operators point at their own pinned
    # git without editing this script; G038), then the known absolute
    # installs (the machine's system git was removed 2026-08-11 with the
    # hermes bundle, so PATH may come up empty; the codex runtime ships its
    # own git). Re-probes every call so a git appearing or disappearing
    # mid-session is noticed (a cached path that vanished is dropped and
    # probed again). Returns '' when no git exists anywhere.
    if ($script:gitExe -and -not (Test-Path -LiteralPath $script:gitExe)) {
        $script:gitExe = $null  # cached path vanished (e.g. runtime deleted)
    }
    if ($null -eq $script:gitExe) {
        $script:gitExe = @(
            (Get-Command git -ErrorAction SilentlyContinue).Source,
            $env:CONSEMA_GIT_EXE,
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
    $headOk = ($LASTEXITCODE -eq 0) -and -not [string]::IsNullOrEmpty($head)
    $status = (& $git -C $root status --porcelain -- Cargo.toml Cargo.lock conformance 'consema*' 2>$null | Out-String)
    $statusOk = ($LASTEXITCODE -eq 0)
    if (-not $headOk -or -not $statusOk) {
        # git is present but failing (G038: exit codes are checked, so a
        # broken git can no longer silently reuse the last build's binaries).
        # Degrade loudly, exactly like the no-git path: one INCIDENT NOTE per
        # session, then a clock-salted hash so every wave rebuilds.
        if (-not $script:gitIncidentLogged) {
            $script:gitIncidentLogged = $true
            Write-Log 'INCIDENT NOTE: git commands failing; tree-hash check degraded, waves cannot verify code-state guard; treating tree as changed'
        }
        return "$((Get-Date).Ticks)|"
    }
    return "$head|$status"
}

# --- ledger append serialization (wave-2 audit) -----------------------------
# The session lock above only serializes session numbering; per-wave ledger
# rows (runs.csv) and log lines (waves.log) are appended outside it, so two
# concurrent driver sessions sharing a ledger could interleave/tear a row.
# Every append below goes through Add-LedgerLine, serialized with a named
# mutex (session-scoped: concurrent sessions in the same Windows session
# share it; cross-session sharing would need a Global\ name, which requires
# admin rights, so the documented concurrency model is one ledger, one
# interactive session, any number of drivers). An abandoned mutex (owner
# killed mid-append) is caught and treated as acquired.
$script:ledgerMutex = New-Object System.Threading.Mutex($false, 'consema-run_waves-ledger-1')

function Add-LedgerLine([string]$path, [string]$value) {
    try { [void]$script:ledgerMutex.WaitOne() } catch { }
    try {
        Add-Content -Path $path -Value $value -Encoding utf8
    } finally {
        try { [void]$script:ledgerMutex.ReleaseMutex() } catch { }
    }
}

function Write-Log([string]$line) {
    $stamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    $full = "[$stamp] $line"
    Add-LedgerLine $wavesLog $full
    Write-Host $full
}

# --- session header ---------------------------------------------------------
# Session numbering: each driver invocation is one session; the ledger's
# `session` column disambiguates the per-session wave numbering. The
# count-read-write is serialized with an exclusive lock file, so two drivers
# sharing a ledger can never allocate the same session number and pollute
# runs.csv keys (G038).
$sessionLock = Join-Path $logs '.session.lock'
$lockStream = $null
for ($try = 0; $try -lt 30; $try++) {
    try {
        $lockStream = [System.IO.File]::Open($sessionLock,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        break
    } catch {
        if ($try -eq 29) { throw "cannot acquire session lock: $sessionLock" }
        Start-Sleep -Milliseconds 200
    }
}
try {
    $sessionNum = 1
    if (Test-Path $wavesLog) {
        $sessionNum = (@(Get-Content $wavesLog -ErrorAction SilentlyContinue | Select-String 'session start').Count) + 1
    }
    if (-not (Test-Path $runsCsv)) {
        Add-LedgerLine $runsCsv 'session,wave,copy,target,iterations,wall_s,cpu_s,exit_code'
    }
    $cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Write-Log "session start: session=$sessionNum waves=$Waves copies=$Copies wave_timeout=${WaveTimeoutSec}s"
    Write-Log "machine: $($cpuInfo.Name); $($cpuInfo.NumberOfCores) physical / $($cpuInfo.NumberOfLogicalProcessors) logical cores; $($osInfo.Caption) $($osInfo.Version)"
    $headVal = ''; $g = Get-GitExe; if ($g) { $headVal = (& $g -C $root rev-parse HEAD 2>$null) }; Write-Log "toolchain: $(rustc --version) | HEAD=$headVal"
}
finally {
    if ($lockStream) { $lockStream.Dispose() }
    Remove-Item -LiteralPath $sessionLock -Force -ErrorAction SilentlyContinue
}

# --- waves ------------------------------------------------------------------
# Async stream buffers per process id (G037): the DataReceived handlers append
# here; Complete-Item flushes them to the per-process logs on exit or kill.
# The handlers are compiled C# delegates (wave-2 audit): PowerShell-scriptblock
# DataReceived callbacks crashed the driver with an unhandled
# PSInvalidOperation on the .NET threadpool (ScriptBlock.GetContextFromTLS
# race; WER-signed, exit code 2 with no record — the same class as the
# unterminated session 916 ledger entry). C# delegates run without a runspace
# context, so they cannot crash the host; the queues drain identically.
Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
/// <summary>Compiled .NET async drain: attaches DataReceived handlers that
/// enqueue lines into per-process queues (no PowerShell runspace involved,
/// so no PSInvalidOperation crash class).</summary>
public static class ConsemaAsyncDrain {
    public static void Attach(Process p, ConcurrentQueue<string> outQ, ConcurrentQueue<string> errQ) {
        p.OutputDataReceived += (s, e) => { if (e.Data != null) outQ.Enqueue(e.Data); };
        p.ErrorDataReceived += (s, e) => { if (e.Data != null) errQ.Enqueue(e.Data); };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
    }
}
"@
$script:procStreams = @{}

function Complete-Item([object]$item) {
    # Drains the async-collected streams, writes the per-process logs and
    # verifies the expected test actually ran (G037): libtest exits 0 even
    # when the filter matches zero tests, so an exit-0 process without the
    # "test result: ok. 1 passed" line is a driver-detected failure (-997).
    try { $item.P.WaitForExit() } catch { }  # best effort (drains async reads)
    $outLines = [System.Collections.Generic.List[string]]::new()
    $errLines = [System.Collections.Generic.List[string]]::new()
    if ($script:procStreams.ContainsKey($item.P.Id)) {
        $buffers = $script:procStreams[$item.P.Id]
        $line = $null
        while ($buffers.Out.TryDequeue([ref]$line)) { $outLines.Add($line) }
        while ($buffers.Err.TryDequeue([ref]$line)) { $errLines.Add($line) }
        $script:procStreams.Remove($item.P.Id)
    }
    $outText = $outLines -join "`n"
    $errText = $errLines -join "`n"
    [System.IO.File]::WriteAllText($item.OutLog, $outText)
    [System.IO.File]::WriteAllText($item.ErrLog, $errText)
    if ($item.ExitCode -eq 0 -and $outText -notmatch 'test result: ok\.\s*1 passed') {
        $item.ExitCode = -997
    }
}

$prevTree = ''
$waveFailures = 0
# Abort-path record (wave-2 audit): a session that never reaches FINAL (hard
# kill, unhandled error, or an early exit) must leave an explicit ABORT line
# in waves.log, so the ledger never silently ends on an unterminated session
# (the historical session 916 ended this way with no note; its disposition
# belongs to the consema-side evidence record).
$script:sessionFinished = $false
try {
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
                # Per-wave logs are named with the session number so a later
                # session can never overwrite an earlier session's evidence
                # (G037).
                $outLog = Join-Path $logs "wave-$sessionNum-w$w-copy$copy-$($t.n).out.log"
                $errLog = Join-Path $logs "wave-$sessionNum-w$w-copy$copy-$($t.n).err.log"
                # Windows PowerShell 5.1 / .NET Framework host: Start-Process
                # -PassThru with or without stream redirection corrupts
                # Process.CPU/ExitCode/HasExited after the child exits (blank
                # values, "null-valued expression" throws; verified 2026-08-07).
                # The direct .NET ProcessStartInfo pattern (UseShellExecute=false,
                # RedirectStandardOutput/Error=true) measures real
                # TotalProcessorTime, HasExited polling and ExitCode correctly
                # (verified on the protocol_decode long run, 2026-08-07). Output
                # is drained asynchronously (BeginOutputReadLine/BeginErrorReadLine)
                # so no pipe-buffer size can deadlock the sampler (G037); the
                # buffers are flushed to the per-process logs by Complete-Item.
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
                # Compiled .NET async drain (see the ConsemaAsyncDrain note
                # above; G037 semantics preserved: no pipe-buffer deadlock).
                $outQ = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
                $errQ = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
                $script:procStreams[$p.Id] = @{
                    Out = $outQ
                    Err = $errQ
                }
                [ConsemaAsyncDrain]::Attach($p, $outQ, $errQ)
                $items += [pscustomobject]@{
                    P = $p; Name = $t.n; Copy = $copy; Wave = $w; Iterations = $iterationsFor[$t.n];
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
                        Complete-Item $item
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
                        Complete-Item $item
                    }
                }
            }
            if (-not $anyRunning) { break }
            if ((Get-Date) -gt $deadline) {
                $timedOut = $true
                # Final observation pass before the kill (G037): processes that
                # exited during the last sleep still get their real exit codes —
                # no wave-wide collateral -1000 for processes that merely
                # finished late.
                foreach ($item in $items) {
                    if ($item.Exited) { continue }
                    try {
                        if ($item.P.HasExited) {
                            $item.Exited = $true
                            $item.ExitCode = $item.P.ExitCode
                            $item.WallEnd = Get-Date
                            Complete-Item $item
                        }
                    } catch { }
                }
                # Kill only the genuinely still-running (hang candidate)
                # processes, then drain and write their per-process logs too
                # (G037: a killed process must not lose its evidence).
                foreach ($item in $items) {
                    if ($item.Exited) { continue }
                    try { $item.P.Kill() } catch { }
                    $item.Exited = $true
                    $item.ExitCode = -1000
                    $item.WallEnd = Get-Date
                    Complete-Item $item
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
            Add-LedgerLine $runsCsv $row
            if ($item.ExitCode -ne 0) {
                $failCount++
                $waveFailures++
                $hint = if ($item.ExitCode -eq -997) { ' (driver: no-test-match, see outlog)' } else { '' }
                Write-Log "FAIL session=$sessionNum wave=$w copy=$($item.Copy) target=$($item.Name) exit=$($item.ExitCode) wall=${wall}s cpu=$([Math]::Round($item.LastCpuS,1))s errlog=$([System.IO.Path]::GetFileName($item.ErrLog))$hint"
            }
        }
        $cpuHours = [Math]::Round($cpuTotal / 3600.0, 3)
        $tag = if ($timedOut) { ' (wave timeout hit)' } else { '' }
        Write-Log "wave $w done: procs=$($items.Count) wall_max=$([Math]::Round($wallMax,1))s cpu_total_s=$([Math]::Round($cpuTotal,1)) cpu_hours=$cpuHours failures=$failCount$tag"
        # Protocol §4.2 (G037): any FAIL (exit != 0) is an event — stop appending
        # immediately; no further waves run in this session.
        if ($failCount -gt 0) {
            Write-Log "FAIL event in wave ${w}: $failCount process(es) exited non-zero; stopping further accumulation per protocol §4.2 (immediate stop on FAIL)"
            break
        }
    }

    # --- final summary ----------------------------------------------------------
    $rows = Import-Csv $runsCsv
    $totalCpu = 0.0
    foreach ($row in $rows) { $totalCpu += [double]$row.cpu_s }
    $sessionRows = @($rows | Where-Object { $_.session -eq "$sessionNum" }).Count
    Write-Log "session done: ledger rows=$($rows.Count) total CPU-hours=$([Math]::Round($totalCpu / 3600.0, 3)) (whole ledger); session rows=$sessionRows failures=$waveFailures (this session)"
    if ($waveFailures -gt 0) {
        Write-Log "FAIL PROPAGATION: $waveFailures failure(s) recorded; driver exits 1 (protocol §4.2: FAIL stops further appending)"
    }
    Write-Log "FINAL"
    $script:sessionFinished = $true
}
finally {
    if (-not $script:sessionFinished) {
        Write-Log "ABORT: session $sessionNum terminated before FINAL (hard kill or unhandled error); no summary row appended; per-process logs remain as evidence"
    }
}
if ($waveFailures -gt 0) { exit 1 }
exit 0
