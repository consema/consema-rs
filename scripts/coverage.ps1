# Consema 0.13.0 gate M3: standing coverage toolchain (gate plan §4 M3,
# roadmap §18.3 "Coverage 不替代语义证明"). Replaces the one-off 84.65% figure
# of CHANGELOG.md / RELEASE-0.8.0.md with a reproducible report committed at a
# fixed commit (docs/COVERAGE-0.13.0.md).
#
# Encoding note: this file is UTF-8 WITH BOM so Windows PowerShell 5.1 parses
# the non-ASCII report template correctly (BOM-less UTF-8 is misread as the
# system ANSI codepage). Keep the BOM when editing.
#
# What the script does:
#   1. Precondition check: cargo-llvm-cov and the rustup llvm-tools-preview
#      component must be installed; both failure messages name the exact
#      install command.
#   2. Runs cargo-llvm-cov over the unified target set that mirrors the gate
#      layout (M1 ci.yml test job): --workspace --all-targets --locked. This
#      covers the workspace libs, the consema facade binary, examples, and
#      every test target -- including the consema-conformance tests, whose
#      vectors/fixtures corpora are embedded at compile time
#      (include_str!/include_bytes!, see consema-conformance/src/*_v1.rs
#      and tests/*_fixtures.rs), so the corpus is exercised with no extra
#      wiring.
#   3. Exports llvm-cov's own per-file summary (--json --summary-only), groups
#      files by crate, and regenerates the report file (docs/COVERAGE-0.13.0.md
#      by default) with the real measured numbers, the methodology, and the
#      §18.3 policy.
#   4. Gates: a hard floor on the workspace totals (enforced with
#      cargo-llvm-cov --fail-under-*) runs on every invocation; with -Trend the
#      workspace totals are additionally compared against the report committed
#      at HEAD and a regression beyond the frozen gate fails. A failed gate
#      still writes the report (evidence for the disposition) and exits 1.
#
# Exit codes: 0 = success (report written, gates green); 1 = coverage gate
# failure (hard floor or -Trend regression); 2 = precondition failure (missing
# tool, no Cargo.lock, not a git work tree); 3 = cargo/llvm-cov execution
# failure.
#
# The report file is generated in full by this script (policy text included),
# so the committed doc and the script can never drift apart — with one
# registered exception (wave-3 ruling R7, 2026-08-14; G154 record): the
# wall-clock assertion list (4 sites) in the report's "CI 环境耦合事实"
# section is manually maintained, in the report and in this template
# together — assertion sites move with the code, the script does not track
# them, and any change to an assertion site must update both texts. Never
# hand-edit the numbers block of the report.

param(
    # Compare the measured workspace totals against the report committed at
    # HEAD and fail if any metric regressed beyond the frozen trend gate.
    [switch]$Trend,
    # Where the generated report is written, relative to the workspace root.
    [string]$ReportPath = 'docs/COVERAGE-0.13.0.md',
    # Workspace root override: measure a different checkout of the same
    # repository (e.g. a clean git worktree) without copying this script
    # into it, so the measured tree stays pristine. Defaults to the parent
    # directory of this script.
    [string]$WorkspaceRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Any unexpected PowerShell exception is an execution failure (exit code 3),
# distinct from the gate failures (exit 1) and the precondition failures
# (exit 2) the script reports explicitly.
trap {
    Write-Output "error: $($_.Exception.Message)"
    exit 3
}

$workspaceRoot = if ($WorkspaceRoot) {
    [IO.Path]::GetFullPath($WorkspaceRoot)
} else {
    Split-Path -Parent $PSScriptRoot
}
$cargo = if ($env:CONSEMA_CARGO) { $env:CONSEMA_CARGO } else { 'cargo' }

# Frozen gate constants (the policy section of the generated report mirrors
# these; changing a constant here changes the committed policy with it).
$hardFloorRegions = 70.0       # workspace total region coverage, percent
$hardFloorFunctions = 70.0     # workspace total function coverage, percent
$hardFloorLines = 80.0         # workspace total line coverage, percent
$trendGatePercentPoints = 1.0      # max allowed drop of a workspace total metric
$crateWarningPercentPoints = 2.0   # per-crate drops at/above this are printed

$gateMessages = @()   # collected gate failures, printed and exit 1 at the end

function Get-Percent {
    param([long]$Covered, [long]$Total)
    if ($Total -eq 0) { return 100.0 }
    return [math]::Round((100.0 * $Covered / $Total), 2)
}

function New-MetricAggregator {
    param([string]$Name)
    return [PSCustomObject]@{ Name = $Name; Covered = [long]0; Total = [long]0 }
}

# --- Preconditions -----------------------------------------------------------

if (-not (Get-Command 'cargo-llvm-cov' -ErrorAction SilentlyContinue)) {
    Write-Output 'error: cargo-llvm-cov is not installed.'
    Write-Output '  Install it with:  cargo install cargo-llvm-cov'
    Write-Output '  (cargo-llvm-cov adds the `cargo llvm-cov` subcommand; a'
    Write-Output '   rustup llvm-tools-preview component is also required,'
    Write-Output '   see below.)'
    exit 2
}

$rustup = Get-Command 'rustup' -ErrorAction SilentlyContinue
$hasLlvmTools = $false
if ($rustup) {
    $componentLines = @(& rustup component list)
    if ($LASTEXITCODE -ne 0) {
        Write-Output 'error: `rustup component list` failed; cannot verify the'
        Write-Output '  llvm-tools-preview component that cargo-llvm-cov needs.'
        exit 2
    }
    foreach ($line in $componentLines) {
        # Newer rustup names the component llvm-tools-<target> (the -preview
        # suffix was dropped); older releases used llvm-tools-preview-<target>.
        if ($line -match '^llvm-tools(?:-preview)?(?:-|$)') {
            $hasLlvmTools = $true
            break
        }
    }
}
if (-not $hasLlvmTools) {
    Write-Output 'error: the rustup llvm-tools-preview component is not'
    Write-Output '  installed; cargo-llvm-cov requires it on stable rustc.'
    Write-Output '  Install it with:  rustup component add llvm-tools-preview'
    exit 2
}

if (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'Cargo.lock') -PathType Leaf)) {
    Write-Output 'error: Cargo.lock not found in the workspace root; coverage'
    Write-Output '  runs are locked to the committed dependency set (--locked).'
    exit 2
}

if (-not (Get-Command 'git' -ErrorAction SilentlyContinue)) {
    Write-Output 'error: git not found on PATH; the report records the'
    Write-Output '  generating commit and -Trend compares against the committed'
    Write-Output '  report, both of which need git.'
    exit 2
}
& git -C $workspaceRoot rev-parse --is-inside-work-tree 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Output 'error: the workspace is not a git work tree; the report is'
    Write-Output '  committed at a fixed commit and cannot be produced here.'
    exit 2
}

# --- Environment facts -------------------------------------------------------

$commitLong = (& git -C $workspaceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $commitLong) {
    throw 'git rev-parse HEAD failed'
}
$commit = $commitLong.Substring(0, [math]::Min(7, $commitLong.Length))
$dirtyEntries = @(& git -C $workspaceRoot status --porcelain)
$dirtyCount = @($dirtyEntries).Count
$rustcVersion = (& rustc --version).Trim()
$cargoVersion = (& $cargo --version).Trim()
$llvmCovVersion = (& cargo llvm-cov --version).Trim()
$hostName = $env:COMPUTERNAME
# $IsWindows is a PowerShell Core 6+ automatic variable; the script header
# promises Windows PowerShell 5.1 (`powershell -File scripts/coverage.ps1`),
# which has no such variable and would throw under Set-StrictMode. $env:OS
# is set on every Windows host (5.1 and Core alike) and unset on non-Windows,
# so this expression keeps the Core behavior and works on 5.1 too.
$osInfo = @(if ($env:OS -eq 'Windows_NT') { Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue })
$osCaption = if ($osInfo.Count -gt 0) {
    $osInfo[0].Caption
} else {
    [System.Environment]::OSVersion.VersionString
}
$runDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'

# --- Coverage run ------------------------------------------------------------

$coverageDirectory = Join-Path $workspaceRoot 'target\coverage'
New-Item -ItemType Directory -Path $coverageDirectory -Force | Out-Null
$summaryJsonPath = Join-Path $coverageDirectory 'summary.json'
# A stale summary from a previous run must not be read when this run fails.
Remove-Item -LiteralPath $summaryJsonPath -Force -ErrorAction SilentlyContinue
# --no-clean avoids `cargo clean` wiping the whole target/ directory (other
# repository tooling keeps state there, e.g. target/oracles toolchains); the
# llvm-cov scratch directory is removed explicitly so the merged profile is
# always built from this run's profraw files only.
Remove-Item -LiteralPath (Join-Path $workspaceRoot 'target\llvm-cov') -Recurse -Force -ErrorAction SilentlyContinue

# One command runs the instrumented test suite and exports llvm-cov's own
# per-file summary. --locked pins Cargo.lock; --all-targets covers lib, bins,
# examples and tests (the conformance corpus is embedded in the test targets).
# --fail-under-* implements the §18.3 hard floor on every run. A floor failure
# still writes the report afterwards so the failing numbers are the evidence;
# the final exit code carries the gate result.
$measureArguments = @(
    'llvm-cov',
    '--workspace',
    '--all-targets',
    '--locked',
    '--no-clean',
    '--json',
    '--summary-only',
    '--output-path', $summaryJsonPath,
    '--fail-under-regions', [string]$hardFloorRegions,
    '--fail-under-functions', [string]$hardFloorFunctions,
    '--fail-under-lines', [string]$hardFloorLines
)
Write-Output "==> $cargo $($measureArguments -join ' ')"
& $cargo @measureArguments
$measureExit = $LASTEXITCODE
if ($measureExit -ne 0) {
    if (-not (Test-Path -LiteralPath $summaryJsonPath -PathType Leaf)) {
        throw "cargo llvm-cov failed (exit $measureExit) and produced no summary at $summaryJsonPath; the coverage run could not complete"
    }
    $gateMessages += (
        "hard floor: at least one workspace total fell below the frozen floors " +
        "(regions $hardFloorRegions% / functions $hardFloorFunctions% / " +
        "lines $hardFloorLines%, §18.3 policy); the report records the failing numbers"
    )
    Write-Output "note: cargo llvm-cov exited $measureExit -- hard floor gate failed, but the summary was produced; the report below records the failing numbers as evidence."
}
if (-not (Test-Path -LiteralPath $summaryJsonPath -PathType Leaf)) {
    throw "llvm-cov summary not produced at $summaryJsonPath"
}

$summary = Get-Content -LiteralPath $summaryJsonPath -Raw -Encoding utf8 |
    ConvertFrom-Json
$dataEntries = @($summary.data)
if ($dataEntries.Count -ne 1) {
    throw "llvm-cov summary at $summaryJsonPath has $($dataEntries.Count) data entries (expected 1)"
}
$fileEntries = @($dataEntries[0].files)
if ($fileEntries.Count -eq 0) {
    throw "llvm-cov summary at $summaryJsonPath contains no files"
}

# --- Per-crate aggregation ---------------------------------------------------

# The summary JSON is {"data": [{"files": [{"filename": ..., "summary":
# {regions/functions/lines: {count, covered, percent}}}], "totals": {...}}]}.
# Totals per crate (and workspace) are the sums of the covered and total
# counters, with percentages recomputed from the sums -- the same aggregation
# llvm-cov uses for its own totals row, which the script cross-checks below.
$crateMetrics = @{}
$otherFiles = [System.Collections.Generic.List[string]]::new()
$totals = @{
    regions = New-MetricAggregator 'regions'
    functions = New-MetricAggregator 'functions'
    lines = New-MetricAggregator 'lines'
}

foreach ($fileEntry in $fileEntries) {
    $filePath = [string]$fileEntry.filename
    $summaryBlock = $fileEntry.summary
    # Attribution must match a workspace member directory segment, not just
    # any directory whose name starts with "consema": the broad pattern
    # `consema[^\\/]*` also matched the repository root directory itself
    # (consema-rs in the six-repo layout), collapsing every file into one
    # fake "consema-rs" crate row. The pattern below is the explicit member
    # list -- the facade crate `consema` plus the 14 `consema-*` members --
    # followed by a path separator.
    $crateMarker = [regex]::Match(
        $filePath,
        '(?:^|[\\/])(consema(?:-(?:conformance|core|document|graph|hcl|ini|json|plist|properties|protocol|pvce|toml|xml|yaml))?)[\\/]'
    )
    $crateName = $null
    if ($crateMarker.Success) { $crateName = $crateMarker.Groups[1].Value }
    if (-not $crateName) {
        $otherFiles.Add($filePath)
    } elseif (-not $crateMetrics.ContainsKey($crateName)) {
        $crateMetrics[$crateName] = @{
            regions = New-MetricAggregator 'regions'
            functions = New-MetricAggregator 'functions'
            lines = New-MetricAggregator 'lines'
        }
    }
    foreach ($metric in @('regions', 'functions', 'lines')) {
        $metricProperty = $summaryBlock.PSObject.Properties[$metric]
        if ($null -eq $metricProperty) { continue }
        $countProperty = $metricProperty.Value.PSObject.Properties['count']
        $coveredProperty = $metricProperty.Value.PSObject.Properties['covered']
        if ($null -eq $countProperty -or $null -eq $coveredProperty) {
            throw "summary entry for $filePath lacks '$metric' count/covered"
        }
        $count = [long]$countProperty.Value
        $covered = [long]$coveredProperty.Value
        if ($crateName) {
            $crateMetrics[$crateName][$metric].Total += $count
            $crateMetrics[$crateName][$metric].Covered += $covered
        }
        $totals[$metric].Total += $count
        $totals[$metric].Covered += $covered
    }
}

# Cross-check against llvm-cov's own totals row: the aggregation above must
# reproduce it exactly, or the report would be lying about the tool's numbers.
$jsonTotals = $dataEntries[0].totals
foreach ($metric in @('regions', 'functions', 'lines')) {
    $toolCount = [long]$jsonTotals.PSObject.Properties[$metric].Value.PSObject.Properties['count'].Value
    $toolCovered = [long]$jsonTotals.PSObject.Properties[$metric].Value.PSObject.Properties['covered'].Value
    if ($toolCount -ne $totals[$metric].Total -or $toolCovered -ne $totals[$metric].Covered) {
        throw "aggregation mismatch for '$metric': script sees $($totals[$metric].Covered)/$($totals[$metric].Total), llvm-cov totals row says $toolCovered/$toolCount"
    }
}

function Get-TotalPercent {
    param([string]$Metric)
    return Get-Percent $totals[$Metric].Covered $totals[$Metric].Total
}

$totalLine = 'coverage.total regions={0} functions={1} lines={2}' -f (
    (Get-TotalPercent 'regions').ToString('0.00'),
    (Get-TotalPercent 'functions').ToString('0.00'),
    (Get-TotalPercent 'lines').ToString('0.00')
)

# --- -Trend comparison against the committed report --------------------------

function Get-CommittedReport {
    # Returns the previous report text committed at HEAD, or $null when no
    # previous report exists (first baseline). Reads from git, never from the
    # working tree, so local edits cannot move the trend line.
    param([string]$RelativePath)

    $argument = "HEAD:$($RelativePath.Replace('\', '/'))"
    # --quiet keeps a missing path silent (git show would print a fatal line).
    & git -C $workspaceRoot rev-parse --verify --quiet $argument 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    $content = & git -C $workspaceRoot show $argument
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($content -join "`n")
}

$previousCrateTotals = @{}
if ($Trend) {
    $relativeReportPath = $ReportPath.Replace('\', '/')
    $previous = Get-CommittedReport $relativeReportPath
    if ($null -eq $previous) {
        # 2026-08-14 波 2 修复：-Trend 请求下基线缺失此前静默放行（首跑即绿，
        # 趋势门禁空转）；现改为硬失败——趋势门禁只在有已入库基线时才有意义，
        # 首次建立基线请先不带 -Trend 运行并提交报告。
        Write-Output "error: -Trend requested but no previous report at HEAD:$relativeReportPath"
        Write-Output '  (-Trend has no baseline to compare against; run once without -Trend,'
        Write-Output '   commit the report, then re-run with -Trend.)'
        exit 1
    } else {
        $previousTotal = [regex]::Match(
            $previous, '(?m)^coverage\.total regions=([0-9.]+) functions=([0-9.]+) lines=([0-9.]+)\s*$'
        )
        if (-not $previousTotal.Success) {
            throw "previous report at HEAD:$relativeReportPath has no parseable coverage.total line (was the numbers block hand-edited?)"
        }
        foreach ($match in [regex]::Matches(
            $previous, '(?m)^coverage\.crate ([^\s]+) regions=([0-9.]+) functions=([0-9.]+) lines=([0-9.]+)\s*$'
        )) {
            $previousCrateTotals[$match.Groups[1].Value] = @{
                regions = [double]$match.Groups[2].Value
                functions = [double]$match.Groups[3].Value
                lines = [double]$match.Groups[4].Value
            }
        }
        $metricNames = @('regions', 'functions', 'lines')
        for ($i = 0; $i -lt $metricNames.Count; $i++) {
            $metric = $metricNames[$i]
            $oldValue = [double]$previousTotal.Groups[$i + 1].Value
            $newValue = Get-TotalPercent $metric
            $delta = $newValue - $oldValue
            $message = "${metric}: $($oldValue.ToString('0.00'))% -> $($newValue.ToString('0.00'))% ($($delta.ToString('+0.00;-0.00;0.00')) pp)"
            if ($delta -lt -$trendGatePercentPoints) {
                $gateMessages += "trend gate: $message"
                Write-Output "trend FAIL: $message"
            } elseif ($delta -lt 0) {
                Write-Output "trend note: $message"
            } else {
                Write-Output "trend ok: $message"
            }
        }
    }
}

# --- Report generation -------------------------------------------------------

$crateRows = @(
    $crateMetrics.GetEnumerator() |
        Sort-Object Key |
        ForEach-Object {
            $name = $_.Key
            $metrics = $_.Value
            [PSCustomObject]@{
                Name = $name
                Regions = (Get-Percent $metrics['regions'].Covered $metrics['regions'].Total).ToString('0.00')
                Functions = (Get-Percent $metrics['functions'].Covered $metrics['functions'].Total).ToString('0.00')
                Lines = (Get-Percent $metrics['lines'].Covered $metrics['lines'].Total).ToString('0.00')
            }
        }
)

# Per-crate trend observations (policy item 4): warn when a crate that existed
# in the previous report dropped noticeably; new crates have no baseline.
foreach ($row in $crateRows) {
    if (-not $previousCrateTotals.ContainsKey($row.Name)) { continue }
    foreach ($metric in @('regions', 'functions', 'lines')) {
        $oldValue = [double]$previousCrateTotals[$row.Name][$metric]
        $newValue = [double]$row.$metric
        if ($newValue -le $oldValue - $crateWarningPercentPoints) {
            Write-Output ("crate note: {0} {1}: {2:0.00}% -> {3:0.00}% " +
                "(regression >= {4} pp; §18.3 policy item 4)") -f (
                $row.Name, $metric, $oldValue, $newValue, $crateWarningPercentPoints
            )
        }
    }
}

$gateMarkers = @()
if ($measureExit -ne 0) { $gateMarkers += 'coverage.gate=hard-floor-failed' }
if ($gateMessages.Count -gt 0 -and $measureExit -eq 0) {
    $gateMarkers += 'coverage.gate=trend-failed'
}

$numbersBlock = @(
    'coverage.commit=' + $commitLong
    'coverage.short-commit=' + $commit
    'coverage.date=' + $runDate
    $totalLine
) + $(if ($dirtyCount -gt 0) { @('coverage.worktree-dirty=' + $dirtyCount) } else { @() }) + $gateMarkers + @(
    foreach ($row in $crateRows) {
        'coverage.crate {0} regions={1} functions={2} lines={3}' -f (
            $row.Name, $row.Regions, $row.Functions, $row.Lines
        )
    }
)

$crateMarkdownLines = @(
    '| crate | regions % | functions % | lines % |',
    '|---|---:|---:|---:|'
)
foreach ($row in $crateRows) {
    $crateMarkdownLines += '| {0} | {1} | {2} | {3} |' -f (
        $row.Name, $row.Regions, $row.Functions, $row.Lines
    )
}
$crateMarkdownLines += '| **workspace total** | **{0}** | **{1}** | **{2}** |' -f (
    (Get-TotalPercent 'regions').ToString('0.00'),
    (Get-TotalPercent 'functions').ToString('0.00'),
    (Get-TotalPercent 'lines').ToString('0.00')
)

if ($otherFiles.Count -gt 0) {
    $otherNote = @(
        '',
        'Files not attributed to a workspace crate (grouped as `other`):',
        ''
    ) + @(foreach ($file in $otherFiles) { '- ' + '`' + $file + '`' }) + @('')
} else {
    $otherNote = @()
}

if ($measureExit -ne 0) {
    $gateBanner = '> GATE FAILED: hard floor -- at least one workspace total fell below the frozen floors (see policy item 2). The numbers below are the failing evidence; the next green run replaces this report.'
} else {
    $gateBanner = ''
}

# NOTE: inside this double-quoted here-string every markdown backtick is
# written doubled (``) because a single backtick is PowerShell's escape
# character (`t is TAB, `r is CR, `$ is a literal dollar sign, `p is p ...).
# The only intentional single-backtick sequences are the "`n" joins inside
# the $(...) subexpressions.
$report = @"
# Consema 0.13.0 Coverage Report

- 报告体例：由 ``scripts/coverage.ps1`` 整体生成（政策文本也在脚本内；禁止手改数字块）。
  登记例外（波 3 裁决 R7，2026-08-14；G154 记录）：下「CI 环境耦合事实」节的
  wall-clock 断言清单（4 处）为人工维护——断言站点随代码变动，脚本不自动跟踪，
  改动断言站点时必须同步更新本报告与该脚本内的模板文本。
  本文件是 0.13.0 门禁 M3 的“报告数值入库”载体（gate plan §4 M3、§7 验收表：
  “coverage 可复现报告”）。
- 取代一次性数字：规范仓（github.com/consema/consema）CHANGELOG.md 与
  docs/RELEASE-0.8.0.md 记录的 84.65% regions / 82.73% functions / 86.59%
  lines 是单次辅助报告，无脚本、无工件、不可复现；自本报告起 coverage 由
  常设脚本在固定 commit 上产出，任何数字变化都来自脚本运行。

$gateBanner

## 本次测量

- 测量 commit：``$commit``（$commitLong）
- 测量日期：$runDate（机器：$hostName / $osCaption）
$(if ($dirtyCount -gt 0) { "- 工作树状态：测量时工作树有 $dirtyCount 个未提交条目（``git status --porcelain``）；数字对应当时的实测状态。要得到与入库数字完全一致的复现，请在记录 commit 的干净 checkout 上重跑。" } else { '- 工作树状态：clean（与记录 commit 完全一致）。' })
- 工具链：$rustcVersion；$cargoVersion；$llvmCovVersion
- 测量命令（与脚本执行等价的重现命令）：

``````text
cargo llvm-cov --workspace --all-targets --locked --no-clean --json --summary-only --output-path target/coverage/summary.json --fail-under-regions $hardFloorRegions --fail-under-functions $hardFloorFunctions --fail-under-lines $hardFloorLines
``````

重跑：``powershell -File scripts/coverage.ps1``；发布里程碑用
``powershell -File scripts/coverage.ps1 -Trend``。

## 数字（脚本从 llvm-cov summary JSON 汇总；逐行精确到 0.01 个百分点）

``````text
$($numbersBlock -join "`n")
``````

$($crateMarkdownLines -join "`n")

$($otherNote -join "`n")## 方法与范围

- 目标集统一为门禁布局：``--workspace --all-targets --locked``（与 M1 ci.yml 的
  test job 同一目标集）——workspace 全部 lib、``consema`` facade 的 bin、examples、
  全部 test target 都计入。
- 语料复用：conformance vectors 与 fixtures 通过 ``include_str!``/``include_bytes!``
  编译进 ``consema-conformance`` 的 lib 与集成测试（``consema-conformance/src/*_v1.rs``、
  ``tests/*_fixtures.rs``），因此本测量天然执行 18 套 suite / 519 case、fixtures、
  hardening 与 encoding corpus，无需额外接线。
- 百分比从 ``llvm-cov export --summary-only``（JSON）的每文件 covered/total 求和
  重算（与 llvm-cov TOTAL 行同一聚合语义）；region 列即 llvm-cov 的 Region 指标
  （Rust stable 上由 ``-C instrument-coverage`` 的 region counter 给出）。
- 行/函数/region 均为“至少执行一次”计数；测试二进制自身代码随
  ``--all-targets`` 计入。doctest 不经 llvm-cov 插桩（rustdoc 单独编译，不参与
  本测量），不在本报告覆盖内。
- 未归属到任何 crate 的文件会在上方列出（如有）；当前仓库无 workspace
  ``[features]``（gate plan §0.1），故无 ``--all-features`` 腿；若将来引入 features，
  需在本节补记。

## CI 环境耦合事实（2026-08-13 记录，G154 文档化处置）

1. **趋势门禁的平台耦合。** 本报告的基线数字在本机（FRANCK-PC / Windows 11，
   rustc 1.97.1 stable-msvc）实测；ci.yml 的 coverage job 在 ubuntu-latest 上
   重新测量并跑 ``-Trend`` 对比本报告。Windows 与 ubuntu 的覆盖率数值存在
   平台差异（编译器 codegen 与标准库内联行为不同），趋势门禁因此存在设计级
   环境耦合：本地无法逐字复现 CI 的测量。**风险**：跨平台差异可能造成 CI 红
   而本地绿（或相反），趋势比较不是纯代码回归探测器。**缓解**：门槛余量
   （跌幅严格超过 1.0 pp 才失败）远大于实测平台差异；CI 与发布里程碑测量
   均以同一脚本同参数执行；任何趋势失败都以 CI 数字为准并在发布记录中
   disposition。
2. **wall-clock 断言。** workspace 共 4 处墙钟断言。本清单为人工维护
   （登记例外，波 3 裁决 R7 与 G154 记录：断言站点随代码变动，脚本不自动
   跟踪；改动断言站点时必须同步更新本清单、本报告头部注记与
   ``scripts/coverage.ps1`` 内的模板文本）。完整清单（2026-08-14 复核）：
   - ``consema-yaml/src/materialization.rs`` 的 B-7/B-8 回归测试两处
     （``elapsed < 8.0s``，debug 构建，2026-08-13 实测两条链路余量均在
     20x 以上）；
   - ``consema-xml/src/parser.rs``
     ``many_small_elements_formation_scales_linearly`` 一处
     （``elapsed.as_secs() < 20``，10k 元素 formation 线性回归守卫，
     2026-08-14 实测整测试 0.18s，余量远大于 20x）；
   - ``consema-document/src/source.rs``
     ``per_call_coordinate_conversion_does_not_rescan_large_utf8_sources``
     一处（``elapsed.as_secs() < 5``，逐调用坐标转换防重扫守卫，
     2026-08-14 实测整测试 1.09s，余量约 4-5x）。
   **风险**：墙钟断言环境耦合（慢机/负载抖动可能误红）。**缓解**：断言值
   针对修复前 O(n²) 实现的耗时（~30-60 s debug / ~6.7 s release）设上限，
   固定实现余量极宽（xml/source 两处亦为线性回归守卫，上限针对修复前
   行为）；误红时按修复前基线人工复核，不降低断言值。

## Coverage 政策（路线图 §18.3 落地）

1. **Coverage 不替代语义证明。** 本报告的百分比只是回归探测器。质量证据的权威
   来源是 conformance 519/519 向量、byte-exact round-trip 证明、hardening 测试、
   差分 oracle、fuzz（0.13.0 M2/M8）与 API 审查（M4）；任何发布记录都不得把单一
   coverage 百分比当作质量证明引用。本报告取代规范仓 CHANGELOG.md 记录的
   一次性数字，也不再制造新的单次数字。
2. **硬下限（每次运行都强制）。** ``scripts/coverage.ps1`` 每次运行都带
   ``--fail-under-*``，workspace 总 coverage 低于 regions ≥ $hardFloorRegions% /
   functions ≥ $hardFloorFunctions% / lines ≥ $hardFloorLines% 即失败（exit 1）。
   下限远低于当前实测值，只作灾难性回退的兜底，不构成刷覆盖率的目标。
3. **趋势门禁（-Trend 模式，发布里程碑执行）。** 与上一个入库报告（git 提交于
   HEAD 的 ``docs/COVERAGE-0.13.0.md``）比较 workspace 总 region/function/line：
   任一指标跌幅超过 $trendGatePercentPoints 个百分点即失败（exit 1）。跌幅在
   0 到 $trendGatePercentPoints pp 之间打印警示；不得把下降解释为“通过了”——任何
   实质下降都应在发布记录中给出 disposition（按 §18.4 至少 P2 级评审）。
4. **逐 crate 观察。** 单 crate 相对上一报告跌幅 ≥ $crateWarningPercentPoints pp
   时脚本打印警示行，供门禁收口（M9）与 §18.3 高风险模块（protocol/varint/offset/
   graph/alias/encoding/atomic edit）复核参考；逐 crate 数字不设硬门禁（小 crate
   的百分比对几行代码极敏感）。
5. **谁更新数字。** 数字只能由 ``scripts/coverage.ps1`` 运行产生并整体写回本文件；
   人工改动数字块视为伪造数据。合法下降（新代码带新测试前的中间态等）必须连同
   运行输出一起提交，并在 release 记录中说明。
6. **如何重跑。** 见“测量命令”节；前置条件：cargo-llvm-cov（``cargo install
   cargo-llvm-cov``）与 rustup 组件 llvm-tools-preview（``rustup component add
   llvm-tools-preview``）。脚本缺工具时以明确消息失败（exit 2），不自动安装。
"@

$reportFilePath = Join-Path $workspaceRoot $ReportPath
$reportDirectory = Split-Path -Parent $reportFilePath
New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
# BOM-less UTF-8 to match the repository's markdown encoding.
[System.IO.File]::WriteAllText(
    $reportFilePath,
    $report,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "report written: $reportFilePath"
Write-Output "total: $totalLine"

# --- Gate exit ---------------------------------------------------------------

if ($gateMessages.Count -gt 0) {
    foreach ($message in $gateMessages) {
        Write-Output "gate FAIL: $message"
    }
    exit 1
}
if ($otherFiles.Count -gt 0) {
    Write-Output "note: $($otherFiles.Count) file(s) not attributed to a workspace crate (listed in the report)"
}
exit 0
