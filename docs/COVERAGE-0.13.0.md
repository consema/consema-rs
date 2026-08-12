# Consema 0.13.0 Coverage Report

- 报告体例：由 `scripts/coverage.ps1` 整体生成（政策文本也在脚本内；禁止手改数字块）。
  本文件是 0.13.0 门禁 M3 的“报告数值入库”载体（gate plan §4 M3、§7 验收表：
  “coverage 可复现报告”）。
- 取代一次性数字：CHANGELOG.md:176 与 RELEASE-0.8.0.md:98 的 84.65% regions /
  82.73% functions / 86.59% lines 是单次辅助报告，无脚本、无工件、不可复现；自本
  报告起 coverage 由常设脚本在固定 commit 上产出，任何数字变化都来自脚本运行。



## 本次测量

- 测量 commit：`9c1ede2`（9c1ede20fab56829cfaeca6924ee115ff01cd5d2）
- 测量日期：2026-08-07 14:11:50 +08:00（机器：FRANCK-PC / Microsoft Windows 11 专业版）
- 工作树状态：clean（与记录 commit 完全一致）。
- 工具链：rustc 1.97.1 (8bab26f4f 2026-07-14)；cargo 1.97.1 (c980f4866 2026-06-30)；cargo-llvm-cov 0.8.7
- 测量命令（与脚本执行等价的重现命令）：

```text
cargo llvm-cov --workspace --all-targets --locked --no-clean --json --summary-only --output-path target/coverage/summary.json --fail-under-regions 70 --fail-under-functions 70 --fail-under-lines 80
```

重跑：`powershell -File scripts/coverage.ps1`；发布里程碑用
`powershell -File scripts/coverage.ps1 -Trend`。

## 数字（脚本从 llvm-cov summary JSON 汇总；逐行精确到 0.01 个百分点）

```text
coverage.commit=9c1ede20fab56829cfaeca6924ee115ff01cd5d2
coverage.short-commit=9c1ede2
coverage.date=2026-08-07 14:11:50 +08:00
coverage.total regions=86.51 functions=82.82 lines=87.91
coverage.crate consema regions=84.15 functions=78.59 lines=83.56
coverage.crate consema-conformance regions=80.97 functions=66.10 lines=85.19
coverage.crate consema-core regions=81.05 functions=88.97 lines=80.75
coverage.crate consema-document regions=92.93 functions=93.49 lines=92.44
coverage.crate consema-graph regions=86.93 functions=85.82 lines=88.00
coverage.crate consema-hcl regions=91.96 functions=94.05 lines=92.17
coverage.crate consema-ini regions=88.28 functions=89.43 lines=89.59
coverage.crate consema-json regions=88.15 functions=94.13 lines=89.39
coverage.crate consema-plist regions=92.38 functions=91.87 lines=93.20
coverage.crate consema-properties regions=87.83 functions=89.37 lines=90.52
coverage.crate consema-protocol regions=84.29 functions=78.61 lines=85.01
coverage.crate consema-pvce regions=76.67 functions=84.21 lines=78.60
coverage.crate consema-toml regions=85.55 functions=92.03 lines=86.82
coverage.crate consema-xml regions=85.10 functions=85.05 lines=86.33
coverage.crate consema-yaml regions=85.23 functions=88.21 lines=87.36
```

| crate | regions % | functions % | lines % |
|---|---:|---:|---:|
| consema | 84.15 | 78.59 | 83.56 |
| consema-conformance | 80.97 | 66.10 | 85.19 |
| consema-core | 81.05 | 88.97 | 80.75 |
| consema-document | 92.93 | 93.49 | 92.44 |
| consema-graph | 86.93 | 85.82 | 88.00 |
| consema-hcl | 91.96 | 94.05 | 92.17 |
| consema-ini | 88.28 | 89.43 | 89.59 |
| consema-json | 88.15 | 94.13 | 89.39 |
| consema-plist | 92.38 | 91.87 | 93.20 |
| consema-properties | 87.83 | 89.37 | 90.52 |
| consema-protocol | 84.29 | 78.61 | 85.01 |
| consema-pvce | 76.67 | 84.21 | 78.60 |
| consema-toml | 85.55 | 92.03 | 86.82 |
| consema-xml | 85.10 | 85.05 | 86.33 |
| consema-yaml | 85.23 | 88.21 | 87.36 |
| **workspace total** | **86.51** | **82.82** | **87.91** |

## 方法与范围

- 目标集统一为门禁布局：`--workspace --all-targets --locked`（与 M1 ci.yml 的
  test job 同一目标集）——workspace 全部 lib、`consema` facade 的 bin、examples、
  全部 test target 都计入。
- 语料复用：conformance vectors 与 fixtures 通过 `include_str!`/`include_bytes!`
  编译进 `consema-conformance` 的 lib 与集成测试（`crates/consema-conformance/src/*_v1.rs`、
  `tests/*_fixtures.rs`），因此本测量天然执行 18 套 suite / 508 case、fixtures、
  hardening 与 encoding corpus，无需额外接线。
- 百分比从 `llvm-cov export --summary-only`（JSON）的每文件 covered/total 求和
  重算（与 llvm-cov TOTAL 行同一聚合语义）；region 列即 llvm-cov 的 Region 指标
  （Rust stable 上由 `-C instrument-coverage` 的 region counter 给出）。
- 行/函数/region 均为“至少执行一次”计数；doctest 与测试二进制自身代码随 cargo
  test 默认包含。
- 未归属到任何 crate 的文件会在上方列出（如有）；当前仓库无 workspace
  `[features]`（gate plan §0.1），故无 `--all-features` 腿；若将来引入 features，
  需在本节补记。

## Coverage 政策（路线图 §18.3 落地）

1. **Coverage 不替代语义证明。** 本报告的百分比只是回归探测器。质量证据的权威
   来源是 conformance 508/508 向量、byte-exact round-trip 证明、hardening 测试、
   差分 oracle、fuzz（0.13.0 M2/M8）与 API 审查（M4）；任何发布记录都不得把单一
   coverage 百分比当作质量证明引用。本报告取代 CHANGELOG.md:176 的一次性数字，
   也不再制造新的单次数字。
2. **硬下限（每次运行都强制）。** `scripts/coverage.ps1` 每次运行都带
   `--fail-under-*`，workspace 总 coverage 低于 regions ≥ 70% /
   functions ≥ 70% / lines ≥ 80% 即失败（exit 1）。
   下限远低于当前实测值，只作灾难性回退的兜底，不构成刷覆盖率的目标。
3. **趋势门禁（-Trend 模式，发布里程碑执行）。** 与上一个入库报告（git 提交于
   HEAD 的 `docs/COVERAGE-0.13.0.md`）比较 workspace 总 region/function/line：
   任一指标跌幅超过 1 个百分点即失败（exit 1）。跌幅在
   0 到 1 pp 之间打印警示；不得把下降解释为“通过了”——任何
   实质下降都应在发布记录中给出 disposition（按 §18.4 至少 P2 级评审）。
4. **逐 crate 观察。** 单 crate 相对上一报告跌幅 ≥ 2 pp
   时脚本打印警示行，供门禁收口（M9）与 §18.3 高风险模块（protocol/varint/offset/
   graph/alias/encoding/atomic edit）复核参考；逐 crate 数字不设硬门禁（小 crate
   的百分比对几行代码极敏感）。
5. **谁更新数字。** 数字只能由 `scripts/coverage.ps1` 运行产生并整体写回本文件；
   人工改动数字块视为伪造数据。合法下降（新代码带新测试前的中间态等）必须连同
   运行输出一起提交，并在 release 记录中说明。
6. **如何重跑。** 见“测量命令”节；前置条件：cargo-llvm-cov（`cargo install
   cargo-llvm-cov`）与 rustup 组件 llvm-tools-preview（`rustup component add
   llvm-tools-preview`）。脚本缺工具时以明确消息失败（exit 2），不自动安装。