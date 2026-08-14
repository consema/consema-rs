# Consema 0.13.0 Coverage Report

- 报告体例：由 `scripts/coverage.ps1` 整体生成（政策文本也在脚本内；禁止手改数字块）。
  本文件是 0.13.0 门禁 M3 的“报告数值入库”载体（gate plan §4 M3、§7 验收表：
  “coverage 可复现报告”）。
- 取代一次性数字：规范仓（github.com/consema/consema）CHANGELOG.md 与
  docs/RELEASE-0.8.0.md 记录的 84.65% regions / 82.73% functions / 86.59%
  lines 是单次辅助报告，无脚本、无工件、不可复现；自本报告起 coverage 由
  常设脚本在固定 commit 上产出，任何数字变化都来自脚本运行。



## 本次测量

- 测量 commit：`d7d1554`（d7d1554f7078be9b8619824f1f768f79cf8d96e7）
- 测量日期：2026-08-13 13:08:44 +08:00（机器：FRANCK-PC / Microsoft Windows 11 专业版）
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
coverage.commit=d7d1554f7078be9b8619824f1f768f79cf8d96e7
coverage.short-commit=d7d1554
coverage.date=2026-08-13 13:08:44 +08:00
coverage.total regions=86.79 functions=83.08 lines=88.20
coverage.crate consema regions=85.20 functions=79.55 lines=84.78
coverage.crate consema-conformance regions=80.99 functions=66.19 lines=85.14
coverage.crate consema-core regions=81.09 functions=88.97 lines=80.81
coverage.crate consema-document regions=93.29 functions=93.52 lines=92.98
coverage.crate consema-graph regions=86.93 functions=85.82 lines=88.00
coverage.crate consema-hcl regions=92.25 functions=94.40 lines=92.52
coverage.crate consema-ini regions=88.46 functions=89.43 lines=89.69
coverage.crate consema-json regions=88.34 functions=94.17 lines=89.58
coverage.crate consema-plist regions=92.47 functions=92.20 lines=93.33
coverage.crate consema-properties regions=87.84 functions=89.37 lines=90.52
coverage.crate consema-protocol regions=84.47 functions=78.81 lines=85.17
coverage.crate consema-pvce regions=76.67 functions=84.21 lines=78.60
coverage.crate consema-toml regions=85.91 functions=92.08 lines=87.14
coverage.crate consema-xml regions=85.28 functions=85.96 lines=86.53
coverage.crate consema-yaml regions=86.44 functions=88.96 lines=88.40
```

| crate | regions % | functions % | lines % |
|---|---:|---:|---:|
| consema | 85.20 | 79.55 | 84.78 |
| consema-conformance | 80.99 | 66.19 | 85.14 |
| consema-core | 81.09 | 88.97 | 80.81 |
| consema-document | 93.29 | 93.52 | 92.98 |
| consema-graph | 86.93 | 85.82 | 88.00 |
| consema-hcl | 92.25 | 94.40 | 92.52 |
| consema-ini | 88.46 | 89.43 | 89.69 |
| consema-json | 88.34 | 94.17 | 89.58 |
| consema-plist | 92.47 | 92.20 | 93.33 |
| consema-properties | 87.84 | 89.37 | 90.52 |
| consema-protocol | 84.47 | 78.81 | 85.17 |
| consema-pvce | 76.67 | 84.21 | 78.60 |
| consema-toml | 85.91 | 92.08 | 87.14 |
| consema-xml | 85.28 | 85.96 | 86.53 |
| consema-yaml | 86.44 | 88.96 | 88.40 |
| **workspace total** | **86.79** | **83.08** | **88.20** |

## 方法与范围

- 目标集统一为门禁布局：`--workspace --all-targets --locked`（与 M1 ci.yml 的
  test job 同一目标集）——workspace 全部 lib、`consema` facade 的 bin、examples、
  全部 test target 都计入。
- 语料复用：conformance vectors 与 fixtures 通过 `include_str!`/`include_bytes!`
  编译进 `consema-conformance` 的 lib 与集成测试（`consema-conformance/src/*_v1.rs`、
  `tests/*_fixtures.rs`），因此本测量天然执行 18 套 suite / 519 case、fixtures、
  hardening 与 encoding corpus，无需额外接线。
- 百分比从 `llvm-cov export --summary-only`（JSON）的每文件 covered/total 求和
  重算（与 llvm-cov TOTAL 行同一聚合语义）；region 列即 llvm-cov 的 Region 指标
  （Rust stable 上由 `-C instrument-coverage` 的 region counter 给出）。
- 行/函数/region 均为“至少执行一次”计数；测试二进制自身代码随
  `--all-targets` 计入。doctest 不经 llvm-cov 插桩（rustdoc 单独编译，不参与
  本测量），不在本报告覆盖内。
- 未归属到任何 crate 的文件会在上方列出（如有）；当前仓库无 workspace
  `[features]`（gate plan §0.1），故无 `--all-features` 腿；若将来引入 features，
  需在本节补记。

## CI 环境耦合事实（2026-08-13 记录，G154 文档化处置）

1. **趋势门禁的平台耦合。** 本报告的基线数字在本机（FRANCK-PC / Windows 11，
   rustc 1.97.1 stable-msvc）实测；ci.yml 的 coverage job 在 ubuntu-latest 上
   重新测量并跑 `-Trend` 对比本报告。Windows 与 ubuntu 的覆盖率数值存在
   平台差异（编译器 codegen 与标准库内联行为不同），趋势门禁因此存在设计级
   环境耦合：本地无法逐字复现 CI 的测量。**风险**：跨平台差异可能造成 CI 红
   而本地绿（或相反），趋势比较不是纯代码回归探测器。**缓解**：门槛余量
   （跌幅严格超过 1.0 pp 才失败）远大于实测平台差异；CI 与发布里程碑测量
   均以同一脚本同参数执行；任何趋势失败都以 CI 数字为准并在发布记录中
   disposition。
2. **wall-clock 断言。** workspace 共 4 处墙钟断言（完整清单，2026-08-14
   复核）：
   - `consema-yaml/src/materialization.rs` 的 B-7/B-8 回归测试两处
     （`elapsed < 8.0s`，debug 构建，2026-08-13 实测两条链路余量均在
     20x 以上）；
   - `consema-xml/src/parser.rs` `many_small_elements_formation_scales_linearly`
     一处（`elapsed.as_secs() < 20`，10k 元素 formation 线性回归守卫，
     2026-08-14 实测整测试 0.18s，余量远大于 20x）；
   - `consema-document/src/source.rs`
     `per_call_coordinate_conversion_does_not_rescan_large_utf8_sources`
     一处（`elapsed.as_secs() < 5`，逐调用坐标转换防重扫守卫，2026-08-14
     实测整测试 1.09s，余量约 4-5x）。
   **风险**：墙钟断言环境耦合（慢机/负载抖动可能误红）。**缓解**：断言值
   针对修复前 O(n²) 实现的耗时（~30-60 s debug / ~6.7 s release）设上限，
   固定实现余量极宽（xml/source 两处亦为线性回归守卫，上限针对修复前
   行为）；误红时按修复前基线人工复核，不降低断言值。

## Coverage 政策（路线图 §18.3 落地）

1. **Coverage 不替代语义证明。** 本报告的百分比只是回归探测器。质量证据的权威
   来源是 conformance 519/519 向量、byte-exact round-trip 证明、hardening 测试、
   差分 oracle、fuzz（0.13.0 M2/M8）与 API 审查（M4）；任何发布记录都不得把单一
   coverage 百分比当作质量证明引用。本报告取代规范仓 CHANGELOG.md 记录的
   一次性数字，
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