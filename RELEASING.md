# Consema Rust 发布流程（crates.io）

本文件是 consema-rs 仓库的发布操作手册（六仓统一纪律见 consema 仓库根
`RELEASING.md`；发布供应链的签名/SBOM/checksum 流程见
consema 仓库 `docs/release-process-0.13.0.md`）。发布是**半自动**的：
版本 bump、CHANGELOG、tag 由人完成；tag 推送后 `.github/workflows/release.yml`
自动把 14 个可发布 crate 按依赖序发布到 crates.io。

- 14 个可发布 crate：`consema-core` `consema-document` `consema-graph`
  `consema-pvce` `consema-json` `consema-toml` `consema-yaml` `consema-ini`
  `consema-properties` `consema-xml` `consema-plist` `consema-hcl`
  `consema-protocol` `consema`（`consema-conformance` 为 `publish = false`，
  只进仓库不打进发布归档，与 verify-package-archives.ps1 及 release.yml 的
  package 门禁（`--exclude consema-conformance`）语义一致）。
- 发布顺序即依赖拓扑序，由 workflow 运行时用 `scripts/publish-order.jq`
  从 `cargo metadata` 的依赖图计算（Kahn 算法，就绪 crate 间按字母序决胜，
  确定性可复现）：每个 crate 的仓内依赖必先于它发布，facade `consema`
  依赖全部 13 个兄弟 crate，故恒为最后、`consema-core` 恒为第一（唯一
  无仓内依赖的 crate；verify-tag 的 resume 探测依赖这一点）。当前 14 个
  crate 的计算结果依次为 core → document → graph → hcl → ini → json →
  plist → properties → pvce → protocol → toml → xml → yaml → consema。
  workflow 中任一 crate 失败即中止，人工处置后重推 tag（或手动补发剩余 crate）。

## 1. 发布步骤（人执行的部分）

1. **版本 bump**：改根 `Cargo.toml` `[workspace.package] version`，同时改
   `README.md` 的 `Workspace version:` 行（`check-version-consistency` 门禁
   断言这两者相等——精确 token 比较（ci.yml 该 job 内注释 G116），bump
   漏改 README 会让 CI 红；同一 job 的 G073 步骤还断言 `README.md` 其余
   位置与 `.github/ISSUE_TEMPLATE/bug_report.yml` 中零版本字面量——新版本
   值一旦硬编码进这些文件就会让 CI 红，所以只允许 `Workspace version:` 行
   一处出现）。版本值字面量实测还出现在：
   依赖方成员 crate `Cargo.toml` 的 workspace 依赖钉（`version` 依赖声明）、
   `CHANGELOG.md` 发布记录（历史载体）与 `scripts/release-sign.ps1` 的 tag
   示例注释；`README.md` 快速开始栅栏用 `<当前版本>` 占位符、
   `.github/ISSUE_TEMPLATE/bug_report.yml` 不写版本字面量。
2. **CHANGELOG 策展**：在根 `CHANGELOG.md` 记录本版本变更（G156：consema
   仓库的 `docs/CHANGELOG.md` 只是勘误页，主记录以根 `CHANGELOG.md` 为
   权威，与其余语言仓同口径）；跨语言变更同步到 consema 仓库根
   `CHANGELOG.md`（组织纪律见 consema 仓 RELEASING.md）。
3. **质量门禁全绿**：main 分支 CI `check (all gates green)` 全绿
   （清单见各仓 ci 配置；其中 `package` job 已常设证明 14 个发布归档
   可从干净环境重建，发布前无需重复打包）。
4. **打 tag 并推送**（发布动作的唯一触发点；语义版本号规范见
   consema 仓 RELEASING.md）：
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
   推送后 `.github/workflows/release.yml` 自动发布；发布 workflow 首先校验
   tag↔版本一致（tag 去掉 `v` 前缀必须等于 Cargo.toml
   `[workspace.package] version`，不一致即 exit 1 中止），并校验 **tag 指向
   main 分支历史**（tag 的 commit 必须是 main HEAD 的祖先；且与 main HEAD
   的提交时间差不超过 24 小时——从陈旧 commit 打 tag 会被拒绝；main 在
   tag 推送后落入新 commit 不会误伤，无需 force 重推）。24 小时窗口只约束
   **首次推送**：若该版本已有 crate 发布到 crates.io（部分发布失败后重推
   tag 续发剩余 crate，G042），守卫识别为 resume 重推，只做祖先校验、
   跳过 24 小时窗口——部分失败后超过 24 小时重推 tag 仍可续发；若失败
   发生在任何 crate 发布之前（无 crate 落 crates.io，无 resume 依据），
   重推 tag 仍会被窗口拒绝，此时应把 tag 改到新的 main commit 上再推
   （版本号未变则校验仍通过）或手动补发。校验通过才进入发布步骤；
   **不要**在 tag 之外手动执行 cargo publish（除非处置失败重试）。

## 2. 凭证配置（用户侧一次性动作）

crates.io **trusted publishing**（OIDC）于 2025-07 GA（RFC #3691），
是本仓库的推荐路径：无长期 token，GitHub Actions 的 `id-token: write`
交换 30 分钟短期 publish token，workflow 结束自动吊销。`release.yml`
已按该机制编写（`rust-lang/crates-io-auth-action@v1`）。

### 2.1 首次发布（必须手动，一次即可）

crates.io 要求 crate 先存在才能挂 trusted publisher，因此各发布 crate 的
**第一次**发布必须手动：

```bash
# 需要本机 crates.io API token（账号 → Account settings → API tokens）
cargo login
# 按依赖序逐个发布（--locked 与 CI 一致）
cargo publish --locked -p consema-core
# …依序发布其余发布 crate（crate 数以 workspace 声明为准）
```

手动首发的替代方案：在 GitHub 仓库 Settings → Secrets and variables →
Actions 配置 `CARGO_REGISTRY_TOKEN`（crates.io API token），直接推 tag 让
workflow 用 fallback 路径发布；发布成功后建议删除该 secret，切换 trusted
publishing。

### 2.2 配置 trusted publisher（每个 crate 一次）

1. 登录 crates.io，进入每个 crate 的 Settings → Trusted Publishers →
   Add GitHub trusted publisher：
   - **Repository owner/name**：`consema/consema-rs`（区分大小写）
   - **Workflow file name**：`release.yml`（必须与本文件精确一致；
     `pull_request_target` / `workflow_run` 触发不被支持）
   - Environment 留空（workflow 未声明 environment）
2. 全部发布 crate 配置完后，可删除 `CARGO_REGISTRY_TOKEN` secret，
   并在 crate 设置启用 "Trusted Publishing Only"。
3. 验证：推送 tag 后，workflow 的 OIDC 交换步骤应成功（不产生
   `continue-on-error` 警告），后续 `cargo publish` 步骤用
   `steps.auth.outputs.token`。

### 2.3 回退路径（trusted publishing 未配置时）

`release.yml` 的每个 publish 步骤读
`CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token || secrets.CARGO_REGISTRY_TOKEN }}`：
OIDC 交换未配置时自动回退到仓库 secret。两路凭证都缺失时发布步骤明确失败
（cargo 401/403），不会静默跳过。

## 3. 发布后核对

1. crates.io 各 crate 页面确认版本可见（发布 crate 逐个）。
2. GitHub Actions 中 release workflow 全部步骤成功。
3. docs.rs 构建（crates.io 自动触发）成功后，crate 页 documentation 链接
   生效（每个 crate 的 Cargo.toml 已声明
   `documentation = https://docs.rs/<crate>`）。
4. 跨语言同步：按 consema 仓 RELEASING.md 的检查单核对其他语言仓的发布
   状态（版本同步发布为 P1 记录，1.0.0 首发时做最终决策）。
