# Contributing to consema-rs（Consema Rust 参考实现）

Consema 六仓拆分的 Rust 仓：本仓承载 Rust 参考实现（15 个 crate）与编译期
嵌入的 conformance 数据；规范权威（RFC / docs / 路线图 / conformance suites）
在[规范仓](https://github.com/consema/consema)。

**社区治理以规范仓主文档为准**：报 bug / 提 feature / RFC 流程 / 提交规范 /
评审规范 / 标签体系 / 发布纪律 / 行为准则，一律参见
[consema/CONTRIBUTING.md](https://github.com/consema/consema/blob/main/CONTRIBUTING.md)。
本文件只列本仓特有内容。

## 开发环境

- Rust stable；MSRV 1.85（workspace `rust-version`，CI msrv job 真实验证）。
- 供应链门禁：`cargo deny check`（deny.toml）与 `cargo audit`（RustSec）。

## 构建与测试

```text
cargo build --workspace
cargo test --workspace
cargo test -p consema-conformance --locked   # 18 套语言无关 suite / 519 cases
```

lint 与 CI 一致：

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked   # CI 带 RUSTDOCFLAGS=-D warnings（ci.yml lint job）
```

## 贡献点

- **Rust 实现**：15 个 crate（`consema-core` / `consema-pvce` / `consema-graph` /
  `consema-document` / 八格式族（json、toml、yaml、ini、properties、xml、
  plist、hcl）/ `consema-protocol` / `consema-conformance` / `consema` CLI
  facade）。
- **Conformance 数据同步**：`conformance/` 是从规范仓 vendored 的快照副本
  （编译期 include 需要），权威在规范仓；任何改动必须回到规范仓提交后再同步
  本仓，并在规范仓更新聚合 digest 与计数。
- **差分 harness**：`consema-conformance` 承载语言无关向量 runner、硬化测试
  与基准工具；跨语言差分脚本在其余语言仓（其脚本构建本仓 Rust emitter 对拍），
  本仓 `scripts/` 负责 coverage 与发布供应链（SBOM / 签名 / 归档校验）。
- **fuzz**：证据与账本由规范仓管理（`docs/fuzz-evidence-*`），本仓驱动脚本
  的改动须遵循规范仓账本纪律。

## CI 门禁

`.github/workflows/ci.yml` 十二个 job：lint（fmt + clippy + rustdoc，三 OS）/
test（三 OS）/ coverage（硬下限 + 趋势门禁）/ msrv / conformance / deny /
audit / semver / package / check-version-consistency / examples /
release-build（release-profile 编译腿），外加 check 聚合门禁（branch
protection 只要求 `check (all gates green)` 这一个 check，见 ci.yml）。
push 到 main 或 PR 均触发；PR 另带 pr-labels.yml 的 kind 标签检查
（如实注记（波 5 P2）：该检查不是分支保护必选——必选只有 check 聚合；
PR 无 kind 标签时该检查红但不会阻断合并，标签见规范仓 .github/LABELS.md）。

## 发布与安全

- 发布：本仓 [RELEASING.md](RELEASING.md)（crates.io，14 个 crate，trusted
  publishing；tag `v*` 触发 release workflow，不要手动发布）。
- 安全：[SECURITY.md](SECURITY.md)；披露统一走规范仓 SECURITY.md 的渠道。
