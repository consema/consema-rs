# Changelog

Consema 遵循 Semantic Versioning。本仓变更记录以规范仓 CHANGELOG 为权威；完整历史与跨语言时间线见 github.com/consema/consema 的 CHANGELOG.md。

## 1.0.0-rc.1（2026-08-10）

六仓拆分落地：本仓自规范仓（github.com/consema/consema）拆分独立（2026-08-12），承载 Rust 参考实现（workspace 版本 1.0.0-rc.1，MSRV 1.85）。版本日期以规范仓 CHANGELOG 的 2026-08-10 记录为权威（版本推进 commit；本仓拆分装配 commit `6bcb068` 于 2026-08-12 落地该版本）。

- crates 拆分落地：自规范仓 `crates/` 迁移组装 15 crate workspace（consema-core / pvce / graph / document / protocol / 八格式族 / conformance / facade CLI），版本沿 0.13.0 基线推进 1.0.0-rc.1；
- conformance 数据以 vendored 快照编译期嵌入（`conformance/`，`include_str!`/`include_bytes!`），权威在规范仓，任何改动必须先回规范仓提交再同步；
- 门禁沿 0.13.0 基线：`cargo test --workspace --locked` 1,636 passed / 0 failed（本仓实测 2026-08-14；规范仓 2026-08-10 基线记录同命令实测 1,629，见规范仓 CHANGELOG "Verified（2026-08-10 实测）" 节，数字随基线后测试演进）、18 套语言无关 suite 519/519（聚合 digest cfd6e296…）、semver 基线为拆分前 v0.8.0 crates/ 树；
- CI（ci.yml）12 job + check 聚合：lint / test / coverage（硬下限 + 趋势门禁）/ msrv / conformance / deny / audit / semver / package / check-version-consistency / examples / release-build（release-profile 编译腿，wave-4 R13 加入）；
- 完整历史与跨语言时间线见规范仓 CHANGELOG。
