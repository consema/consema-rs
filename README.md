# Consema Rust workspace（consema-rs）

Consema 语言中立契约（RFC 0016：portable value、无损文档、类型化查询、投影、
materialization 与结构编辑）的 **Rust 参考实现**。

本仓库是 Consema 六仓拆分中的 Rust 仓：规范权威（RFC、docs、路线图、跨语言
conformance suites）在 [github.com/consema/consema](https://github.com/consema/consema)；
本仓只承载 Rust 实现与编译期嵌入的 conformance 数据。

## Workspace（15 crates）

- `consema-core`：PortableValue、诊断、Capability 和类型化查询协议；
- `consema-pvce`：PVCE/1 规范编码与严格解码；
- `consema-graph`：PortableGraph、PGCE/1 与 graph query；
- `consema-document`：不可变 source snapshot、Span、NodeRef、materialization、
  edit plan、proof 与 ChangeSet 公共事实；
- `consema-json` / `consema-toml` / `consema-yaml` / `consema-ini` /
  `consema-properties` / `consema-xml` / `consema-plist` / `consema-hcl`：
  八种格式族的无损文档、原生语义、查询、投影、materialization 与原子编辑；
- `consema-protocol`：语言无关固定 schema、公共注册表、canonical JSON/PVCE
  transport 与严格 payload validation；
- `consema-conformance`：仓库内、不可发布的语言无关向量 runner、上游语料、
  固定 runtime oracle、真实配置夹具、硬化与基准工具（`publish = false`）；
- `consema`：公开 facade（CLI 二进制）。

## 构建与测试

```text
cargo build --workspace
cargo test --workspace
```

MSRV 1.85（workspace `rust-version`；CI msrv job 真实验证）。

## Conformance

- 18 套语言无关 conformance suite 共 **508/508 cases**，通过 `include_str!` /
  `include_bytes!` 编译进 `consema-conformance`（lib、examples、tests）。
  单独运行：`cargo test -p consema-conformance --locked`。
- `conformance/` 是从规范仓（consema）vendored 的快照副本（编译期 include
  需要），含 vectors / fixtures / oracles / corpora / differential；权威在
  规范仓，一致性由 CI（conformance job 的 suite-count 断言与共享 conformance
  校验）保证，任何改动必须回到规范仓提交后再同步。

## CI

`.github/workflows/ci.yml`：lint / test / coverage / msrv / conformance /
deny / audit / semver / package 九个 job（coverage 硬下限 + 趋势门禁；
semver baseline 为拆分前的 v0.8.0 crates/ 树，见 ci.yml 注释）。

## 链接

- 规范仓（RFC / docs / 路线图）：https://github.com/consema/consema
- Go 实现：https://github.com/consema/consema-go
