# Consema Rust workspace（consema-rs）

![CI](https://img.shields.io/github/actions/workflow/status/consema/consema-rs/ci.yml?branch=main)
![Version](https://img.shields.io/github/v/tag/consema/consema-rs)
![License](https://img.shields.io/github/license/consema/consema-rs)

Consema 语言中立契约（RFC 0016：portable value、无损文档、类型化查询、投影、
materialization 与结构编辑）的 **Rust 参考实现**。

本仓库是 Consema 六仓拆分中的 Rust 仓：规范权威（RFC、docs、路线图、跨语言
conformance suites）在 [github.com/consema/consema](https://github.com/consema/consema)；
本仓只承载 Rust 实现与编译期嵌入的 conformance 数据。

Workspace version: 1.0.0-rc.1（`Cargo.toml` `[workspace.package] version`；CI
check-version-consistency job 断言与 README 一致）。

## 快速开始（30 秒跑通）

```toml
[dependencies]
consema = "1.0.0-rc.1"
```

把下面代码放进 `src/main.rs`（一个 JSON 文档走完 parse → query → edit → render 四条链）：

```rust
use std::sync::Arc;

use consema::core::{BigInteger, PortableValue};
use consema::document::ProfileId;
use consema::json::{
    EditTransactionBuilder, JsonValue, RepresentationPolicy, SemanticAvailability,
};
use consema::registry::parse_document;

/// 原生语义树成员查找（查询助手；完整操作符查询见 sdk_chain 示例）。
fn member<'a>(value: JsonValue<'a>, name: &str) -> JsonValue<'a> {
    let SemanticAvailability::Available(Some(members)) = value.object_members() else {
        panic!("not an object");
    };
    members
        .into_iter()
        .find(|m| matches!(m.name(), SemanticAvailability::Available(n) if n == name))
        .expect("member")
        .value()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source: Arc<[u8]> = Arc::from(br#"{"a":1,"b":{"c":2}}"#.as_slice());
    // 1. parse：json.strict 无损解析，render() 与源字节逐字节一致
    let document = parse_document(source, &ProfileId::new("json.strict", 1))?;
    let json = document.as_json()?;
    // 2. query：原生语义树读 `b.c`
    let c = member(member(json.root(), "b"), "c");
    // 3. edit：`b.c` 语义替换为 42（CanonicalForProfile），编辑外字节原样保留
    let mut builder = EditTransactionBuilder::new(json);
    builder.semantic_scalar(
        c.node_ref(),
        PortableValue::integer(BigInteger::from(42)),
        RepresentationPolicy::CanonicalForProfile,
    );
    let edited = json.commit(&builder.build())?.document;
    // 4. render：输出 `{"a":1,"b":{"c":42}}`
    println!("{}", String::from_utf8_lossy(edited.render()));
    Ok(())
}
```

完整链示例（parse → 操作符式原生语义查询 → best-exact 投影 → 结构编辑 → canonical 物化 → 跨格式转换到 TOML）：[`consema/examples/sdk_chain.rs`](consema/examples/sdk_chain.rs)，运行 `cargo run -p consema --example sdk_chain`。

## API 摘要

核心面一行式（完整签名见源码 doc；八个格式家族各有独立的 `parse_*` / `execute_*_query` / `project` / `materialize` / `convert_*` 入口）：

| 操作 | facade 入口 |
| --- | --- |
| parse | `consema::registry::parse_document(source: Arc<[u8]>, profile: &ProfileId) -> Result<Document, FatalFormationFailure>` |
| query | `consema::json::execute_json_query(&ExecutableQuery, &json::Document, QueryLimits, &CancellationToken) -> Result<QueryExecution<JsonMatch>, QueryFailure>` |
| project | `json::Document::project(&ProjectionRequest) -> ProjectionResult`（请求：`ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1).build()`） |
| edit | `json::EditTransactionBuilder::new(&json::Document)` + `json::Document::commit(&EditTransaction) -> Result<EditCommit, EditFailure>`（`commit.document` 为编辑后文档） |
| materialize | `consema::json::materialize(&PortableValue, &MaterializationRequest) -> document::MaterializationResult` |
| convert | `consema::convert_json(&json::Document, &json::ProjectionRequest, &MaterializationRequest) -> ConversionResult`（另有 convert_toml / convert_yaml / convert_ini / convert_properties / convert_xml / convert_plist / convert_hcl） |
| registry | `registry::format_families()` / `registry::profiles()` / `registry::query_domains()` / `registry::operation_registry(&ProfileId)`（8 家族 / 16 profiles / 21 查询域 / 16 操作注册表） |

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

- 18 套语言无关 conformance suite 共 **519/519 cases**，通过 `include_str!` /
  `include_bytes!` 编译进 `consema-conformance`（lib、examples、tests）。
  单独运行：`cargo test -p consema-conformance --locked`。
- `conformance/` 是从规范仓（consema）vendored 的快照副本（编译期 include
  需要），含 vectors / fixtures / oracles / corpora / differential；权威在
  规范仓。本仓 CI 的 conformance job 断言 suite-count（18 套 / 519 case）；
  共享 conformance 的聚合 digest 校验在 Go 仓与规范仓 fc-manifest。任何
  改动必须回到规范仓提交后再同步。

## CI

`.github/workflows/ci.yml`：lint / test / coverage / msrv / conformance /
deny / audit / semver / package / check-version-consistency / examples
十一个 job，外加 check 聚合门禁（coverage 硬下限 + 趋势门禁；
semver baseline 为拆分前的 v0.8.0 crates/ 树，见 ci.yml 注释）。

## FAQ

- **支持哪些配置格式？** 八个格式家族、16 个 profiles：JSON（`json.strict@1` / `jsonc.bounded@1` / `json5.standard@1`）、TOML（`toml.1.0@1`）、YAML（`yaml.1.2-core@1` / `yaml.1.1-compat@1`）、INI（`ini.portable@1` / `ini.windows@1` / `ini.python-configparser@1`）、Java Properties（`java-properties.reader@1` / `java-properties.latin1@1`）、XML（`xml.1.0-safe@1`）、Property List（`plist.xml@1` / `plist.binary@1`）、HCL（`hcl.native@1` / `hcl.tfvars@1`）。完整面枚举见 `registry::profiles()`。
- **与 serde 的关系？** 无依赖关系：serde 是 Rust 类型序列化框架，Consema 是格式内容处理引擎（无损文档、公共值、类型化查询、显式投影、原子编辑、跨格式转换），二者可共存。契约是语言中立的（RFC 0016），五个语言实现同等地位、互不调用。
- **性能如何？** 解析/渲染基准、硬化语料与基准工具见规范仓 `docs/BENCHMARKS-0.13.0.md`（consema-conformance 基准工具）；CI 带 coverage 硬下限 + 趋势门禁与 deny/audit/semver 门禁。
- **零依赖吗？** 发布 crates 的 7 个 workspace 外部依赖全部精确固定版本（`=x.y.z`）：encoding_rs、sha2、toml_edit、saphyr-parser、unicode-id-start、unicode-ident、xmlparser；此外 CLI facade（consema crate）依赖 `ctrlc = "3.5"`（非精确固定，Cargo.lock 当前为 3.5.2）。
- **跨语言一致性如何保证？** 18 套语言无关 conformance suite 共 519/519 cases（聚合 digest `cfd6e296…`）由规范仓维护、五仓共享；CI 多仓 checkout 跑 conformance runner 与跨语言差分（byte parity / normalized differential / protocol-exchange）门禁。
- **兼容承诺？** 语义化版本；`check-version-consistency` 门禁断言 README 版本行与 `Cargo.toml` 一致；semver-check 基线为拆分前 v0.8.0 树；兼容与支持政策见 RFC 0020。
- **如何贡献？** 见本仓 [CONTRIBUTING.md](CONTRIBUTING.md)（规范仓为权威版）；conformance 向量/夹具/oracle/差分数据权威在规范仓——向量变更是五仓同步事件，必须先回规范仓提交再同步五个语言仓。
- **"默认拒绝信息损失"是什么意思？** 投影/转换/编辑中的任何 loss（如 YAML 共享结构展开、Properties 重复键折叠、数值舍入）必须显式授权；未授权时操作原子失败（`ConversionResult::Failed(ConversionFailure::UnauthorizedLoss)`；fidelity 三档：Exact / Transformed / Lossy）。

## 六仓导航

| 仓库 | 角色 |
| --- | --- |
| [consema](https://github.com/consema/consema) | 规范 / RFC / 路线图 / 审计证据 / conformance 仲裁层（语言无关权威） |
| [consema-rs](https://github.com/consema/consema-rs)（本仓） | Rust 参考实现 |
| [consema-go](https://github.com/consema/consema-go) | Go 实现 |
| [consema-ts](https://github.com/consema/consema-ts) | TypeScript 实现 |
| [consema-py](https://github.com/consema/consema-py) | Python 实现 |
| [consema-kt](https://github.com/consema/consema-kt) | Kotlin 实现 |

## 文档导航

- 规范仓（RFC / docs / 路线图 / conformance 权威）：https://github.com/consema/consema
- [RFC 0001-0016](https://github.com/consema/consema/tree/main/docs/rfcs) + [RFC 0020 兼容与支持政策](https://github.com/consema/consema/blob/main/docs/rfcs/0020-compatibility-and-support-policy-v1.md)：语言无关规范的权威载体
- [1.0.0 产品路线图](https://github.com/consema/consema/blob/main/Consema%201.0.0%20产品路线图与双语言落地设计.md)
- [平台接入指南](https://github.com/consema/consema/blob/main/docs/platform-integration-guide.md)
- [CLI Cookbook（可复制配方）](https://github.com/consema/consema/blob/main/docs/cookbook.md)
- [多语言实现计划](https://github.com/consema/consema/blob/main/docs/multi-language-implementation-plan.md) / [五语言 CI 设计](https://github.com/consema/consema/blob/main/docs/five-language-ci-design.md)
