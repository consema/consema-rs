# Consema 语言无关 Conformance Suites

本目录保存跨语言可复放的行为契约。向量只使用 strict JSON，二进制位模式、任意精度数字和 wire 结果使用字符串表示，避免宿主语言的数值模型改变预期事实。

当前 suite：

- `vectors/v1.json`：`consema.conformance@1`，覆盖 0.1.0 core、PVCE、JSON、query、projection 与 edit 基线，共 30 个 case；
- `vectors/toml-v1.json`：`consema.toml.conformance@1`，覆盖 `toml.1.0@1` 的 document、native items、query、projection、edit、limits 与真实工程语料，共 18 个 case；
- `vectors/protocol-v1.json`：`consema.protocol.conformance@1`，覆盖 15 个稳定 payload、canonical JSON/PVCE、registry/error code、process-local identity 拒绝与资源边界，共 32 个 case；
- `vectors/source-v1.json`：`consema.source.conformance@1`，覆盖 raw identity、五种 encoding、decoded location、binary coverage、SourcePatch 与资源失败，共 28 个 case；
- `vectors/syntax-query-v1.json`：`consema.syntax-query.conformance@1`，以共享案例覆盖 JSON/TOML lossless kind/text/order/selection/limit/cancellation 与 cursor terminal，共 19 个 case；
- `vectors/protocol-v2.json`：`consema.protocol.conformance@2`，覆盖 semantic-model v2 registry、SourceSnapshot/SourcePatch 双传输、伪造事实拒绝与 wire 后验证，共 11 个 case；
- `vectors/operations-v1.json`：`consema.operations.conformance@1`，覆盖 JSON/TOML materialization、两向 conversion、format operation registry、结构编辑与冲突矩阵、dry-run/SourcePatch/UntouchedByteProof、semantic-model v3 双传输和资源边界，共 35 个 case；
- `vectors/json-family-v2.json`：`consema.json-family.conformance@2`，覆盖 JSON5 形成、精确数值、query v2、投影、materialization、跨方言 conversion、表示保持编辑、同对象 member move、semantic-model v4 与资源边界，共 33 个 case；
- `vectors/portable-graph-v1.json`：`consema.portable-graph.conformance@1`，覆盖 PortableGraph 同构与拓扑语义、PGCE/1 固定字节、严格拒绝、循环、确定性图查询及资源边界，共 10 个 case；
- `vectors/semantic-model-v5.json`：`consema.semantic-model-v5.conformance@1`，覆盖 v1-v4 registry 冻结、v5 graph/YAML payload 双传输、角色/关联/来源约束、process-local 拒绝、稳定 error code 与 wire mutation，共 22 个 case；
- `vectors/yaml-v1.json`：`consema.yaml.conformance@1`，覆盖 YAML 1.2/1.1 Profile、encoding、stream、lossless/native/graph、query、projection、materialization、edit、恢复（undefined anchor、version-directive 拒绝）与 limits（depth、alias 预算），共 31 个 case；
- `vectors/semantic-model-v6.json`：`consema.semantic-model-v6.conformance@1`，覆盖 v1-v5 registry 冻结、INI/Properties 外部 query payload、精确 Java UTF-16 code units、source encoding facts、错误码与 wire mutation，共 25 个 case；
- `vectors/ini-v1.json`：`consema.ini.conformance@1`，覆盖 Portable、Windows、Python ConfigParser 三个显式 Profile 的 formation、encoding、query、projection、materialization、八类 edit 与 limits，共 20 个 case；
- `vectors/java-properties-v1.json`：`consema.java-properties.conformance@1`，覆盖 Reader/Latin-1 Profile、自然行/逻辑行、Java UTF-16、query、projection、materialization、五类 edit、limits 与家族 parse/encoding 失败（malformed unicode escape、invalid sequence、BOM conflict），共 25 个 case；
- `vectors/xml-1-0-safe-v1.json`：`consema.xml-1-0-safe.conformance@1`，覆盖 namespace-aware 无损 Document、显式 source/encoding contract、bounded safe DOCTYPE、恢复与诊断、native/syntax query、三种 projection、canonical materialization、八类 edit 与 limits，共 34 个 case；
- `vectors/plist-v1.json`：`consema.plist.conformance@1`，覆盖 XML/binary 双表示形成、全部值类型、双表示 round-trip 转换、native/syntax/binary query、projection、materialization、六类 edit 与 limits（含 binary container-depth/object-count/string-code-units/data-bytes 失败 case），共 49 个 case；
- `vectors/hcl-v1.json`：`consema.hcl.conformance@1`，覆盖 formation、全部表达式/模板/heredoc 文法、恢复、双查询域、projection、materialization、六类（tfvars 四类）edit 与 limits，共 57 个 case；
- `vectors/cli-v1.json`：`consema.cli.conformance@1`，覆盖 RFC 0015 的 11 个正式命令、exit-code 分类、`core.cli-output@1` 机器信封、plan/apply 批量状态机与 secret redaction，共 40 个 case；
- `oracles/java-properties-v1/`：固定 Microsoft OpenJDK 25.0.4 的 `java.util.Properties` Reader/Latin-1 行为，共 11 个差分 case；
- `oracles/python-configparser-v1/`：固定 CPython 3.14.6 默认 `ConfigParser` 的 formation、DEFAULT/raw view、Unicode `optionxform` 与异常分类，共 9 个差分 case；
- `oracles/dotnet-ini-v1/`：固定 .NET SDK 10.0.302 / `IniConfigurationProvider` 10.0.10 的扁平化、大小写等价、引号与重复拒绝行为，共 7 个差分 case；
- `oracles/windows-ini-v1/`：固定 Windows wide profile API、`kernel32.dll` 与 Windows build 的检索/枚举行为，共 5 个差分 case；
- `oracles/qt-ini-v1/`：固定 Qt 6.10.2 `QSettings::IniFormat` 与官方 MinGW 13.1.0 的 portable shared subset，共 4 个差分 case；
- `corpora/json5-v2.2.3.json`：固定到 JSON5 官方 `v2.2.3`/`c3a7524` 的 43 个接受与 39 个拒绝输入（文件内 82 项；门禁口径 83 = 82 + 1 个完整真实夹具），记录上游来源、Git blob、LF 存储变换和 MIT 许可；
- `corpora/mutation-v1.json`：mutation 语料（46 fixtures / 174,921 cases + regressions 数组，0.13.0 gate plan M2）：逐 fixture 字节 mutation 全集 + fuzz 回归输入；确定性重放生成，`-- --check` 门禁保证与生成器同步（新增回归条目永久入 corpus，见 `corpora/README.md`）；
- `differential/`：跨语言差分 case 集单一权威（byte-parity `cases.json` 68 / `normalized/cases.json` 108 / `protocol-exchange/cases.json` 83），2026-08-12 由 `00c850d` 自 `go/conformance/differential/` 迁入；五语言 harness 与 verify 脚本统一从本目录取数，各语言侧测试断言精确计数（68/108/83），任何一侧漂移即红；
- `fixtures/json5/package-json5-v2.2.3.json5`：官方完整真实 JSON5 配置夹具；
- `fixtures/real-world/`：覆盖 package JSON、TypeScript/VS Code JSONC 与服务 JSON5 的非专有典型项目配置；
- `fixtures/toml/`：由向量按仓库相对路径引用的合法与非法 TOML 真实语料；其中 `toml.corpus.cargo-manifest` 向量（`vectors/toml-v1.json:104`）的裸根引用 `"Cargo.toml"` 按**特判约定**解析为 `fixtures/toml/Cargo.toml`（`943c014` 归位的单一权威，与 consema-rs 根清单逐字节一致；TS runner 显式特判，typescript/src/conformance/suites/toml_v1.ts:33-36）——裸根路径不指向任何仓库根文件，五语言 runner 与 provision 均按此约定解析，不向 workspace 根复制 Cargo.toml；
- `fixtures/yaml/`：Kubernetes、GitHub Actions、Compose 与 anchor-heavy 自有 MIT 工程夹具，无 secret 或第三方复制内容；
- `fixtures/ini/`：桌面应用、.NET 风格服务、Python 工具、mixed-newline 与显式 CP1252 自有 MIT 工程夹具；
- `fixtures/properties/`：logging、localization、build tool、Windows path、continuation、Latin-1 与 Java UTF-16 edge 自有 MIT 工程夹具；
- `corpora/licenses/yaml-test-suite-MIT.txt`：固定官方 YAML suite 的许可证证据；完整 402-case 上游数据由可复现 adapter 从固定 tag/commit 执行，不复制进仓库。

每个 case 固定包含：

- `id`：稳定测试身份；
- `capability`：被验证的版本化行为承诺；
- `input`：可直接重放的 source、fixture、profile、target 或 limit；
- `expected`：控制流和公开结果，不依赖本地化错误文本或内部 AST。

Rust runner 为：

- `consema_conformance::run_v1()`；
- `consema_conformance::run_toml_v1()`；
- `consema_conformance::run_protocol_v1()`；
- `consema_conformance::run_source_v1()`；
- `consema_conformance::run_syntax_query_v1()`；
- `consema_conformance::run_protocol_v2()`；
- `consema_conformance::run_operations_v1()`；
- `consema_conformance::run_json_family_v2()`；
- `consema_conformance::run_portable_graph_v1()`；
- `consema_conformance::run_semantic_model_v5()`；
- `consema_conformance::run_yaml_v1()`；
- `consema_conformance::run_semantic_model_v6()`；
- `consema_conformance::run_ini_v1()`；
- `consema_conformance::run_properties_v1()`；
- `consema_conformance::run_xml_v1()`；
- `consema_conformance::run_plist_v1()`；
- `consema_conformance::run_hcl_v1()`；
- `consema_conformance::run_cli_v1()`；
- `consema_conformance::run_json5_reference_corpus()`；
- `consema_conformance::run_properties_jdk25_oracle()`；
- `consema_conformance::run_ini_python_oracle()`；
- `consema_conformance::run_ini_dotnet_oracle()`；
- `consema_conformance::run_ini_windows_oracle()`；
- `consema_conformance::run_ini_qt_oracle()`。

上述 18 套语言无关向量合计 519 个 case。独立外部 gate 包括 JSON5 83 项（门禁口径 = corpus 43 valid + 39 invalid + 1 个完整真实夹具）、YAML 官方 402 项（307 valid、94 invalid、1 个显式 Profile exclusion）、TOML 官方 679 项，以及 INI/Properties 五套固定运行时 oracle 合计 36 项。每个 runner 固定校验 suite/schema/semantic-model、case ID 唯一性与未知 action 拒绝；向量或 manifest 中的 input/expected 会实际驱动执行，防止把预期值硬编码进 runner。官方参考 gate 只继承其 manifest 明示的公开行为，不继承第三方 loader 的数值降精度、未声明 duplicate collapse、implicit merge、provider layering 或语言对象构造行为。

未来 Go 实现必须直接消费相同向量和 fixture。任何实现不得用序列化本地 AST、异常对象或第三方 parser 私有类型来替代向量中的公共字段。

新增或修改行为时，必须遵循：

1. capability 或 profile 的既有语义不变时，增加 case；
2. 既有语义发生不兼容变化时，创建新 suite/profile/operator version；
3. runner 只是执行器，向量和对应 RFC 才是跨语言事实；
4. 每个 suite 必须验证 case 数量，防止 runner 静默跳过未知项。
