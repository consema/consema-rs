//! Deterministic PortableValue materialization for TOML 1.0.

use crate::{Document, TomlItem, TomlItemKind, TomlProfile, parse};
use consema_core::{
    AssociationLocation, AssociationRole, BinaryFloat64, Date, Decimal, Diagnostic,
    DiagnosticCategory, DiagnosticSeverity, LocalDateTime, OffsetDateTime, PortableValue,
    PortableValueKind, Time, ValuePath, ValuePathSegment,
};
use consema_document::{
    CompleteMaterialization, FailedMaterializationAttempt, MappingPolicy, MaterializationFailure,
    MaterializationFidelity, MaterializationInputLocation, MaterializationLimits,
    MaterializationProvenanceEntry, MaterializationProvenanceMap, MaterializationRelation,
    MaterializationReport, MaterializationRequest, MaterializationResult, MaterializedOrigin,
    NewlinePolicy, ParseLimits, SourceEncoding,
};
use std::collections::HashSet;
use std::fmt::{self, Write as _};

/// Materializes one complete PortableValue into a new immutable TOML document.
#[must_use]
pub fn materialize(
    value: &PortableValue,
    request: &MaterializationRequest,
) -> MaterializationResult<Document> {
    let mut attempt = Attempt::default();
    match materialize_complete(value, request, &mut attempt) {
        Ok(complete) => MaterializationResult::Complete(complete),
        Err(failure) => MaterializationResult::Failed(FailedMaterializationAttempt {
            failure,
            report: attempt.report,
            analyzed_input_paths: attempt.analyzed,
        }),
    }
}

/// Renders one canonical TOML value fragment for structural editing.
pub(crate) fn canonical_fragment(
    value: &PortableValue,
    limits: MaterializationLimits,
) -> Result<Vec<u8>, MaterializationFailure> {
    let mut analyzed = Vec::new();
    let mut writer = TomlWriter::new(NewlinePolicy::Lf, limits, &mut analyzed);
    writer.value(value, &ValuePath::root(), 0)?;
    Ok(writer.output.finish())
}

#[derive(Default)]
struct Attempt {
    report: MaterializationReport,
    analyzed: Vec<ValuePath>,
}

fn materialize_complete(
    value: &PortableValue,
    request: &MaterializationRequest,
    attempt: &mut Attempt,
) -> Result<CompleteMaterialization<Document>, MaterializationFailure> {
    requested_contract(request)?;
    let prepared = prepare_root(value, request, &mut attempt.report)?;
    let mut writer = TomlWriter::new(request.newline(), request.limits(), &mut attempt.analyzed);
    writer.root(prepared)?;
    let bytes = writer.output.finish();
    let document = parse(bytes, TomlProfile::Toml10V1, parse_limits(request.limits()))
        .map_err(|_| MaterializationFailure::FormationFailed)?;

    let mut provenance = ProvenanceBuilder::new(&document, request.limits());
    provenance.collect(value, &ValuePath::root(), document.root())?;
    let provenance = MaterializationProvenanceMap::new(
        provenance.entries,
        document.snapshot_identity(),
        request.limits(),
    )?;
    Ok(CompleteMaterialization {
        document,
        fidelity: prepared.fidelity(),
        report: attempt.report.clone(),
        provenance,
    })
}

fn requested_contract(request: &MaterializationRequest) -> Result<(), MaterializationFailure> {
    if (
        request.target_profile().id(),
        request.target_profile().version(),
    ) != ("toml.1.0", 1)
    {
        return Err(MaterializationFailure::UnsupportedProfile);
    }
    if (request.style().id(), request.style().version()) != ("toml.canonical-document", 1) {
        return Err(MaterializationFailure::UnsupportedStyle);
    }
    if request.encoding() != SourceEncoding::Utf8 {
        return Err(MaterializationFailure::UnsupportedEncoding);
    }
    if !matches!(request.newline(), NewlinePolicy::Lf | NewlinePolicy::CrLf) {
        return Err(MaterializationFailure::UnsupportedNewline);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PreparedRoot<'a> {
    Object(&'a [consema_core::ObjectEntry]),
    Mapping(&'a [consema_core::EntryMappingEntry]),
}

impl PreparedRoot<'_> {
    const fn fidelity(self) -> MaterializationFidelity {
        match self {
            Self::Object(_) => MaterializationFidelity::Exact,
            Self::Mapping(_) => MaterializationFidelity::Transformed,
        }
    }
}

fn prepare_root<'a>(
    value: &'a PortableValue,
    request: &MaterializationRequest,
    report: &mut MaterializationReport,
) -> Result<PreparedRoot<'a>, MaterializationFailure> {
    if let Some(entries) = value.as_object() {
        return Ok(PreparedRoot::Object(entries));
    }
    let Some(entries) = value.as_entry_mapping() else {
        return Err(MaterializationFailure::Unrepresentable {
            path: ValuePath::root(),
            kind: value.kind(),
        });
    };
    if request.mapping_policy() != MappingPolicy::UniqueStringEntriesToObject {
        return Err(MaterializationFailure::Unrepresentable {
            path: ValuePath::root(),
            kind: PortableValueKind::EntryMapping,
        });
    }
    if entries.len() > request.limits().max_input_nodes {
        return Err(MaterializationFailure::ResourceLimit("input-nodes"));
    }
    let mut keys = HashSet::new();
    keys.try_reserve(entries.len())
        .map_err(|_| MaterializationFailure::ResourceLimit("mapping-key-allocation"))?;
    for (index, entry) in entries.iter().enumerate() {
        let ordinal = u64::try_from(index)
            .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
        let path = ValuePath::root().child(ValuePathSegment::EntryKey(ordinal));
        let Some(key) = entry.key().as_string() else {
            return Err(MaterializationFailure::Unrepresentable {
                path,
                kind: entry.key().kind(),
            });
        };
        if !keys.insert(key) {
            return Err(MaterializationFailure::Unrepresentable {
                path,
                kind: PortableValueKind::String,
            });
        }
    }
    let mut event = Diagnostic::new(
        "core.materialization.mapping-transformed@1",
        DiagnosticCategory::Materialization,
        DiagnosticSeverity::Info,
        None,
        0,
    );
    event
        .arguments
        .insert("from".to_owned(), "EntryMapping".to_owned());
    event.arguments.insert(
        "policy".to_owned(),
        "UniqueStringEntriesToObject".to_owned(),
    );
    event.arguments.insert("to".to_owned(), "Object".to_owned());
    *report = MaterializationReport::new(vec![event], request.limits())?;
    Ok(PreparedRoot::Mapping(entries))
}

const fn parse_limits(limits: MaterializationLimits) -> ParseLimits {
    ParseLimits {
        max_source_bytes: limits.max_output_bytes,
        max_nesting_depth: limits.max_depth,
        max_token_count: limits.max_output_bytes,
        max_node_count: limits.max_input_nodes.saturating_mul(4),
        max_diagnostics: limits.max_report_entries,
    }
}

struct TomlWriter<'a> {
    newline: NewlinePolicy,
    limits: MaterializationLimits,
    input_nodes: usize,
    output: BoundedOutput,
    analyzed: &'a mut Vec<ValuePath>,
}

impl<'a> TomlWriter<'a> {
    fn new(
        newline: NewlinePolicy,
        limits: MaterializationLimits,
        analyzed: &'a mut Vec<ValuePath>,
    ) -> Self {
        Self {
            newline,
            limits,
            input_nodes: 0,
            output: BoundedOutput::new(limits.max_output_bytes),
            analyzed,
        }
    }

    fn root(&mut self, root: PreparedRoot<'_>) -> Result<(), MaterializationFailure> {
        let path = ValuePath::root();
        self.analyze(&path, 0)?;
        match root {
            PreparedRoot::Object(entries) => {
                for entry in entries {
                    self.write_key(entry.key())?;
                    self.output.push_bytes(b" = ")?;
                    self.value(
                        entry.value(),
                        &path.child(ValuePathSegment::ObjectValue(entry.key().to_owned())),
                        1,
                    )?;
                    self.output.push_bytes(self.newline.bytes())?;
                }
                if entries.is_empty() {
                    self.output.push_bytes(self.newline.bytes())?;
                }
            }
            PreparedRoot::Mapping(entries) => {
                for (index, entry) in entries.iter().enumerate() {
                    let ordinal = u64::try_from(index)
                        .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
                    let key_path = path.child(ValuePathSegment::EntryKey(ordinal));
                    self.analyze(&key_path, 1)?;
                    let key =
                        entry
                            .key()
                            .as_string()
                            .ok_or(MaterializationFailure::Unrepresentable {
                                path: key_path,
                                kind: entry.key().kind(),
                            })?;
                    self.write_key(key)?;
                    self.output.push_bytes(b" = ")?;
                    self.value(
                        entry.value(),
                        &path.child(ValuePathSegment::EntryValue(ordinal)),
                        1,
                    )?;
                    self.output.push_bytes(self.newline.bytes())?;
                }
                if entries.is_empty() {
                    self.output.push_bytes(self.newline.bytes())?;
                }
            }
        }
        Ok(())
    }

    fn value(
        &mut self,
        value: &PortableValue,
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.analyze(path, depth)?;
        match value.kind() {
            PortableValueKind::Boolean => self.output.push_bytes(
                if value
                    .as_boolean()
                    .expect("PortableValue kind and view agree")
                {
                    b"true"
                } else {
                    b"false"
                },
            ),
            PortableValueKind::Integer => {
                let integer = value
                    .as_integer()
                    .expect("PortableValue kind and view agree");
                if integer.to_i64().is_none() {
                    return Self::unrepresentable(path, value.kind());
                }
                write!(&mut self.output, "{integer}")
                    .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))
            }
            PortableValueKind::BinaryFloat64 => self.write_float(
                value
                    .as_binary_float64()
                    .expect("PortableValue kind and view agree"),
                path,
            ),
            PortableValueKind::String => self.write_string(
                value
                    .as_string()
                    .expect("PortableValue kind and view agree"),
            ),
            PortableValueKind::Date => self.write_date(
                value.as_date().expect("PortableValue kind and view agree"),
                path,
            ),
            PortableValueKind::Time => self.write_time(
                value.as_time().expect("PortableValue kind and view agree"),
                path,
            ),
            PortableValueKind::LocalDateTime => self.write_local_datetime(
                value
                    .as_local_date_time()
                    .expect("PortableValue kind and view agree"),
                path,
            ),
            PortableValueKind::OffsetDateTime => self.write_offset_datetime(
                value
                    .as_offset_date_time()
                    .expect("PortableValue kind and view agree"),
                path,
            ),
            PortableValueKind::Sequence => self.write_sequence(
                value
                    .as_sequence()
                    .expect("PortableValue kind and view agree"),
                path,
                depth,
            ),
            PortableValueKind::Object => self.write_inline_object(
                value
                    .as_object()
                    .expect("PortableValue kind and view agree"),
                path,
                depth,
            ),
            kind => Self::unrepresentable(path, kind),
        }
    }

    fn analyze(&mut self, path: &ValuePath, depth: usize) -> Result<(), MaterializationFailure> {
        if depth > self.limits.max_depth {
            return Err(MaterializationFailure::ResourceLimit("input-depth"));
        }
        self.input_nodes = self.input_nodes.saturating_add(1);
        if self.input_nodes > self.limits.max_input_nodes {
            return Err(MaterializationFailure::ResourceLimit("input-nodes"));
        }
        self.analyzed
            .try_reserve(1)
            .map_err(|_| MaterializationFailure::ResourceLimit("analysis-allocation"))?;
        self.analyzed.push(path.clone());
        Ok(())
    }

    fn write_key(&mut self, value: &str) -> Result<(), MaterializationFailure> {
        self.write_string(value)
    }

    fn write_string(&mut self, value: &str) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'"')?;
        for character in value.chars() {
            match character {
                '\u{0008}' => self.output.push_bytes(br"\b")?,
                '\t' => self.output.push_bytes(br"\t")?,
                '\n' => self.output.push_bytes(br"\n")?,
                '\u{000c}' => self.output.push_bytes(br"\f")?,
                '\r' => self.output.push_bytes(br"\r")?,
                '"' => self.output.push_bytes(br#"\""#)?,
                '\\' => self.output.push_bytes(br"\\")?,
                '\u{0000}'..='\u{001f}' | '\u{007f}' => {
                    write!(&mut self.output, "\\u{:04X}", u32::from(character))
                        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
                }
                _ => {
                    let mut encoded = [0_u8; 4];
                    self.output
                        .push_bytes(character.encode_utf8(&mut encoded).as_bytes())?;
                }
            }
        }
        self.output.push_byte(b'"')
    }

    fn write_float(
        &mut self,
        value: BinaryFloat64,
        path: &ValuePath,
    ) -> Result<(), MaterializationFailure> {
        let bits = value.bits();
        let float = f64::from_bits(bits);
        if float.is_nan() {
            return match bits {
                0x7ff8_0000_0000_0000 => self.output.push_bytes(b"nan"),
                0xfff8_0000_0000_0000 => self.output.push_bytes(b"-nan"),
                _ => Self::unrepresentable(path, PortableValueKind::BinaryFloat64),
            };
        }
        if float == f64::INFINITY {
            return self.output.push_bytes(b"inf");
        }
        if float == f64::NEG_INFINITY {
            return self.output.push_bytes(b"-inf");
        }
        let mut output = float.to_string();
        if !output.contains(['.', 'e', 'E']) {
            output.push_str(".0");
        }
        self.output.push_bytes(output.as_bytes())
    }

    fn write_date(&mut self, value: &Date, path: &ValuePath) -> Result<(), MaterializationFailure> {
        let Some(year) = value
            .year()
            .to_i64()
            .filter(|year| (0..=9999).contains(year))
        else {
            return Self::unrepresentable(path, PortableValueKind::Date);
        };
        write!(
            &mut self.output,
            "{year:04}-{:02}-{:02}",
            value.month(),
            value.day()
        )
        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))
    }

    fn write_time(&mut self, value: &Time, path: &ValuePath) -> Result<(), MaterializationFailure> {
        let Some(mut nanoseconds) = exact_nanoseconds(value.fractional_second()) else {
            return Self::unrepresentable(path, PortableValueKind::Time);
        };
        write!(
            &mut self.output,
            "{:02}:{:02}:{:02}",
            value.hour(),
            value.minute(),
            value.second()
        )
        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
        if nanoseconds != 0 {
            let mut width = 9usize;
            while nanoseconds % 10 == 0 {
                nanoseconds /= 10;
                width -= 1;
            }
            write!(&mut self.output, ".{nanoseconds:0width$}")
                .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
        }
        Ok(())
    }

    fn write_local_datetime(
        &mut self,
        value: &LocalDateTime,
        path: &ValuePath,
    ) -> Result<(), MaterializationFailure> {
        self.write_date(value.date(), path)?;
        self.output.push_byte(b'T')?;
        self.write_time(value.time(), path)
    }

    fn write_offset_datetime(
        &mut self,
        value: &OffsetDateTime,
        path: &ValuePath,
    ) -> Result<(), MaterializationFailure> {
        self.write_local_datetime(value.local(), path)?;
        let seconds = value.offset_seconds();
        if seconds == 0 {
            return self.output.push_byte(b'Z');
        }
        if seconds % 60 != 0 {
            return Self::unrepresentable(path, PortableValueKind::OffsetDateTime);
        }
        let minutes = seconds / 60;
        if minutes.unsigned_abs() >= 24 * 60 {
            return Self::unrepresentable(path, PortableValueKind::OffsetDateTime);
        }
        let sign = if minutes < 0 { '-' } else { '+' };
        let magnitude = minutes.unsigned_abs();
        write!(
            &mut self.output,
            "{sign}{:02}:{:02}",
            magnitude / 60,
            magnitude % 60
        )
        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))
    }

    fn write_sequence(
        &mut self,
        values: &[PortableValue],
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'[')?;
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                self.output.push_bytes(b", ")?;
            }
            let ordinal = u64::try_from(index)
                .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
            self.value(
                value,
                &path.child(ValuePathSegment::SequenceElement(ordinal)),
                depth.saturating_add(1),
            )?;
        }
        self.output.push_byte(b']')
    }

    fn write_inline_object(
        &mut self,
        entries: &[consema_core::ObjectEntry],
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'{')?;
        if !entries.is_empty() {
            self.output.push_byte(b' ')?;
        }
        for (index, entry) in entries.iter().enumerate() {
            if index != 0 {
                self.output.push_bytes(b", ")?;
            }
            self.write_key(entry.key())?;
            self.output.push_bytes(b" = ")?;
            self.value(
                entry.value(),
                &path.child(ValuePathSegment::ObjectValue(entry.key().to_owned())),
                depth.saturating_add(1),
            )?;
        }
        if !entries.is_empty() {
            self.output.push_byte(b' ')?;
        }
        self.output.push_byte(b'}')
    }

    fn unrepresentable<T>(
        path: &ValuePath,
        kind: PortableValueKind,
    ) -> Result<T, MaterializationFailure> {
        Err(MaterializationFailure::Unrepresentable {
            path: path.clone(),
            kind,
        })
    }
}

fn exact_nanoseconds(value: &Decimal) -> Option<u32> {
    if value.coefficient().to_i64()? == 0 {
        return Some(0);
    }
    let exponent = value.exponent().to_i64()?;
    if !(-9..0).contains(&exponent) {
        return None;
    }
    let mut nanoseconds = value.coefficient().to_i64()?;
    if nanoseconds < 0 {
        return None;
    }
    for _ in 0..(exponent + 9) {
        nanoseconds = nanoseconds.checked_mul(10)?;
    }
    u32::try_from(nanoseconds)
        .ok()
        .filter(|value| *value < 1_000_000_000)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    max: usize,
}

impl BoundedOutput {
    const fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
        }
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), MaterializationFailure> {
        self.push_bytes(&[byte])
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Result<(), MaterializationFailure> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
        if new_len > self.max {
            return Err(MaterializationFailure::ResourceLimit("output-bytes"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| MaterializationFailure::ResourceLimit("output-allocation"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Write for BoundedOutput {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_bytes(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

struct ProvenanceBuilder<'a> {
    document: &'a Document,
    limits: MaterializationLimits,
    units: usize,
    entries: Vec<MaterializationProvenanceEntry>,
}

impl<'a> ProvenanceBuilder<'a> {
    const fn new(document: &'a Document, limits: MaterializationLimits) -> Self {
        Self {
            document,
            limits,
            units: 0,
            entries: Vec::new(),
        }
    }

    fn collect(
        &mut self,
        input: &PortableValue,
        path: &ValuePath,
        output: TomlItem<'_>,
    ) -> Result<(), MaterializationFailure> {
        let relation = if input.kind() == PortableValueKind::EntryMapping {
            MaterializationRelation::Reencoded
        } else {
            MaterializationRelation::Direct
        };
        self.push_origin(
            MaterializationInputLocation::Value(path.clone()),
            self.origin(output.node_ref(), output.span(), relation),
        )?;

        match input.kind() {
            PortableValueKind::Sequence => {
                if output.kind() != TomlItemKind::Array {
                    return Err(MaterializationFailure::FormationFailed);
                }
                let values = input
                    .as_sequence()
                    .ok_or(MaterializationFailure::FormationFailed)?;
                let elements = output
                    .array_elements()
                    .ok_or(MaterializationFailure::FormationFailed)?;
                if values.len() != elements.len() {
                    return Err(MaterializationFailure::FormationFailed);
                }
                for (index, (value, element)) in values.iter().zip(elements).enumerate() {
                    let ordinal = u64::try_from(index)
                        .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
                    let child_path = path.child(ValuePathSegment::SequenceElement(ordinal));
                    self.collect(value, &child_path, element.item())?;
                    self.add_output(
                        &MaterializationInputLocation::Value(child_path),
                        self.origin(
                            element.node_ref(),
                            element.span(),
                            MaterializationRelation::Generated,
                        ),
                    )?;
                }
            }
            PortableValueKind::Object => {
                self.collect_object(
                    input
                        .as_object()
                        .ok_or(MaterializationFailure::FormationFailed)?,
                    path,
                    output,
                )?;
            }
            PortableValueKind::EntryMapping => {
                self.collect_mapping(
                    input
                        .as_entry_mapping()
                        .ok_or(MaterializationFailure::FormationFailed)?,
                    path,
                    output,
                )?;
            }
            kind if !scalar_kind_matches(kind, output.kind()) => {
                return Err(MaterializationFailure::FormationFailed);
            }
            _ => {}
        }
        Ok(())
    }

    fn collect_object(
        &mut self,
        inputs: &[consema_core::ObjectEntry],
        path: &ValuePath,
        output: TomlItem<'_>,
    ) -> Result<(), MaterializationFailure> {
        let entries = output
            .table_entries()
            .ok_or(MaterializationFailure::FormationFailed)?;
        if inputs.len() != entries.len() {
            return Err(MaterializationFailure::FormationFailed);
        }
        for (index, (input, entry)) in inputs.iter().zip(entries).enumerate() {
            if input.key() != entry.name() {
                return Err(MaterializationFailure::FormationFailed);
            }
            let ordinal = u64::try_from(index)
                .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
            self.push_origin(
                MaterializationInputLocation::Association(AssociationLocation::new(
                    path.clone(),
                    ordinal,
                    AssociationRole::ObjectEntry,
                )),
                self.origin(
                    entry.node_ref(),
                    entry.span(),
                    MaterializationRelation::Direct,
                ),
            )?;
            self.push_origin(
                MaterializationInputLocation::Association(AssociationLocation::new(
                    path.clone(),
                    ordinal,
                    AssociationRole::ObjectKey,
                )),
                self.origin(
                    entry.key_node_ref(),
                    self.document.entity(entry.entity().key).span,
                    MaterializationRelation::Direct,
                ),
            )?;
            self.collect(
                input.value(),
                &path.child(ValuePathSegment::ObjectValue(input.key().to_owned())),
                entry.item(),
            )?;
        }
        Ok(())
    }

    fn collect_mapping(
        &mut self,
        inputs: &[consema_core::EntryMappingEntry],
        path: &ValuePath,
        output: TomlItem<'_>,
    ) -> Result<(), MaterializationFailure> {
        let entries = output
            .table_entries()
            .ok_or(MaterializationFailure::FormationFailed)?;
        if inputs.len() != entries.len() {
            return Err(MaterializationFailure::FormationFailed);
        }
        for (index, (input, entry)) in inputs.iter().zip(entries).enumerate() {
            let ordinal = u64::try_from(index)
                .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
            if input.key().as_string() != Some(entry.name()) {
                return Err(MaterializationFailure::FormationFailed);
            }
            self.push_origin(
                MaterializationInputLocation::Association(AssociationLocation::new(
                    path.clone(),
                    ordinal,
                    AssociationRole::EntryMappingEntry,
                )),
                self.origin(
                    entry.node_ref(),
                    entry.span(),
                    MaterializationRelation::Reencoded,
                ),
            )?;
            self.push_origin(
                MaterializationInputLocation::Value(
                    path.child(ValuePathSegment::EntryKey(ordinal)),
                ),
                self.origin(
                    entry.key_node_ref(),
                    self.document.entity(entry.entity().key).span,
                    MaterializationRelation::Reencoded,
                ),
            )?;
            self.collect(
                input.value(),
                &path.child(ValuePathSegment::EntryValue(ordinal)),
                entry.item(),
            )?;
        }
        Ok(())
    }

    fn origin(
        &self,
        node: consema_document::NodeRef,
        span: consema_document::Span,
        relation: MaterializationRelation,
    ) -> MaterializedOrigin {
        MaterializedOrigin {
            snapshot: self.document.snapshot_identity(),
            node,
            span,
            relation,
        }
    }

    fn push_origin(
        &mut self,
        input: MaterializationInputLocation,
        output: MaterializedOrigin,
    ) -> Result<(), MaterializationFailure> {
        self.units = self
            .units
            .checked_add(2)
            .ok_or(MaterializationFailure::ResourceLimit("provenance-entries"))?;
        if self.units > self.limits.max_provenance_entries {
            return Err(MaterializationFailure::ResourceLimit("provenance-entries"));
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| MaterializationFailure::ResourceLimit("provenance-allocation"))?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve(1)
            .map_err(|_| MaterializationFailure::ResourceLimit("provenance-allocation"))?;
        outputs.push(output);
        self.entries
            .push(MaterializationProvenanceEntry { input, outputs });
        Ok(())
    }

    fn add_output(
        &mut self,
        input: &MaterializationInputLocation,
        output: MaterializedOrigin,
    ) -> Result<(), MaterializationFailure> {
        self.units = self
            .units
            .checked_add(1)
            .ok_or(MaterializationFailure::ResourceLimit("provenance-entries"))?;
        if self.units > self.limits.max_provenance_entries {
            return Err(MaterializationFailure::ResourceLimit("provenance-entries"));
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| &entry.input == input)
            .ok_or(MaterializationFailure::FormationFailed)?;
        entry
            .outputs
            .try_reserve(1)
            .map_err(|_| MaterializationFailure::ResourceLimit("provenance-allocation"))?;
        entry.outputs.push(output);
        Ok(())
    }
}

const fn scalar_kind_matches(input: PortableValueKind, output: TomlItemKind) -> bool {
    matches!(
        (input, output),
        (PortableValueKind::String, TomlItemKind::String)
            | (PortableValueKind::Integer, TomlItemKind::Integer)
            | (PortableValueKind::BinaryFloat64, TomlItemKind::Float)
            | (PortableValueKind::Boolean, TomlItemKind::Boolean)
            | (PortableValueKind::Date, TomlItemKind::LocalDate)
            | (PortableValueKind::Time, TomlItemKind::LocalTime)
            | (
                PortableValueKind::LocalDateTime,
                TomlItemKind::LocalDateTime
            )
            | (
                PortableValueKind::OffsetDateTime,
                TomlItemKind::OffsetDateTime
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProjectionRequest, ProjectionResult, ProjectionTarget};
    use consema_core::{BigInteger, Date, EntryMappingBuilder, ObjectBuilder, SequenceBuilder};
    use consema_document::{MaterializationStyleId, ProfileId};

    fn request(newline: NewlinePolicy) -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("toml.1.0", 1),
            MaterializationStyleId::new("toml.canonical-document", 1),
        )
        .with_newline(newline)
    }

    fn complete(result: MaterializationResult<Document>) -> CompleteMaterialization<Document> {
        match result {
            MaterializationResult::Complete(complete) => complete,
            MaterializationResult::Failed(failed) => panic!("materialization failed: {failed:?}"),
        }
    }

    #[test]
    fn canonical_document_round_trips_scalar_container_and_temporal_values() {
        let date = Date::new(BigInteger::from(2026_i64), 8, 4).unwrap();
        let time = Time::new(
            12,
            34,
            56,
            Decimal::new(BigInteger::from(123_i64), BigInteger::from(-3_i64)),
        )
        .unwrap();
        let local = LocalDateTime::new(date.clone(), time.clone());
        let offset = OffsetDateTime::new(local.clone(), 8 * 60 * 60).unwrap();
        let mut nested = ObjectBuilder::new();
        nested
            .insert("enabled", PortableValue::boolean(true))
            .unwrap();
        let mut sequence = SequenceBuilder::new();
        sequence.push(PortableValue::integer(BigInteger::from(1_i64)));
        sequence.push(PortableValue::string("two"));
        let mut root = ObjectBuilder::new();
        root.insert("date", PortableValue::date(date.clone()))
            .unwrap();
        root.insert("time", PortableValue::time(time.clone()))
            .unwrap();
        root.insert("local", PortableValue::local_date_time(local))
            .unwrap();
        root.insert("offset", PortableValue::offset_date_time(offset))
            .unwrap();
        root.insert("items", sequence.build()).unwrap();
        root.insert("nested", nested.build()).unwrap();
        root.insert(
            "float",
            PortableValue::binary_float64(BinaryFloat64::from_bits(1.5_f64.to_bits())),
        )
        .unwrap();
        root.insert(
            "nan",
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0000)),
        )
        .unwrap();
        let input = root.build();
        let result = complete(materialize(&input, &request(NewlinePolicy::Lf)));
        let projection = result
            .document
            .project(ProjectionRequest::new(ProjectionTarget::BestExactCoreV1));
        assert!(matches!(
            projection,
            ProjectionResult::Complete(ref complete) if complete.value == input
        ));
        assert_eq!(result.fidelity, MaterializationFidelity::Exact);
        assert!(result.document.render().ends_with(b"\n"));
    }

    #[test]
    fn explicit_unique_mapping_conversion_is_reported_and_reversible_as_object() {
        let mut mapping = EntryMappingBuilder::new();
        mapping.push(PortableValue::string("a"), PortableValue::boolean(true));
        mapping.push(
            PortableValue::string("b"),
            PortableValue::integer(BigInteger::from(2_i64)),
        );
        let input = mapping.build();
        let result = complete(materialize(
            &input,
            &request(NewlinePolicy::CrLf)
                .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject),
        ));
        assert_eq!(result.fidelity, MaterializationFidelity::Transformed);
        assert_eq!(result.report.events().len(), 1);
        assert_eq!(
            result.report.events()[0].code,
            "core.materialization.mapping-transformed@1"
        );
        assert_eq!(result.document.render(), b"\"a\" = true\r\n\"b\" = 2\r\n");
        let projection = result
            .document
            .project(ProjectionRequest::new(ProjectionTarget::BestExactCoreV1));
        let mut expected = ObjectBuilder::new();
        expected.insert("a", PortableValue::boolean(true)).unwrap();
        expected
            .insert("b", PortableValue::integer(BigInteger::from(2_i64)))
            .unwrap();
        assert!(matches!(
            projection,
            ProjectionResult::Complete(ref complete) if complete.value == expected.build()
        ));
    }

    #[test]
    fn unrepresentable_values_and_implicit_mapping_conversion_fail() {
        let too_large =
            PortableValue::integer(BigInteger::parse_decimal("9223372036854775808").unwrap());
        let mut root = ObjectBuilder::new();
        root.insert("value", too_large).unwrap();
        assert!(matches!(
            materialize(&root.build(), &request(NewlinePolicy::Lf)),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable {
                    kind: PortableValueKind::Integer,
                    ..
                },
                ..
            })
        ));

        let mut mapping = EntryMappingBuilder::new();
        mapping.push(PortableValue::string("x"), PortableValue::boolean(true));
        assert!(matches!(
            materialize(&mapping.build(), &request(NewlinePolicy::Lf)),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable {
                    kind: PortableValueKind::EntryMapping,
                    ..
                },
                ..
            })
        ));

        let mut duplicate = EntryMappingBuilder::new();
        duplicate.push(PortableValue::string("x"), PortableValue::boolean(true));
        duplicate.push(PortableValue::string("x"), PortableValue::boolean(false));
        assert!(matches!(
            materialize(
                &duplicate.build(),
                &request(NewlinePolicy::Lf)
                    .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable {
                    kind: PortableValueKind::String,
                    ..
                },
                ..
            })
        ));

        let mut nan_root = ObjectBuilder::new();
        nan_root
            .insert(
                "nan",
                PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0001)),
            )
            .unwrap();
        assert!(matches!(
            materialize(&nan_root.build(), &request(NewlinePolicy::Lf)),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable {
                    kind: PortableValueKind::BinaryFloat64,
                    ..
                },
                ..
            })
        ));

        let mut limited = ObjectBuilder::new();
        limited
            .insert("value", PortableValue::boolean(true))
            .unwrap();
        assert!(matches!(
            materialize(
                &limited.build(),
                &request(NewlinePolicy::Lf).with_limits(MaterializationLimits {
                    max_output_bytes: 3,
                    ..MaterializationLimits::default()
                })
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::ResourceLimit("output-bytes"),
                ..
            })
        ));

        let mut reported = EntryMappingBuilder::new();
        reported.push(PortableValue::string("x"), PortableValue::boolean(true));
        assert!(matches!(
            materialize(
                &reported.build(),
                &request(NewlinePolicy::Lf)
                    .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject)
                    .with_limits(MaterializationLimits {
                        max_report_entries: 0,
                        ..MaterializationLimits::default()
                    })
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::ResourceLimit("report-entries"),
                ..
            })
        ));
        assert!(matches!(
            materialize(&ObjectBuilder::new().build(), &request(NewlinePolicy::None)),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedNewline,
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &ObjectBuilder::new().build(),
                &request(NewlinePolicy::Lf).with_encoding(SourceEncoding::Utf16Be)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedEncoding,
                ..
            })
        ));
    }
}
