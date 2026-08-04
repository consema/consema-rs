//! Deterministic PortableValue materialization for JSON-family profiles.

use crate::{Document, JsonProfile, JsonValue, JsonValueKind, SemanticAvailability, parse};
use consema_core::{
    AssociationLocation, AssociationRole, PortableValue, PortableValueKind, ValuePath,
    ValuePathSegment,
};
use consema_document::{
    CompleteMaterialization, FailedMaterializationAttempt, MaterializationFailure,
    MaterializationFidelity, MaterializationInputLocation, MaterializationLimits,
    MaterializationProvenanceEntry, MaterializationProvenanceMap, MaterializationRelation,
    MaterializationReport, MaterializationRequest, MaterializationResult, MaterializedOrigin,
    NewlinePolicy, ParseLimits, SourceEncoding,
};
use std::fmt::{self, Write as _};

/// Materializes one complete PortableValue into a new immutable JSON or JSONC document.
#[must_use]
pub fn materialize(
    value: &PortableValue,
    request: &MaterializationRequest,
) -> MaterializationResult<Document> {
    let mut analyzed = Vec::new();
    match materialize_complete(value, request, &mut analyzed) {
        Ok(complete) => MaterializationResult::Complete(complete),
        Err(failure) => MaterializationResult::Failed(FailedMaterializationAttempt {
            failure,
            report: MaterializationReport::default(),
            analyzed_input_paths: analyzed,
        }),
    }
}

pub(crate) fn canonical_fragment(
    value: &PortableValue,
    profile: JsonProfile,
    limits: MaterializationLimits,
) -> Result<Vec<u8>, MaterializationFailure> {
    let mut analyzed = Vec::new();
    let mut writer = JsonWriter::new(
        if profile.is_json5() {
            JsonStyle::Json5Compact
        } else {
            JsonStyle::Compact
        },
        NewlinePolicy::None,
        limits,
        &mut analyzed,
    );
    writer.value(value, &ValuePath::root(), 0)?;
    Ok(writer.output.finish())
}

fn materialize_complete(
    value: &PortableValue,
    request: &MaterializationRequest,
    analyzed: &mut Vec<ValuePath>,
) -> Result<CompleteMaterialization<Document>, MaterializationFailure> {
    let profile = requested_profile(request)?;
    let style = requested_style(request, profile)?;
    if request.encoding() != SourceEncoding::Utf8 {
        return Err(MaterializationFailure::UnsupportedEncoding);
    }
    if style.is_pretty() && request.newline() == NewlinePolicy::None {
        return Err(MaterializationFailure::UnsupportedNewline);
    }

    let mut writer = JsonWriter::new(style, request.newline(), request.limits(), analyzed);
    writer.value(value, &ValuePath::root(), 0)?;
    if request.newline() != NewlinePolicy::None {
        writer.output.push_bytes(request.newline().bytes())?;
    }
    let bytes = writer.output.finish();
    let document = parse(bytes, profile, parse_limits(request.limits()))
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    if document.formation_status() != consema_document::FormationStatus::Complete {
        return Err(MaterializationFailure::FormationFailed);
    }

    let mut provenance = ProvenanceBuilder::new(&document, request.limits());
    provenance.collect(value, &ValuePath::root(), document.root())?;
    let provenance = MaterializationProvenanceMap::new(
        provenance.entries,
        document.snapshot_identity(),
        request.limits(),
    )?;
    Ok(CompleteMaterialization {
        document,
        fidelity: MaterializationFidelity::Exact,
        report: MaterializationReport::default(),
        provenance,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonStyle {
    Compact,
    Pretty,
    Json5Compact,
    Json5Pretty,
}

impl JsonStyle {
    const fn is_pretty(self) -> bool {
        matches!(self, Self::Pretty | Self::Json5Pretty)
    }

    const fn is_json5(self) -> bool {
        matches!(self, Self::Json5Compact | Self::Json5Pretty)
    }
}

fn requested_profile(
    request: &MaterializationRequest,
) -> Result<JsonProfile, MaterializationFailure> {
    match (
        request.target_profile().id(),
        request.target_profile().version(),
    ) {
        ("json.strict", 1) => Ok(JsonProfile::StrictV1),
        ("jsonc.bounded", 1) => Ok(JsonProfile::JsoncBoundedV1),
        ("json5.standard", 1) => Ok(JsonProfile::Json5StandardV1),
        _ => Err(MaterializationFailure::UnsupportedProfile),
    }
}

fn requested_style(
    request: &MaterializationRequest,
    profile: JsonProfile,
) -> Result<JsonStyle, MaterializationFailure> {
    match (profile, request.style().id(), request.style().version()) {
        (JsonProfile::StrictV1 | JsonProfile::JsoncBoundedV1, "json.canonical-compact", 1) => {
            Ok(JsonStyle::Compact)
        }
        (JsonProfile::StrictV1 | JsonProfile::JsoncBoundedV1, "json.canonical-pretty", 1) => {
            Ok(JsonStyle::Pretty)
        }
        (JsonProfile::Json5StandardV1, "json5.canonical-compact", 1) => Ok(JsonStyle::Json5Compact),
        (JsonProfile::Json5StandardV1, "json5.canonical-pretty", 1) => Ok(JsonStyle::Json5Pretty),
        _ => Err(MaterializationFailure::UnsupportedStyle),
    }
}

const fn parse_limits(limits: MaterializationLimits) -> ParseLimits {
    ParseLimits {
        max_source_bytes: limits.max_output_bytes,
        max_nesting_depth: limits.max_depth,
        max_token_count: limits.max_output_bytes,
        max_node_count: limits.max_input_nodes.saturating_mul(3),
        max_diagnostics: limits.max_report_entries,
    }
}

struct JsonWriter<'a> {
    style: JsonStyle,
    newline: NewlinePolicy,
    limits: MaterializationLimits,
    input_nodes: usize,
    output: BoundedOutput,
    analyzed: &'a mut Vec<ValuePath>,
}

impl<'a> JsonWriter<'a> {
    fn new(
        style: JsonStyle,
        newline: NewlinePolicy,
        limits: MaterializationLimits,
        analyzed: &'a mut Vec<ValuePath>,
    ) -> Self {
        Self {
            style,
            newline,
            limits,
            input_nodes: 0,
            output: BoundedOutput::new(limits.max_output_bytes),
            analyzed,
        }
    }

    fn value(
        &mut self,
        value: &PortableValue,
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.analyze(path, depth)?;

        match value.kind() {
            PortableValueKind::Null => self.output.push_bytes(b"null"),
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
            PortableValueKind::Integer => self.write_integer(
                value
                    .as_integer()
                    .expect("PortableValue kind and view agree"),
            ),
            PortableValueKind::Decimal => self.write_decimal(
                value
                    .as_decimal()
                    .expect("PortableValue kind and view agree"),
            ),
            PortableValueKind::BinaryFloat64 if self.style.is_json5() => self.write_binary_float64(
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
            PortableValueKind::Sequence => self.write_sequence(
                value
                    .as_sequence()
                    .expect("PortableValue kind and view agree"),
                path,
                depth,
            ),
            PortableValueKind::Object => self.write_object(
                value
                    .as_object()
                    .expect("PortableValue kind and view agree"),
                path,
                depth,
            ),
            PortableValueKind::EntryMapping => self.write_entry_mapping(
                value
                    .as_entry_mapping()
                    .expect("PortableValue kind and view agree"),
                path,
                depth,
            ),
            kind => Err(MaterializationFailure::Unrepresentable {
                path: path.clone(),
                kind,
            }),
        }
    }

    fn write_integer(
        &mut self,
        value: &consema_core::BigInteger,
    ) -> Result<(), MaterializationFailure> {
        write!(&mut self.output, "{value}")
            .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))
    }

    fn write_decimal(
        &mut self,
        value: &consema_core::Decimal,
    ) -> Result<(), MaterializationFailure> {
        write!(
            &mut self.output,
            "{}e{}",
            value.coefficient(),
            value.exponent()
        )
        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))
    }

    fn write_string(&mut self, value: &str) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'"')?;
        for character in value.chars() {
            match character {
                '"' => self.output.push_bytes(br#"\""#)?,
                '\\' => self.output.push_bytes(br"\\")?,
                '\u{0008}' => self.output.push_bytes(br"\b")?,
                '\u{000c}' => self.output.push_bytes(br"\f")?,
                '\n' => self.output.push_bytes(br"\n")?,
                '\r' => self.output.push_bytes(br"\r")?,
                '\t' => self.output.push_bytes(br"\t")?,
                '\u{0000}'..='\u{001f}' => {
                    write!(&mut self.output, "\\u{:04x}", u32::from(character))
                        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
                }
                '\u{2028}' | '\u{2029}' if self.style.is_json5() => {
                    write!(&mut self.output, "\\u{:04x}", u32::from(character))
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

    fn write_binary_float64(
        &mut self,
        value: consema_core::BinaryFloat64,
        path: &ValuePath,
    ) -> Result<(), MaterializationFailure> {
        let spelling: &[u8] = match value.bits() {
            0x7ff0_0000_0000_0000 => b"Infinity",
            0xfff0_0000_0000_0000 => b"-Infinity",
            0x7ff8_0000_0000_0000 => b"NaN",
            0xfff8_0000_0000_0000 => b"-NaN",
            _ => {
                return Err(MaterializationFailure::Unrepresentable {
                    path: path.clone(),
                    kind: PortableValueKind::BinaryFloat64,
                });
            }
        };
        self.output.push_bytes(spelling)
    }

    fn write_sequence(
        &mut self,
        values: &[PortableValue],
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'[')?;
        if !values.is_empty() && self.style.is_pretty() {
            self.layout_newline(depth.saturating_add(1))?;
        }
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                self.output.push_byte(b',')?;
                if self.style.is_pretty() {
                    self.layout_newline(depth.saturating_add(1))?;
                }
            }
            let ordinal = u64::try_from(index)
                .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
            self.value(
                value,
                &path.child(ValuePathSegment::SequenceElement(ordinal)),
                depth.saturating_add(1),
            )?;
        }
        if !values.is_empty() && self.style.is_pretty() {
            self.layout_newline(depth)?;
        }
        self.output.push_byte(b']')
    }

    fn write_object(
        &mut self,
        entries: &[consema_core::ObjectEntry],
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'{')?;
        if !entries.is_empty() && self.style.is_pretty() {
            self.layout_newline(depth.saturating_add(1))?;
        }
        for (index, entry) in entries.iter().enumerate() {
            self.member_separator(index, depth)?;
            self.write_string(entry.key())?;
            self.output.push_byte(b':')?;
            if self.style.is_pretty() {
                self.output.push_byte(b' ')?;
            }
            self.value(
                entry.value(),
                &path.child(ValuePathSegment::ObjectValue(entry.key().to_owned())),
                depth.saturating_add(1),
            )?;
        }
        if !entries.is_empty() && self.style.is_pretty() {
            self.layout_newline(depth)?;
        }
        self.output.push_byte(b'}')
    }

    fn write_entry_mapping(
        &mut self,
        entries: &[consema_core::EntryMappingEntry],
        path: &ValuePath,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        self.output.push_byte(b'{')?;
        if !entries.is_empty() && self.style.is_pretty() {
            self.layout_newline(depth.saturating_add(1))?;
        }
        for (index, entry) in entries.iter().enumerate() {
            self.member_separator(index, depth)?;
            let ordinal = u64::try_from(index)
                .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
            let key_path = path.child(ValuePathSegment::EntryKey(ordinal));
            self.analyze(&key_path, depth.saturating_add(1))?;
            let Some(key) = entry.key().as_string() else {
                return Err(MaterializationFailure::Unrepresentable {
                    path: key_path,
                    kind: entry.key().kind(),
                });
            };
            self.write_string(key)?;
            self.output.push_byte(b':')?;
            if self.style.is_pretty() {
                self.output.push_byte(b' ')?;
            }
            self.value(
                entry.value(),
                &path.child(ValuePathSegment::EntryValue(ordinal)),
                depth.saturating_add(1),
            )?;
        }
        if !entries.is_empty() && self.style.is_pretty() {
            self.layout_newline(depth)?;
        }
        self.output.push_byte(b'}')
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

    fn member_separator(
        &mut self,
        index: usize,
        depth: usize,
    ) -> Result<(), MaterializationFailure> {
        if index != 0 {
            self.output.push_byte(b',')?;
            if self.style.is_pretty() {
                self.layout_newline(depth.saturating_add(1))?;
            }
        }
        Ok(())
    }

    fn layout_newline(&mut self, depth: usize) -> Result<(), MaterializationFailure> {
        self.output.push_bytes(self.newline.bytes())?;
        for _ in 0..depth {
            self.output.push_bytes(b"  ")?;
        }
        Ok(())
    }
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
        output: JsonValue<'_>,
    ) -> Result<(), MaterializationFailure> {
        let expected_kind = match input.kind() {
            PortableValueKind::Null => JsonValueKind::Null,
            PortableValueKind::Boolean => JsonValueKind::Boolean,
            PortableValueKind::Integer => JsonValueKind::Integer,
            PortableValueKind::Decimal => JsonValueKind::Decimal,
            PortableValueKind::BinaryFloat64 => JsonValueKind::BinaryFloat64,
            PortableValueKind::String => JsonValueKind::String,
            PortableValueKind::Sequence => JsonValueKind::Array,
            PortableValueKind::Object | PortableValueKind::EntryMapping => JsonValueKind::Object,
            _ => return Err(MaterializationFailure::FormationFailed),
        };
        if !matches!(
            output.kind(),
            SemanticAvailability::Available(kind) if kind == expected_kind
        ) {
            return Err(MaterializationFailure::FormationFailed);
        }
        if input.kind() == PortableValueKind::BinaryFloat64
            && input.as_binary_float64()
                != match output.as_binary_float64() {
                    SemanticAvailability::Available(value) => value,
                    SemanticAvailability::Unavailable(_) => None,
                }
        {
            return Err(MaterializationFailure::FormationFailed);
        }
        self.push_origin(
            MaterializationInputLocation::Value(path.clone()),
            self.origin(
                output.node_ref(),
                output.span(),
                MaterializationRelation::Direct,
            ),
        )?;

        match input.kind() {
            PortableValueKind::Sequence => {
                let values = input
                    .as_sequence()
                    .ok_or(MaterializationFailure::FormationFailed)?;
                let SemanticAvailability::Available(Some(elements)) = output.array_elements()
                else {
                    return Err(MaterializationFailure::FormationFailed);
                };
                if values.len() != elements.len() {
                    return Err(MaterializationFailure::FormationFailed);
                }
                for (index, (value, element)) in values.iter().zip(elements).enumerate() {
                    let ordinal = u64::try_from(index)
                        .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
                    let child_path = path.child(ValuePathSegment::SequenceElement(ordinal));
                    self.collect(value, &child_path, element.value())?;
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
                let entries = input
                    .as_object()
                    .ok_or(MaterializationFailure::FormationFailed)?;
                let members = available_members(output)?;
                if entries.len() != members.len() {
                    return Err(MaterializationFailure::FormationFailed);
                }
                for (index, (entry, member)) in entries.iter().zip(members).enumerate() {
                    if !matches!(member.name(), SemanticAvailability::Available(name) if name == entry.key())
                    {
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
                            member.node_ref(),
                            member.span(),
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
                            member.key_node_ref(),
                            self.document.span(member.entity().key),
                            MaterializationRelation::Direct,
                        ),
                    )?;
                    self.collect(
                        entry.value(),
                        &path.child(ValuePathSegment::ObjectValue(entry.key().to_owned())),
                        member.value(),
                    )?;
                }
            }
            PortableValueKind::EntryMapping => {
                let entries = input
                    .as_entry_mapping()
                    .ok_or(MaterializationFailure::FormationFailed)?;
                let members = available_members(output)?;
                if entries.len() != members.len() {
                    return Err(MaterializationFailure::FormationFailed);
                }
                for (index, (entry, member)) in entries.iter().zip(members).enumerate() {
                    let ordinal = u64::try_from(index)
                        .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
                    let key = entry
                        .key()
                        .as_string()
                        .ok_or(MaterializationFailure::FormationFailed)?;
                    if !matches!(member.name(), SemanticAvailability::Available(name) if name == key)
                    {
                        return Err(MaterializationFailure::FormationFailed);
                    }
                    self.push_origin(
                        MaterializationInputLocation::Association(AssociationLocation::new(
                            path.clone(),
                            ordinal,
                            AssociationRole::EntryMappingEntry,
                        )),
                        self.origin(
                            member.node_ref(),
                            member.span(),
                            MaterializationRelation::Direct,
                        ),
                    )?;
                    self.push_origin(
                        MaterializationInputLocation::Value(
                            path.child(ValuePathSegment::EntryKey(ordinal)),
                        ),
                        self.origin(
                            member.key_node_ref(),
                            self.document.span(member.entity().key),
                            MaterializationRelation::Reencoded,
                        ),
                    )?;
                    self.collect(
                        entry.value(),
                        &path.child(ValuePathSegment::EntryValue(ordinal)),
                        member.value(),
                    )?;
                }
            }
            _ => {}
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

fn available_members(
    output: JsonValue<'_>,
) -> Result<Vec<crate::JsonObjectMember<'_>>, MaterializationFailure> {
    match output.object_members() {
        SemanticAvailability::Available(Some(members)) => Ok(members),
        _ => Err(MaterializationFailure::FormationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProjectionRequestBuilder, ProjectionResult, ProjectionTarget};
    use consema_core::{
        BigInteger, BinaryFloat64, Decimal, EntryMappingBuilder, ObjectBuilder, SequenceBuilder,
    };
    use consema_document::{MappingPolicy, MaterializationStyleId, ProfileId};

    fn request(style: &str, newline: NewlinePolicy) -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("json.strict", 1),
            MaterializationStyleId::new(style, 1),
        )
        .with_newline(newline)
    }

    fn json5_request(style: &str, newline: NewlinePolicy) -> MaterializationRequest {
        MaterializationRequest::new(
            ProfileId::new("json5.standard", 1),
            MaterializationStyleId::new(style, 1),
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
    fn compact_materialization_round_trips_exact_core_kinds() {
        let mut sequence = SequenceBuilder::new();
        sequence.push(PortableValue::null());
        sequence.push(PortableValue::decimal(Decimal::new(
            BigInteger::from(12_i64),
            BigInteger::from(-2_i64),
        )));
        let mut object = ObjectBuilder::new();
        object
            .insert("text", PortableValue::string("a\n\u{0001}"))
            .unwrap();
        object.insert("values", sequence.build()).unwrap();
        let input = object.build();
        let result = complete(materialize(
            &input,
            &request("json.canonical-compact", NewlinePolicy::None),
        ));
        assert_eq!(
            result.document.render(),
            br#"{"text":"a\n\u0001","values":[null,12e-2]}"#
        );
        let projection = result.document.project(
            &ProjectionRequestBuilder::new(ProjectionTarget::BestExactCoreV1)
                .build()
                .unwrap(),
        );
        assert!(matches!(
            projection,
            ProjectionResult::Complete(ref complete) if complete.value == input
        ));
        assert_eq!(result.fidelity, MaterializationFidelity::Exact);
        assert!(!result.provenance.entries().is_empty());
    }

    #[test]
    fn entry_mapping_keeps_duplicate_names_and_order() {
        let mut mapping = EntryMappingBuilder::new();
        mapping.push(
            PortableValue::string("x"),
            PortableValue::integer(BigInteger::from(1_i64)),
        );
        mapping.push(
            PortableValue::string("x"),
            PortableValue::integer(BigInteger::from(2_i64)),
        );
        let input = mapping.build();
        let result = complete(materialize(
            &input,
            &request("json.canonical-compact", NewlinePolicy::Lf)
                .with_mapping_policy(MappingPolicy::UniqueStringEntriesToObject),
        ));
        assert_eq!(result.document.render(), b"{\"x\":1,\"x\":2}\n");
        let projection = result.document.project(
            &ProjectionRequestBuilder::new(ProjectionTarget::ProjectAsEntryMappingV1)
                .build()
                .unwrap(),
        );
        assert!(matches!(
            projection,
            ProjectionResult::Complete(ref complete) if complete.value == input
        ));
    }

    #[test]
    fn pretty_style_and_request_failures_are_explicit() {
        let input = PortableValue::sequence(vec![PortableValue::boolean(true)]);
        let pretty = complete(materialize(
            &input,
            &request("json.canonical-pretty", NewlinePolicy::CrLf),
        ));
        assert_eq!(pretty.document.render(), b"[\r\n  true\r\n]\r\n");

        assert!(matches!(
            materialize(
                &input,
                &request("json.canonical-pretty", NewlinePolicy::None)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedNewline,
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &PortableValue::binary_float64(consema_core::BinaryFloat64::from_bits(0)),
                &request("json.canonical-compact", NewlinePolicy::None)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable {
                    kind: PortableValueKind::BinaryFloat64,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &PortableValue::string("too large"),
                &request("json.canonical-compact", NewlinePolicy::None).with_limits(
                    MaterializationLimits {
                        max_output_bytes: 3,
                        ..MaterializationLimits::default()
                    }
                )
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::ResourceLimit("output-bytes"),
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &PortableValue::boolean(true),
                &request("json.canonical-compact", NewlinePolicy::None)
                    .with_encoding(SourceEncoding::Utf16Le)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedEncoding,
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &PortableValue::boolean(true),
                &request("json.canonical-compact", NewlinePolicy::None).with_limits(
                    MaterializationLimits {
                        max_provenance_entries: 1,
                        ..MaterializationLimits::default()
                    }
                )
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::ResourceLimit("provenance-entries"),
                ..
            })
        ));
    }

    #[test]
    fn json5_materialization_is_bit_exact_and_profile_bound() {
        let input = PortableValue::sequence(vec![
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff0_0000_0000_0000)),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0xfff0_0000_0000_0000)),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x7ff8_0000_0000_0000)),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0xfff8_0000_0000_0000)),
            PortableValue::string("a\u{2028}b"),
        ]);
        let complete = complete(materialize(
            &input,
            &json5_request("json5.canonical-compact", NewlinePolicy::None),
        ));
        assert_eq!(
            complete.document.render(),
            br#"[Infinity,-Infinity,NaN,-NaN,"a\u2028b"]"#
        );
        let projection = complete.document.project(
            &ProjectionRequestBuilder::new(ProjectionTarget::Json5BestExactCoreV1)
                .build()
                .unwrap(),
        );
        assert!(matches!(
            projection,
            ProjectionResult::Complete(ref result) if result.value == input
        ));

        assert!(matches!(
            materialize(
                &PortableValue::binary_float64(BinaryFloat64::from_bits(0)),
                &json5_request("json5.canonical-compact", NewlinePolicy::None)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable {
                    kind: PortableValueKind::BinaryFloat64,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &PortableValue::null(),
                &json5_request("json.canonical-compact", NewlinePolicy::None)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedStyle,
                ..
            })
        ));
    }
}
