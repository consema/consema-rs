//! Canonical PortableValue materialization for exact Java Properties profiles.

use crate::{
    Document, DuplicatePolicy, ProjectionLimits, ProjectionRequest, ProjectionResult,
    PropertiesEncodingSelection, PropertiesParseLimits, PropertiesProfile, parse,
};
use consema_core::{
    AssociationLocation, AssociationRole, PortableValue, PortableValueKind, ValuePath,
    ValuePathSegment,
};
use consema_document::{
    CompleteMaterialization, FailedMaterializationAttempt, MaterializationFailure,
    MaterializationFidelity, MaterializationInputLocation, MaterializationLimits,
    MaterializationProvenanceEntry, MaterializationProvenanceMap, MaterializationRelation,
    MaterializationReport, MaterializationRequest, MaterializationResult, MaterializedOrigin,
    NewlinePolicy, ParseLimits, SourceEncoding, Span,
};
use encoding_rs::{
    BIG5, EUC_KR, Encoding, GBK, SHIFT_JIS, UTF_8, WINDOWS_874, WINDOWS_1250, WINDOWS_1251,
    WINDOWS_1252, WINDOWS_1253, WINDOWS_1254, WINDOWS_1255, WINDOWS_1256, WINDOWS_1257,
    WINDOWS_1258,
};

/// Materializes one flat String mapping into a new canonical Properties document.
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

fn materialize_complete(
    value: &PortableValue,
    request: &MaterializationRequest,
    analyzed: &mut Vec<ValuePath>,
) -> Result<CompleteMaterialization<Document>, MaterializationFailure> {
    let profile = requested_profile(request)?;
    validate_request(request, profile)?;
    let text_limit = text_budget(request.encoding(), request.limits().max_output_bytes)?;
    let mut writer = Writer {
        profile,
        newline: request.newline(),
        limits: request.limits(),
        input_nodes: 0,
        output: BoundedText::new(text_limit),
        analyzed,
    };
    let input_entries = writer.document(value, &ValuePath::root(), 0)?;
    let text = writer.output.finish();
    let bytes = encode_text(&text, request.encoding(), request.limits().max_output_bytes)?;
    let selection = match profile {
        PropertiesProfile::ReaderV1 => PropertiesEncodingSelection::Reader(request.encoding()),
        PropertiesProfile::Latin1V1 => PropertiesEncodingSelection::Latin1,
    };
    let document = parse(bytes, profile, selection, parse_limits(request.limits()))
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    if document.formation_status() != consema_document::FormationStatus::Complete {
        return Err(MaterializationFailure::FormationFailed);
    }
    verify_closure(value, request, &document)?;
    let provenance = build_provenance(&input_entries, &document, request.limits())?;
    Ok(CompleteMaterialization {
        document,
        fidelity: MaterializationFidelity::Exact,
        report: MaterializationReport::default(),
        provenance,
    })
}

fn requested_profile(
    request: &MaterializationRequest,
) -> Result<PropertiesProfile, MaterializationFailure> {
    match (
        request.target_profile().id(),
        request.target_profile().version(),
    ) {
        ("java-properties.reader", 1) => Ok(PropertiesProfile::ReaderV1),
        ("java-properties.latin1", 1) => Ok(PropertiesProfile::Latin1V1),
        _ => Err(MaterializationFailure::UnsupportedProfile),
    }
}

fn validate_request(
    request: &MaterializationRequest,
    profile: PropertiesProfile,
) -> Result<(), MaterializationFailure> {
    let style_matches = matches!(
        (profile, request.style().id(), request.style().version()),
        (
            PropertiesProfile::ReaderV1,
            "java-properties.reader-canonical",
            1
        ) | (
            PropertiesProfile::Latin1V1,
            "java-properties.latin1-canonical",
            1
        )
    );
    if !style_matches {
        return Err(MaterializationFailure::UnsupportedStyle);
    }
    if !matches!(request.newline(), NewlinePolicy::Lf | NewlinePolicy::CrLf) {
        return Err(MaterializationFailure::UnsupportedNewline);
    }
    let encoding_valid = match profile {
        PropertiesProfile::ReaderV1 => request.encoding() != SourceEncoding::Binary,
        PropertiesProfile::Latin1V1 => request.encoding() == SourceEncoding::Latin1,
    };
    if !encoding_valid {
        return Err(MaterializationFailure::UnsupportedEncoding);
    }
    Ok(())
}

const fn parse_limits(limits: MaterializationLimits) -> PropertiesParseLimits {
    PropertiesParseLimits {
        common: ParseLimits {
            max_source_bytes: limits.max_output_bytes,
            max_nesting_depth: limits.max_depth,
            max_token_count: limits.max_output_bytes,
            max_node_count: limits.max_output_bytes.saturating_mul(2).saturating_add(1),
            max_diagnostics: limits.max_report_entries,
        },
        max_decoded_utf8_bytes: limits.max_output_bytes.saturating_mul(3),
        max_decoded_scalars: limits.max_output_bytes.saturating_mul(2),
        max_natural_lines: limits.max_input_nodes,
        max_natural_line_bytes: limits.max_output_bytes,
        max_natural_line_scalars: limits.max_output_bytes,
        max_logical_lines: limits.max_input_nodes,
        max_logical_line_natural_lines: 1,
        max_logical_line_scalars: limits.max_output_bytes,
        max_properties: limits.max_input_nodes,
        max_comments: 0,
        max_escapes: limits.max_output_bytes,
        max_unicode_escapes: limits.max_output_bytes,
        max_java_code_units_per_string: limits.max_output_bytes,
        max_total_java_code_units: limits.max_output_bytes.saturating_mul(2),
        max_duplicate_group_members: limits.max_input_nodes,
        max_recovery_regions: limits.max_report_entries,
    }
}

#[derive(Clone, Debug)]
struct InputEntry {
    association: MaterializationInputLocation,
    key: MaterializationInputLocation,
    value: MaterializationInputLocation,
}

struct MappingItem<'a> {
    key: &'a str,
    value: &'a PortableValue,
    association: MaterializationInputLocation,
    key_location: MaterializationInputLocation,
    value_path: ValuePath,
}

struct Writer<'a> {
    profile: PropertiesProfile,
    newline: NewlinePolicy,
    limits: MaterializationLimits,
    input_nodes: usize,
    output: BoundedText,
    analyzed: &'a mut Vec<ValuePath>,
}

impl Writer<'_> {
    fn document(
        &mut self,
        value: &PortableValue,
        path: &ValuePath,
        depth: usize,
    ) -> Result<Vec<InputEntry>, MaterializationFailure> {
        let entries = self.mapping_items(value, path, depth)?;
        let mut input_entries = Vec::new();
        input_entries
            .try_reserve_exact(entries.len())
            .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
        for entry in entries {
            self.analyze(&entry.value_path, depth + 1)?;
            let Some(value) = entry.value.as_string() else {
                return Err(MaterializationFailure::Unrepresentable {
                    path: entry.value_path,
                    kind: entry.value.kind(),
                });
            };
            self.write_string(entry.key, true)?;
            self.output.push_char('=')?;
            self.write_string(value, false)?;
            self.output.push_str(match self.newline {
                NewlinePolicy::Lf => "\n",
                NewlinePolicy::CrLf => "\r\n",
                NewlinePolicy::None => unreachable!("request validation rejects no newline"),
            })?;
            input_entries.push(InputEntry {
                association: entry.association,
                key: entry.key_location,
                value: MaterializationInputLocation::Value(entry.value_path),
            });
        }
        Ok(input_entries)
    }

    fn mapping_items<'a>(
        &mut self,
        value: &'a PortableValue,
        path: &ValuePath,
        depth: usize,
    ) -> Result<Vec<MappingItem<'a>>, MaterializationFailure> {
        self.analyze(path, depth)?;
        let length = match value.kind() {
            PortableValueKind::Object => value.as_object().expect("kind agrees").len(),
            PortableValueKind::EntryMapping => value.as_entry_mapping().expect("kind agrees").len(),
            kind => {
                return Err(MaterializationFailure::Unrepresentable {
                    path: path.clone(),
                    kind,
                });
            }
        };
        if length > self.limits.max_input_nodes {
            return Err(MaterializationFailure::ResourceLimit("input-nodes"));
        }
        let mut items = Vec::new();
        items
            .try_reserve_exact(length)
            .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
        if let Some(entries) = value.as_object() {
            for (index, entry) in entries.iter().enumerate() {
                let ordinal = to_u64(index)?;
                items.push(MappingItem {
                    key: entry.key(),
                    value: entry.value(),
                    association: MaterializationInputLocation::Association(
                        AssociationLocation::new(
                            path.clone(),
                            ordinal,
                            AssociationRole::ObjectEntry,
                        ),
                    ),
                    key_location: MaterializationInputLocation::Association(
                        AssociationLocation::new(path.clone(), ordinal, AssociationRole::ObjectKey),
                    ),
                    value_path: path.child(ValuePathSegment::ObjectValue(entry.key().to_owned())),
                });
            }
        } else {
            for (index, entry) in value
                .as_entry_mapping()
                .expect("mapping kind was checked")
                .iter()
                .enumerate()
            {
                let ordinal = to_u64(index)?;
                let key_path = path.child(ValuePathSegment::EntryKey(ordinal));
                self.analyze(&key_path, depth + 1)?;
                let Some(key) = entry.key().as_string() else {
                    return Err(MaterializationFailure::Unrepresentable {
                        path: key_path,
                        kind: entry.key().kind(),
                    });
                };
                items.push(MappingItem {
                    key,
                    value: entry.value(),
                    association: MaterializationInputLocation::Association(
                        AssociationLocation::new(
                            path.clone(),
                            ordinal,
                            AssociationRole::EntryMappingEntry,
                        ),
                    ),
                    key_location: MaterializationInputLocation::Value(key_path),
                    value_path: path.child(ValuePathSegment::EntryValue(ordinal)),
                });
            }
        }
        Ok(items)
    }

    fn analyze(&mut self, path: &ValuePath, depth: usize) -> Result<(), MaterializationFailure> {
        if depth > self.limits.max_depth {
            return Err(MaterializationFailure::ResourceLimit("input-depth"));
        }
        self.input_nodes = self
            .input_nodes
            .checked_add(1)
            .ok_or(MaterializationFailure::ResourceLimit("input-nodes"))?;
        if self.input_nodes > self.limits.max_input_nodes {
            return Err(MaterializationFailure::ResourceLimit("input-nodes"));
        }
        self.analyzed
            .try_reserve(1)
            .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
        self.analyzed.push(path.clone());
        Ok(())
    }

    fn write_string(&mut self, value: &str, is_key: bool) -> Result<(), MaterializationFailure> {
        let mut leading_value_space = !is_key;
        for character in value.chars() {
            match character {
                ' ' if is_key || leading_value_space => self.output.push_str("\\ ")?,
                '\t' => self.output.push_str("\\t")?,
                '\n' => self.output.push_str("\\n")?,
                '\r' => self.output.push_str("\\r")?,
                '\u{000c}' => self.output.push_str("\\f")?,
                '\\' => self.output.push_str("\\\\")?,
                '#' | '!' | '=' | ':' => {
                    self.output.push_char('\\')?;
                    self.output.push_char(character)?;
                }
                control if control.is_control() => self.write_unicode_scalar(control)?,
                non_ascii
                    if self.profile == PropertiesProfile::Latin1V1
                        && !(0x20..=0x7E).contains(&u32::from(non_ascii)) =>
                {
                    self.write_unicode_scalar(non_ascii)?;
                }
                printable => self.output.push_char(printable)?,
            }
            if character != ' ' {
                leading_value_space = false;
            }
        }
        Ok(())
    }

    fn write_unicode_scalar(&mut self, value: char) -> Result<(), MaterializationFailure> {
        let mut units = [0_u16; 2];
        for unit in value.encode_utf16(&mut units) {
            self.output.push_str("\\u")?;
            self.output.push_hex_unit(*unit)?;
        }
        Ok(())
    }
}

fn verify_closure(
    input: &PortableValue,
    request: &MaterializationRequest,
    document: &Document,
) -> Result<(), MaterializationFailure> {
    let projection_limits = ProjectionLimits {
        max_source_associations: request.limits().max_input_nodes,
        max_value_nodes: request
            .limits()
            .max_input_nodes
            .saturating_mul(2)
            .saturating_add(1),
        max_report_entries: request.limits().max_report_entries,
        max_provenance_units: request.limits().max_provenance_entries,
    };
    let projection = if input.kind() == PortableValueKind::Object {
        document.project(
            ProjectionRequest::require_object(DuplicatePolicy::RequireUnique)
                .with_limits(projection_limits),
        )
    } else {
        document
            .project(ProjectionRequest::best_exact_entry_mapping().with_limits(projection_limits))
    };
    match projection {
        ProjectionResult::Complete(complete) if complete.value == *input => Ok(()),
        ProjectionResult::Failed(failed)
            if failed.diagnostics.first().is_some_and(|diagnostic| {
                diagnostic.code == "core.projection.resource-limit@1"
            }) =>
        {
            let limit = failed
                .diagnostics
                .first()
                .and_then(|diagnostic| diagnostic.arguments.get("limit"))
                .map(String::as_str);
            Err(MaterializationFailure::ResourceLimit(match limit {
                Some("max_source_associations" | "max_value_nodes") => "input-nodes",
                Some("max_report_entries") => "report-entries",
                Some("max_provenance_units") => "provenance-entries",
                _ => "projection",
            }))
        }
        ProjectionResult::Complete(_) | ProjectionResult::Failed(_) => {
            Err(MaterializationFailure::FormationFailed)
        }
    }
}

fn build_provenance(
    input_entries: &[InputEntry],
    document: &Document,
    limits: MaterializationLimits,
) -> Result<MaterializationProvenanceMap, MaterializationFailure> {
    if input_entries.len() != document.properties().len() {
        return Err(MaterializationFailure::FormationFailed);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(input_entries.len().saturating_mul(3).saturating_add(1))
        .map_err(|_| MaterializationFailure::ResourceLimit("provenance-entries"))?;
    let root_span = document
        .authority
        .span(0, document.source().len())
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    entries.push(provenance_entry(
        MaterializationInputLocation::Value(ValuePath::root()),
        document.node_ref(),
        vec![root_span],
        document,
    ));
    for (input, property) in input_entries.iter().zip(document.properties()) {
        entries.push(provenance_entry(
            input.association.clone(),
            property.node_ref(),
            vec![property.span()],
            document,
        ));
        entries.push(provenance_entry(
            input.key.clone(),
            property.node_ref(),
            nonempty_spans(property.key_fragments(), property.key_anchor()),
            document,
        ));
        entries.push(provenance_entry(
            input.value.clone(),
            property.node_ref(),
            nonempty_spans(property.value_fragments(), property.value_anchor()),
            document,
        ));
    }
    MaterializationProvenanceMap::new(entries, document.snapshot_identity(), limits)
}

fn nonempty_spans(fragments: &[Span], anchor: Span) -> Vec<Span> {
    if fragments.is_empty() {
        vec![anchor]
    } else {
        fragments.to_vec()
    }
}

fn provenance_entry(
    input: MaterializationInputLocation,
    node: consema_document::NodeRef,
    spans: Vec<Span>,
    document: &Document,
) -> MaterializationProvenanceEntry {
    MaterializationProvenanceEntry {
        input,
        outputs: spans
            .into_iter()
            .map(|span| MaterializedOrigin {
                snapshot: document.snapshot_identity(),
                node,
                span,
                relation: MaterializationRelation::Reencoded,
            })
            .collect(),
    }
}

struct BoundedText {
    text: String,
    max_bytes: usize,
}

impl BoundedText {
    const fn new(max_bytes: usize) -> Self {
        Self {
            text: String::new(),
            max_bytes,
        }
    }

    fn push_str(&mut self, value: &str) -> Result<(), MaterializationFailure> {
        let new_len = self
            .text
            .len()
            .checked_add(value.len())
            .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
        if new_len > self.max_bytes {
            return Err(MaterializationFailure::ResourceLimit("output-bytes"));
        }
        self.text
            .try_reserve(value.len())
            .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
        self.text.push_str(value);
        Ok(())
    }

    fn push_char(&mut self, value: char) -> Result<(), MaterializationFailure> {
        let mut encoded = [0_u8; 4];
        self.push_str(value.encode_utf8(&mut encoded))
    }

    fn push_hex_unit(&mut self, value: u16) -> Result<(), MaterializationFailure> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let digits = [
            HEX[usize::from((value >> 12) & 0xF)],
            HEX[usize::from((value >> 8) & 0xF)],
            HEX[usize::from((value >> 4) & 0xF)],
            HEX[usize::from(value & 0xF)],
        ];
        self.push_str(std::str::from_utf8(&digits).expect("ASCII hex digits"))
    }

    fn finish(self) -> String {
        self.text
    }
}

fn text_budget(
    encoding: SourceEncoding,
    max_output_bytes: usize,
) -> Result<usize, MaterializationFailure> {
    match encoding {
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be | SourceEncoding::Latin1 => {
            Ok(max_output_bytes.saturating_mul(2))
        }
        SourceEncoding::WindowsCodePage(code_page) if code_page.number() != 65001 => {
            Ok(max_output_bytes.saturating_mul(3))
        }
        SourceEncoding::Binary => Err(MaterializationFailure::UnsupportedEncoding),
        SourceEncoding::Utf8 | SourceEncoding::WindowsCodePage(_) => Ok(max_output_bytes),
    }
}

fn encode_text(
    text: &str,
    encoding: SourceEncoding,
    max_output_bytes: usize,
) -> Result<Vec<u8>, MaterializationFailure> {
    let bom_bytes = if matches!(encoding, SourceEncoding::Utf16Le | SourceEncoding::Utf16Be) {
        2
    } else {
        0
    };
    let fragment_limit = max_output_bytes
        .checked_sub(bom_bytes)
        .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
    let fragment = encode_fragment(text, encoding, fragment_limit)?;
    if bom_bytes == 0 {
        return Ok(fragment);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(fragment.len().saturating_add(2))
        .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
    output.extend(if encoding == SourceEncoding::Utf16Le {
        [0xFF, 0xFE]
    } else {
        [0xFE, 0xFF]
    });
    output.extend(fragment);
    Ok(output)
}

pub(crate) fn encode_fragment(
    text: &str,
    encoding: SourceEncoding,
    max_output_bytes: usize,
) -> Result<Vec<u8>, MaterializationFailure> {
    let mut output = match encoding {
        SourceEncoding::Utf8 => {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(text.len())
                .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
            bytes.extend_from_slice(text.as_bytes());
            bytes
        }
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => {
            let units = text.encode_utf16().count();
            let length = units
                .checked_mul(2)
                .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
            if length > max_output_bytes {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
            for unit in text.encode_utf16() {
                bytes.extend(if encoding == SourceEncoding::Utf16Le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            bytes
        }
        SourceEncoding::Latin1 => {
            let scalar_count = text.chars().count();
            if scalar_count > max_output_bytes {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(scalar_count)
                .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
            for character in text.chars() {
                let byte = u8::try_from(u32::from(character))
                    .map_err(|_| MaterializationFailure::UnsupportedEncoding)?;
                bytes.push(byte);
            }
            bytes
        }
        SourceEncoding::WindowsCodePage(code_page) => {
            let (encoded, _, had_errors) = code_page_encoding(code_page.number()).encode(text);
            if had_errors {
                return Err(MaterializationFailure::UnsupportedEncoding);
            }
            encoded.into_owned()
        }
        SourceEncoding::Binary => return Err(MaterializationFailure::UnsupportedEncoding),
    };
    if output.len() > max_output_bytes {
        output.clear();
        return Err(MaterializationFailure::ResourceLimit("output-bytes"));
    }
    Ok(output)
}

fn code_page_encoding(number: u16) -> &'static Encoding {
    match number {
        874 => WINDOWS_874,
        932 => SHIFT_JIS,
        936 => GBK,
        949 => EUC_KR,
        950 => BIG5,
        1250 => WINDOWS_1250,
        1251 => WINDOWS_1251,
        1252 => WINDOWS_1252,
        1253 => WINDOWS_1253,
        1254 => WINDOWS_1254,
        1255 => WINDOWS_1255,
        1256 => WINDOWS_1256,
        1257 => WINDOWS_1257,
        1258 => WINDOWS_1258,
        65001 => UTF_8,
        _ => unreachable!("WindowsCodePage rejects unpublished values"),
    }
}

fn to_u64(value: usize) -> Result<u64, MaterializationFailure> {
    u64::try_from(value).map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{EntryMappingBuilder, ObjectBuilder};
    use consema_document::{MaterializationStyleId, ProfileId, WindowsCodePage};

    fn request(profile: PropertiesProfile) -> MaterializationRequest {
        match profile {
            PropertiesProfile::ReaderV1 => MaterializationRequest::new(
                ProfileId::new("java-properties.reader", 1),
                MaterializationStyleId::new("java-properties.reader-canonical", 1),
            ),
            PropertiesProfile::Latin1V1 => MaterializationRequest::new(
                ProfileId::new("java-properties.latin1", 1),
                MaterializationStyleId::new("java-properties.latin1-canonical", 1),
            )
            .with_encoding(SourceEncoding::Latin1),
        }
    }

    fn mapping(entries: &[(&str, &str)]) -> PortableValue {
        let mut mapping = EntryMappingBuilder::new();
        for (key, value) in entries {
            mapping.push(PortableValue::string(*key), PortableValue::string(*value));
        }
        mapping.build()
    }

    #[test]
    fn reader_canonical_escapes_structure_and_controls() {
        let value = mapping(&[(" a#", "  v:=!\\\t\u{0008}值")]);
        let MaterializationResult::Complete(result) =
            materialize(&value, &request(PropertiesProfile::ReaderV1))
        else {
            panic!("Reader materialization");
        };
        assert_eq!(
            result.document.render(),
            "\\ a\\#=\\ \\ v\\:\\=\\!\\\\\\t\\u0008值\n".as_bytes()
        );
        assert_eq!(result.fidelity, MaterializationFidelity::Exact);
        assert!(result.report.events().is_empty());
        let ProjectionResult::Complete(projected) = result
            .document
            .project(ProjectionRequest::best_exact_entry_mapping())
        else {
            panic!("closure projection");
        };
        assert_eq!(projected.value, value);
        assert_eq!(result.provenance.entries().len(), 4);
    }

    #[test]
    fn latin1_canonical_uses_uppercase_utf16_escapes_without_bom() {
        let value = mapping(&[("emoji😀", "café\u{007f}")]);
        let request = request(PropertiesProfile::Latin1V1).with_newline(NewlinePolicy::CrLf);
        let MaterializationResult::Complete(result) = materialize(&value, &request) else {
            panic!("Latin-1 materialization");
        };
        assert_eq!(
            result.document.render(),
            b"emoji\\uD83D\\uDE00=caf\\u00E9\\u007F\r\n"
        );
        assert_eq!(
            result.document.source().encoding_facts().selected(),
            SourceEncoding::Latin1
        );
        assert_eq!(result.document.source().encoding_facts().bom(), None);
    }

    #[test]
    fn reader_utf16_and_strict_code_pages_are_explicit() {
        let unicode = mapping(&[("名", "值")]);
        let utf16 = request(PropertiesProfile::ReaderV1)
            .with_encoding(SourceEncoding::Utf16Be)
            .with_newline(NewlinePolicy::CrLf);
        let MaterializationResult::Complete(result) = materialize(&unicode, &utf16) else {
            panic!("UTF-16 Reader materialization");
        };
        assert_eq!(&result.document.render()[..2], &[0xFE, 0xFF]);
        assert_eq!(
            result.document.source().encoding_facts().selected(),
            SourceEncoding::Utf16Be
        );

        let cp1252 = WindowsCodePage::from_number(1252).unwrap();
        let cp_request = request(PropertiesProfile::ReaderV1)
            .with_encoding(SourceEncoding::WindowsCodePage(cp1252));
        let latin = mapping(&[("name", "café")]);
        let MaterializationResult::Complete(result) = materialize(&latin, &cp_request) else {
            panic!("code-page Reader materialization");
        };
        assert!(result.document.render().contains(&0xE9));
        assert!(matches!(
            materialize(&unicode, &cp_request),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedEncoding,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_entry_mapping_and_unique_object_close_exactly() {
        let duplicate = mapping(&[("a", "first"), ("a", "last")]);
        let MaterializationResult::Complete(result) =
            materialize(&duplicate, &request(PropertiesProfile::ReaderV1))
        else {
            panic!("duplicate mapping");
        };
        assert_eq!(result.document.properties().len(), 2);

        let mut object = ObjectBuilder::new();
        object.insert("a", PortableValue::string("one")).unwrap();
        object.insert("b", PortableValue::string("two")).unwrap();
        let object = object.build();
        let MaterializationResult::Complete(result) =
            materialize(&object, &request(PropertiesProfile::ReaderV1))
        else {
            panic!("object materialization");
        };
        let ProjectionResult::Complete(projected) = result.document.project(
            ProjectionRequest::require_object(DuplicatePolicy::RequireUnique),
        ) else {
            panic!("object closure");
        };
        assert_eq!(projected.value, object);

        let empty = mapping(&[("", "")]);
        let tight = request(PropertiesProfile::ReaderV1).with_limits(MaterializationLimits {
            max_input_nodes: 3,
            max_output_bytes: 2,
            ..MaterializationLimits::default()
        });
        let MaterializationResult::Complete(result) = materialize(&empty, &tight) else {
            panic!("dense empty property");
        };
        assert_eq!(result.document.render(), b"=\n");
    }

    #[test]
    fn invalid_requests_shapes_and_limits_fail_atomically() {
        let value = mapping(&[("key", "value")]);
        assert!(matches!(
            materialize(
                &value,
                &request(PropertiesProfile::Latin1V1).with_encoding(SourceEncoding::Utf8)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedEncoding,
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &value,
                &request(PropertiesProfile::ReaderV1).with_newline(NewlinePolicy::None)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedNewline,
                ..
            })
        ));
        assert!(matches!(
            materialize(
                &PortableValue::string("scalar"),
                &request(PropertiesProfile::ReaderV1)
            ),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::Unrepresentable { .. },
                ..
            })
        ));
        for limits in [
            MaterializationLimits {
                max_input_nodes: 1,
                ..MaterializationLimits::default()
            },
            MaterializationLimits {
                max_output_bytes: 2,
                ..MaterializationLimits::default()
            },
            MaterializationLimits {
                max_provenance_entries: 1,
                ..MaterializationLimits::default()
            },
        ] {
            assert!(matches!(
                materialize(
                    &value,
                    &request(PropertiesProfile::ReaderV1).with_limits(limits)
                ),
                MaterializationResult::Failed(FailedMaterializationAttempt {
                    failure: MaterializationFailure::ResourceLimit(_),
                    ..
                })
            ));
        }
    }
}
