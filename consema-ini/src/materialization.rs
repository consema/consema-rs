//! Canonical PortableValue materialization for explicit INI profiles.

use crate::{
    CollisionPolicy, Document, IniEncodingSelection, IniParseLimits, IniProfile, NameComparison,
    ProjectionLimits, ProjectionRequest, ProjectionResult, parse,
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
    NewlinePolicy, ParseLimits, SourceEncoding,
};
use encoding_rs::{
    BIG5, EUC_KR, Encoding, GBK, SHIFT_JIS, UTF_8, WINDOWS_874, WINDOWS_1250, WINDOWS_1251,
    WINDOWS_1252, WINDOWS_1253, WINDOWS_1254, WINDOWS_1255, WINDOWS_1256, WINDOWS_1257,
    WINDOWS_1258,
};
use std::collections::HashSet;
use std::fmt;

/// Materializes one nested String mapping into a new canonical INI document.
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
    let utf8_budget = text_budget(request.encoding(), request.limits().max_output_bytes)?;
    let mut writer = Writer {
        profile,
        limits: request.limits(),
        input_nodes: 0,
        output: BoundedText::new(utf8_budget),
        analyzed,
    };
    let sections = writer.document(value, &ValuePath::root(), 0)?;
    let text = writer.output.finish();
    let bytes = encode_text(&text, request.encoding(), request.limits().max_output_bytes)?;
    let selection = parse_encoding_selection(profile, request.encoding());
    let document = parse(bytes, profile, selection, parse_limits(request.limits()))
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    if document.formation_status() != consema_document::FormationStatus::Complete {
        return Err(MaterializationFailure::FormationFailed);
    }
    verify_closure(value, request, &document)?;
    let provenance = build_provenance(value, &sections, &document, request.limits())?;
    Ok(CompleteMaterialization {
        document,
        fidelity: MaterializationFidelity::Exact,
        report: MaterializationReport::default(),
        provenance,
    })
}

fn requested_profile(
    request: &MaterializationRequest,
) -> Result<IniProfile, MaterializationFailure> {
    match (
        request.target_profile().id(),
        request.target_profile().version(),
    ) {
        ("ini.portable", 1) => Ok(IniProfile::PortableV1),
        ("ini.windows", 1) => Ok(IniProfile::WindowsV1),
        ("ini.python-configparser", 1) => Ok(IniProfile::PythonConfigParserV1),
        _ => Err(MaterializationFailure::UnsupportedProfile),
    }
}

fn validate_request(
    request: &MaterializationRequest,
    profile: IniProfile,
) -> Result<(), MaterializationFailure> {
    let style_matches = matches!(
        (profile, request.style().id(), request.style().version()),
        (IniProfile::PortableV1, "ini.portable-canonical", 1)
            | (IniProfile::WindowsV1, "ini.windows-canonical", 1)
            | (
                IniProfile::PythonConfigParserV1,
                "ini.python-configparser-canonical",
                1
            )
    );
    if !style_matches {
        return Err(MaterializationFailure::UnsupportedStyle);
    }
    let expected_newline = match profile {
        IniProfile::WindowsV1 => NewlinePolicy::CrLf,
        IniProfile::PortableV1 | IniProfile::PythonConfigParserV1 => NewlinePolicy::Lf,
    };
    if request.newline() != expected_newline {
        return Err(MaterializationFailure::UnsupportedNewline);
    }
    let encoding_valid = match profile {
        IniProfile::PortableV1 => request.encoding() == SourceEncoding::Utf8,
        IniProfile::WindowsV1 => matches!(
            request.encoding(),
            SourceEncoding::Utf16Le | SourceEncoding::WindowsCodePage(_)
        ),
        IniProfile::PythonConfigParserV1 => request.encoding() != SourceEncoding::Binary,
    };
    if !encoding_valid {
        return Err(MaterializationFailure::UnsupportedEncoding);
    }
    Ok(())
}

fn parse_encoding_selection(profile: IniProfile, encoding: SourceEncoding) -> IniEncodingSelection {
    match (profile, encoding) {
        (IniProfile::PortableV1 | IniProfile::PythonConfigParserV1, SourceEncoding::Utf8)
        | (IniProfile::WindowsV1, SourceEncoding::Utf16Le) => IniEncodingSelection::ProfileDefault,
        _ => IniEncodingSelection::Explicit(encoding),
    }
}

const fn parse_limits(limits: MaterializationLimits) -> IniParseLimits {
    IniParseLimits {
        common: ParseLimits {
            max_source_bytes: limits.max_output_bytes,
            max_nesting_depth: limits.max_depth,
            max_token_count: limits.max_output_bytes,
            max_node_count: limits.max_output_bytes,
            max_diagnostics: limits.max_report_entries,
        },
        max_decoded_utf8_bytes: limits.max_output_bytes.saturating_mul(3),
        max_decoded_scalars: limits.max_output_bytes,
        max_physical_lines: limits.max_output_bytes,
        max_physical_line_bytes: limits.max_output_bytes,
        max_physical_line_scalars: limits.max_output_bytes,
        max_logical_lines: limits.max_input_nodes,
        max_logical_line_bytes: limits.max_output_bytes,
        max_logical_line_scalars: limits.max_output_bytes,
        max_continuation_lines: limits.max_output_bytes,
        max_sections: limits.max_input_nodes,
        max_entries: limits.max_input_nodes,
        max_duplicate_group_members: limits.max_input_nodes,
        max_recovery_regions: limits.max_report_entries,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MappingShape {
    Object,
    EntryMapping,
}

#[derive(Clone, Debug)]
struct InputEntry {
    association: MaterializationInputLocation,
    key: MaterializationInputLocation,
    value: MaterializationInputLocation,
}

#[derive(Clone, Debug)]
struct InputSection {
    association: MaterializationInputLocation,
    key: MaterializationInputLocation,
    value: MaterializationInputLocation,
    entries: Vec<InputEntry>,
}

struct MappingItem<'a> {
    key: &'a str,
    value: &'a PortableValue,
    association: MaterializationInputLocation,
    key_location: MaterializationInputLocation,
    value_path: ValuePath,
}

struct Writer<'a> {
    profile: IniProfile,
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
    ) -> Result<Vec<InputSection>, MaterializationFailure> {
        let (shape, outer) = self.mapping_items(value, path, depth)?;
        if shape == MappingShape::Object && self.profile == IniProfile::WindowsV1 {
            reject_case_equivalent_object_names(&outer)?;
        }
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(outer.len())
            .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
        for section in outer {
            self.validate_section_name(section.key)?;
            self.output.push_char('[')?;
            self.output.push_str(section.key)?;
            self.output.push_char(']')?;
            self.newline()?;
            let (entry_shape, entries) =
                self.mapping_items(section.value, &section.value_path, depth + 1)?;
            if entry_shape == MappingShape::Object && self.profile == IniProfile::WindowsV1 {
                reject_case_equivalent_object_names(&entries)?;
            }
            let mut input_entries = Vec::new();
            input_entries
                .try_reserve_exact(entries.len())
                .map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))?;
            for entry in entries {
                self.validate_key(entry.key)?;
                self.analyze(&entry.value_path, depth + 2)?;
                let Some(value) = entry.value.as_string() else {
                    return Err(MaterializationFailure::Unrepresentable {
                        path: entry.value_path,
                        kind: entry.value.kind(),
                    });
                };
                self.write_entry(entry.key, value)?;
                input_entries.push(InputEntry {
                    association: entry.association,
                    key: entry.key_location,
                    value: MaterializationInputLocation::Value(entry.value_path),
                });
            }
            sections.push(InputSection {
                association: section.association,
                key: section.key_location,
                value: MaterializationInputLocation::Value(section.value_path),
                entries: input_entries,
            });
        }
        Ok(sections)
    }

    fn mapping_items<'a>(
        &mut self,
        value: &'a PortableValue,
        path: &ValuePath,
        depth: usize,
    ) -> Result<(MappingShape, Vec<MappingItem<'a>>), MaterializationFailure> {
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
            Ok((MappingShape::Object, items))
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
            Ok((MappingShape::EntryMapping, items))
        }
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
        self.analyzed.push(path.clone());
        Ok(())
    }

    fn validate_section_name(&self, value: &str) -> Result<(), MaterializationFailure> {
        let valid = match self.profile {
            IniProfile::PortableV1 => !value.is_empty() && value.bytes().all(is_portable_name),
            IniProfile::WindowsV1 => !value.is_empty() && value.bytes().all(is_windows_name),
            IniProfile::PythonConfigParserV1 => {
                !value.is_empty() && !value.contains(['\0', '\r', '\n'])
            }
        };
        if valid {
            Ok(())
        } else {
            Err(MaterializationFailure::InvalidRequest(
                "section name is not representable",
            ))
        }
    }

    fn validate_key(&self, value: &str) -> Result<(), MaterializationFailure> {
        let valid = match self.profile {
            IniProfile::PortableV1 => !value.is_empty() && value.bytes().all(is_portable_name),
            IniProfile::WindowsV1 => !value.is_empty() && value.bytes().all(is_windows_name),
            IniProfile::PythonConfigParserV1 => {
                !value.is_empty()
                    && !value.contains(['\0', '\r', '\n', '=', ':'])
                    && trim_horizontal(value) == value
            }
        };
        if valid {
            Ok(())
        } else {
            Err(MaterializationFailure::InvalidRequest(
                "entry key is not representable",
            ))
        }
    }

    fn write_entry(&mut self, key: &str, value: &str) -> Result<(), MaterializationFailure> {
        match self.profile {
            IniProfile::PortableV1 => {
                if !value.bytes().all(is_portable_value) {
                    return Err(MaterializationFailure::InvalidRequest(
                        "portable value is not representable",
                    ));
                }
                self.output.push_str(key)?;
                self.output.push_char('=')?;
                self.output.push_str(value)?;
                self.newline()
            }
            IniProfile::WindowsV1 => {
                if value.contains(['\0', '\r', '\n']) {
                    return Err(MaterializationFailure::InvalidRequest(
                        "Windows value is not representable",
                    ));
                }
                self.output.push_str(key)?;
                self.output.push_char('=')?;
                if windows_value_needs_quotes(value) {
                    let quote = if value.starts_with('"') && value.ends_with('"') {
                        '\''
                    } else {
                        '"'
                    };
                    self.output.push_char(quote)?;
                    self.output.push_str(value)?;
                    self.output.push_char(quote)?;
                } else {
                    self.output.push_str(value)?;
                }
                self.newline()
            }
            IniProfile::PythonConfigParserV1 => self.write_python_entry(key, value),
        }
    }

    fn write_python_entry(&mut self, key: &str, value: &str) -> Result<(), MaterializationFailure> {
        if value.contains(['\0', '\r']) {
            return Err(MaterializationFailure::InvalidRequest(
                "Python value is not representable",
            ));
        }
        if value.ends_with('\n') {
            return Err(MaterializationFailure::InvalidRequest(
                "trailing empty Python value line is not representable",
            ));
        }
        let mut lines = value.split('\n');
        let first = lines.next().expect("split always yields one item");
        validate_python_value_line(first)?;
        self.output.push_str(key)?;
        self.output.push_str(" =")?;
        if !first.is_empty() {
            self.output.push_char(' ')?;
            self.output.push_str(first)?;
        }
        self.newline()?;
        for line in lines {
            validate_python_value_line(line)?;
            if !line.is_empty() {
                self.output.push_str("    ")?;
                self.output.push_str(line)?;
            }
            self.newline()?;
        }
        Ok(())
    }

    fn newline(&mut self) -> Result<(), MaterializationFailure> {
        self.output.push_str(match self.profile {
            IniProfile::WindowsV1 => "\r\n",
            IniProfile::PortableV1 | IniProfile::PythonConfigParserV1 => "\n",
        })
    }
}

fn validate_python_value_line(line: &str) -> Result<(), MaterializationFailure> {
    if trim_horizontal(line) == line {
        Ok(())
    } else {
        Err(MaterializationFailure::InvalidRequest(
            "Python value line edge whitespace is not representable",
        ))
    }
}

fn reject_case_equivalent_object_names(
    entries: &[MappingItem<'_>],
) -> Result<(), MaterializationFailure> {
    let mut seen = HashSet::new();
    if entries
        .iter()
        .any(|entry| !seen.insert(entry.key.to_ascii_lowercase()))
    {
        Err(MaterializationFailure::InvalidRequest(
            "Object cannot fabricate Windows case-equivalent collisions",
        ))
    } else {
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
        max_value_nodes: request.limits().max_input_nodes,
        max_report_entries: request.limits().max_report_entries,
        max_provenance_units: request.limits().max_provenance_entries,
    };
    let projection = if input.kind() == PortableValueKind::Object {
        document.project(
            ProjectionRequest::require_object(
                NameComparison::OriginalExact,
                CollisionPolicy::Reject,
            )
            .with_limits(projection_limits),
        )
    } else {
        document
            .project(ProjectionRequest::best_exact_entry_mapping().with_limits(projection_limits))
    };
    match projection {
        ProjectionResult::Complete(complete) if complete.value == *input => Ok(()),
        ProjectionResult::Complete(_) | ProjectionResult::Failed(_) => {
            Err(MaterializationFailure::FormationFailed)
        }
    }
}

fn build_provenance(
    input: &PortableValue,
    sections: &[InputSection],
    document: &Document,
    limits: MaterializationLimits,
) -> Result<MaterializationProvenanceMap, MaterializationFailure> {
    let mut entries = Vec::new();
    let root_span = document
        .authority
        .span(0, document.source().len())
        .map_err(|_| MaterializationFailure::FormationFailed)?;
    entries.push(provenance_entry(
        MaterializationInputLocation::Value(ValuePath::root()),
        document.node_ref(),
        root_span,
        document,
        MaterializationRelation::Reencoded,
    ));
    let mut entry_offset = 0usize;
    for (section_index, input_section) in sections.iter().enumerate() {
        let section = document
            .sections()
            .get(section_index)
            .ok_or(MaterializationFailure::FormationFailed)?;
        entries.push(provenance_entry(
            input_section.association.clone(),
            section.node_ref(),
            section.span(),
            document,
            MaterializationRelation::Reencoded,
        ));
        entries.push(provenance_entry(
            input_section.key.clone(),
            section.node_ref(),
            section.name_span(),
            document,
            MaterializationRelation::Reencoded,
        ));
        entries.push(provenance_entry(
            input_section.value.clone(),
            section.node_ref(),
            section.span(),
            document,
            MaterializationRelation::Generated,
        ));
        for input_entry in &input_section.entries {
            let entry = document
                .entries()
                .get(entry_offset)
                .ok_or(MaterializationFailure::FormationFailed)?;
            if entry.section() != section.node_ref() {
                return Err(MaterializationFailure::FormationFailed);
            }
            entries.push(provenance_entry(
                input_entry.association.clone(),
                entry.node_ref(),
                entry.span(),
                document,
                MaterializationRelation::Reencoded,
            ));
            entries.push(provenance_entry(
                input_entry.key.clone(),
                entry.node_ref(),
                entry.key_span(),
                document,
                MaterializationRelation::Reencoded,
            ));
            let mut value_outputs = vec![MaterializedOrigin {
                snapshot: document.snapshot_identity(),
                node: entry.node_ref(),
                span: entry.value_span(),
                relation: MaterializationRelation::Reencoded,
            }];
            append_continuation_outputs(document, entry, &mut value_outputs);
            entries.push(MaterializationProvenanceEntry {
                input: input_entry.value.clone(),
                outputs: value_outputs,
            });
            entry_offset += 1;
        }
    }
    if entry_offset != document.entries().len()
        || !matches!(
            input.kind(),
            PortableValueKind::Object | PortableValueKind::EntryMapping
        )
    {
        return Err(MaterializationFailure::FormationFailed);
    }
    MaterializationProvenanceMap::new(entries, document.snapshot_identity(), limits)
}

fn append_continuation_outputs(
    document: &Document,
    entry: &crate::IniEntry,
    output: &mut Vec<MaterializedOrigin>,
) {
    let logical = document
        .logical_line(entry.logical_line())
        .expect("materialized entry logical line exists");
    let pieces = document.lossless_structural_index().pieces();
    for physical_node in logical.physical_lines().iter().skip(1) {
        let physical = document
            .physical_line(*physical_node)
            .expect("materialized continuation line exists");
        let start = pieces.partition_point(|piece| {
            piece.span().end_byte() <= physical.content_span().start_byte()
        });
        for (ordinal, piece) in pieces.iter().enumerate().skip(start) {
            if piece.span().start_byte() >= physical.content_span().end_byte() {
                break;
            }
            if document.lossless_syntax_kinds()[ordinal] == crate::IniSyntaxKind::EntryValue {
                output.push(MaterializedOrigin {
                    snapshot: document.snapshot_identity(),
                    node: entry.node_ref(),
                    span: piece.span(),
                    relation: MaterializationRelation::Reencoded,
                });
            }
        }
    }
}

fn provenance_entry(
    input: MaterializationInputLocation,
    node: consema_document::NodeRef,
    span: consema_document::Span,
    document: &Document,
    relation: MaterializationRelation,
) -> MaterializationProvenanceEntry {
    MaterializationProvenanceEntry {
        input,
        outputs: vec![MaterializedOrigin {
            snapshot: document.snapshot_identity(),
            node,
            span,
            relation,
        }],
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
        let mut encoded = [0u8; 4];
        self.push_str(value.encode_utf8(&mut encoded))
    }

    fn finish(self) -> String {
        self.text
    }
}

impl fmt::Write for BoundedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_str(value).map_err(|_| fmt::Error)
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
    let mut output = match encoding {
        SourceEncoding::Utf8 => text.as_bytes().to_vec(),
        SourceEncoding::Utf16Le | SourceEncoding::Utf16Be => {
            let units = text.encode_utf16().count();
            let length = units
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2))
                .ok_or(MaterializationFailure::ResourceLimit("output-bytes"))?;
            if length > max_output_bytes {
                return Err(MaterializationFailure::ResourceLimit("output-bytes"));
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| MaterializationFailure::ResourceLimit("output-bytes"))?;
            bytes.extend(if encoding == SourceEncoding::Utf16Le {
                [0xff, 0xfe]
            } else {
                [0xfe, 0xff]
            });
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
                let code = u32::from(character);
                let byte =
                    u8::try_from(code).map_err(|_| MaterializationFailure::UnsupportedEncoding)?;
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
        _ => unreachable!("WindowsCodePage constructor rejects unpublished values"),
    }
}

fn to_u64(value: usize) -> Result<u64, MaterializationFailure> {
    u64::try_from(value).map_err(|_| MaterializationFailure::ResourceLimit("input-nodes"))
}

fn trim_horizontal(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

const fn is_portable_name(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

const fn is_portable_value(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'\'' | b'"' | b'\\' | b':' | b'#' | b';')
        || byte == b' '
}

const fn is_windows_name(byte: u8) -> bool {
    (byte.is_ascii_graphic() || byte == b' ')
        && !matches!(byte, b'[' | b']' | b'=' | b'\0' | b'\r' | b'\n')
}

fn windows_value_needs_quotes(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        || value
            .as_bytes()
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        || (value.len() >= 2
            && matches!(
                (value.as_bytes()[0], value.as_bytes()[value.len() - 1]),
                (b'\'', b'\'') | (b'"', b'"')
            ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{EntryMappingBuilder, ObjectBuilder};
    use consema_document::{MaterializationStyleId, ProfileId, WindowsCodePage};

    fn request(profile: IniProfile) -> MaterializationRequest {
        match profile {
            IniProfile::PortableV1 => MaterializationRequest::new(
                ProfileId::new("ini.portable", 1),
                MaterializationStyleId::new("ini.portable-canonical", 1),
            ),
            IniProfile::WindowsV1 => MaterializationRequest::new(
                ProfileId::new("ini.windows", 1),
                MaterializationStyleId::new("ini.windows-canonical", 1),
            )
            .with_encoding(SourceEncoding::Utf16Le)
            .with_newline(NewlinePolicy::CrLf),
            IniProfile::PythonConfigParserV1 => MaterializationRequest::new(
                ProfileId::new("ini.python-configparser", 1),
                MaterializationStyleId::new("ini.python-configparser-canonical", 1),
            ),
        }
    }

    fn nested_entry_mapping(sections: &[(&str, &[(&str, &str)])]) -> PortableValue {
        let mut outer = EntryMappingBuilder::new();
        for (section, entries) in sections {
            let mut inner = EntryMappingBuilder::new();
            for (key, value) in *entries {
                inner.push(PortableValue::string(*key), PortableValue::string(*value));
            }
            outer.push(PortableValue::string(*section), inner.build());
        }
        outer.build()
    }

    #[test]
    fn all_canonical_profiles_close_exactly() {
        let portable = nested_entry_mapping(&[("main", &[("key", "value"), ("empty", "")])]);
        let MaterializationResult::Complete(result) =
            materialize(&portable, &request(IniProfile::PortableV1))
        else {
            panic!("portable materialization");
        };
        assert_eq!(result.document.render(), b"[main]\nkey=value\nempty=\n");

        let windows =
            nested_entry_mapping(&[("Main", &[("quoted", " value "), ("literal", "\"both\"")])]);
        let MaterializationResult::Complete(result) =
            materialize(&windows, &request(IniProfile::WindowsV1))
        else {
            panic!("Windows materialization");
        };
        assert_eq!(result.document.entries()[0].value(), " value ");
        assert_eq!(result.document.entries()[1].value(), "\"both\"");
        assert_eq!(
            result.document.source().encoding_facts().selected(),
            SourceEncoding::Utf16Le
        );

        let python = nested_entry_mapping(&[(
            "DEFAULT",
            &[("raw", "%(name)s"), ("multi", "first\n\nthird")],
        )]);
        let MaterializationResult::Complete(result) =
            materialize(&python, &request(IniProfile::PythonConfigParserV1))
        else {
            panic!("Python materialization");
        };
        assert_eq!(result.document.entries()[1].value(), "first\n\nthird");
        assert!(
            result
                .provenance
                .entries()
                .iter()
                .any(|entry| entry.outputs.len() > 1)
        );
    }

    #[test]
    fn windows_code_page_is_strict_and_duplicate_entry_mapping_survives() {
        let value = nested_entry_mapping(&[("s", &[("name", "café"), ("name", "two")])]);
        let cp1252 = WindowsCodePage::from_number(1252).unwrap();
        let request =
            request(IniProfile::WindowsV1).with_encoding(SourceEncoding::WindowsCodePage(cp1252));
        let MaterializationResult::Complete(result) = materialize(&value, &request) else {
            panic!("code-page materialization");
        };
        assert_eq!(result.document.render().last(), Some(&0x0a));
        assert!(result.document.render().contains(&0xe9));
        assert_eq!(result.document.entries().len(), 2);

        let unrepresentable = nested_entry_mapping(&[("s", &[("name", "漢")])]);
        assert!(matches!(
            materialize(&unrepresentable, &request),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedEncoding,
                ..
            })
        ));
    }

    #[test]
    fn python_explicit_text_encodings_are_representability_checked() {
        let latin = nested_entry_mapping(&[("s", &[("name", "café")])]);
        let latin_request =
            request(IniProfile::PythonConfigParserV1).with_encoding(SourceEncoding::Latin1);
        let MaterializationResult::Complete(result) = materialize(&latin, &latin_request) else {
            panic!("Latin-1 Python materialization");
        };
        assert_eq!(
            result.document.source().encoding_facts().selected(),
            SourceEncoding::Latin1
        );
        assert!(result.document.render().contains(&0xe9));

        let unicode = nested_entry_mapping(&[("節", &[("鍵", "値")])]);
        let utf16_request =
            request(IniProfile::PythonConfigParserV1).with_encoding(SourceEncoding::Utf16Be);
        let MaterializationResult::Complete(result) = materialize(&unicode, &utf16_request) else {
            panic!("UTF-16BE Python materialization");
        };
        assert_eq!(&result.document.render()[..2], &[0xfe, 0xff]);
        assert_eq!(
            result.document.source().encoding_facts().selected(),
            SourceEncoding::Utf16Be
        );

        assert!(matches!(
            materialize(&unicode, &latin_request),
            MaterializationResult::Failed(FailedMaterializationAttempt {
                failure: MaterializationFailure::UnsupportedEncoding,
                ..
            })
        ));
    }

    #[test]
    fn object_input_is_unique_and_cannot_fabricate_windows_case_collisions() {
        let mut inner = ObjectBuilder::new();
        inner.insert("Name", PortableValue::string("one")).unwrap();
        inner.insert("name", PortableValue::string("two")).unwrap();
        let mut outer = ObjectBuilder::new();
        outer.insert("s", inner.build()).unwrap();
        assert!(matches!(
            materialize(&outer.build(), &request(IniProfile::WindowsV1)),
            MaterializationResult::Failed(_)
        ));

        let mut inner = ObjectBuilder::new();
        inner.insert("Name", PortableValue::string("one")).unwrap();
        let mut outer = ObjectBuilder::new();
        outer.insert("s", inner.build()).unwrap();
        assert!(matches!(
            materialize(&outer.build(), &request(IniProfile::WindowsV1)),
            MaterializationResult::Complete(_)
        ));
    }

    #[test]
    fn malformed_shapes_unrepresentable_values_and_limits_fail_atomically() {
        let scalar = PortableValue::string("x");
        assert!(matches!(
            materialize(&scalar, &request(IniProfile::PortableV1)),
            MaterializationResult::Failed(_)
        ));

        let trailing = nested_entry_mapping(&[("s", &[("value", "line\n")])]);
        assert!(matches!(
            materialize(&trailing, &request(IniProfile::PythonConfigParserV1)),
            MaterializationResult::Failed(_)
        ));

        let value = nested_entry_mapping(&[("s", &[("key", "value")])]);
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
                materialize(&value, &request(IniProfile::PortableV1).with_limits(limits)),
                MaterializationResult::Failed(_)
            ));
        }
    }
}
