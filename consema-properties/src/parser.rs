use crate::{
    Document, JavaString, PropertiesComment, PropertiesEncodingSelection, PropertiesErrorLine,
    PropertiesEscape, PropertiesEscapeKind, PropertiesLogicalLine, PropertiesLogicalLineKind,
    PropertiesNaturalLine, PropertiesParseLimits, PropertiesProfile, PropertiesSyntaxKind,
    PropertiesValueState, Property,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    BomPolicy, DecodedOffset, DocumentAuthority, EncodingRequest, FatalFormationFailure,
    FormationStatus, LosslessStructuralIndex, NodeRef, NodeRole, SourceEncoding, SourceLimits,
    SourceSnapshot, Span, StructuralPiece, StructuralPieceKind,
};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

pub(crate) fn parse(
    bytes: Arc<[u8]>,
    profile: PropertiesProfile,
    selection: PropertiesEncodingSelection,
    limits: PropertiesParseLimits,
) -> Result<Document, FatalFormationFailure> {
    let request = encoding_request(profile, selection)?;
    let source = SourceSnapshot::from_raw(
        bytes,
        request,
        SourceLimits {
            max_raw_bytes: limits.common.max_source_bytes,
            max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
            max_decoded_scalars: limits.max_decoded_scalars,
        },
    )
    .map_err(FatalFormationFailure::source_error)?;
    validate_profile_encoding(&source, profile, selection)?;
    Parser::new(source, profile, limits)?.parse()
}

fn encoding_request(
    profile: PropertiesProfile,
    selection: PropertiesEncodingSelection,
) -> Result<EncodingRequest, FatalFormationFailure> {
    match (profile, selection) {
        (PropertiesProfile::ReaderV1, PropertiesEncodingSelection::Reader(encoding))
            if encoding != SourceEncoding::Binary =>
        {
            Ok(EncodingRequest::new(encoding).with_caller_override(encoding))
        }
        (PropertiesProfile::Latin1V1, PropertiesEncodingSelection::Latin1) => {
            Ok(EncodingRequest::new(SourceEncoding::Latin1)
                .with_caller_override(SourceEncoding::Latin1)
                .with_bom_policy(BomPolicy::TreatAsContent))
        }
        _ => Err(profile_failure()),
    }
}

fn validate_profile_encoding(
    source: &SourceSnapshot,
    profile: PropertiesProfile,
    selection: PropertiesEncodingSelection,
) -> Result<(), FatalFormationFailure> {
    let facts = source.encoding_facts();
    let valid = match (profile, selection) {
        (PropertiesProfile::ReaderV1, PropertiesEncodingSelection::Reader(encoding)) => {
            encoding != SourceEncoding::Binary
                && facts.selected() == encoding
                && facts.bom_policy() == BomPolicy::DetectUnicode
        }
        (PropertiesProfile::Latin1V1, PropertiesEncodingSelection::Latin1) => {
            facts.selected() == SourceEncoding::Latin1
                && facts.bom_policy() == BomPolicy::TreatAsContent
                && facts.bom().is_none()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(profile_failure())
    }
}

fn profile_failure() -> FatalFormationFailure {
    FatalFormationFailure::from_diagnostic(Diagnostic::new(
        "java-properties.source.profile-encoding@1",
        DiagnosticCategory::Encoding,
        DiagnosticSeverity::Error,
        None,
        0,
    ))
}

#[derive(Clone, Debug)]
struct Atom {
    ch: char,
    raw_start: usize,
    raw_end: usize,
    syntax: Option<PropertiesSyntaxKind>,
}

#[derive(Clone, Debug)]
struct ScannedLine {
    atom_start: usize,
    atom_content_end: usize,
    atom_end: usize,
    natural_index: usize,
}

#[derive(Clone, Debug)]
struct EscapeSpec {
    atom_indices: Vec<usize>,
    kind: PropertiesEscapeKind,
    output_start: usize,
    output_end: usize,
}

#[derive(Clone, Debug)]
struct DecodedJavaString {
    units: Vec<u16>,
    escapes: Vec<EscapeSpec>,
    unicode_escapes: usize,
}

#[derive(Clone, Debug)]
struct DecodeError {
    atom_start: usize,
    atom_end: usize,
}

struct Parser {
    source: SourceSnapshot,
    profile: PropertiesProfile,
    limits: PropertiesParseLimits,
    authority: DocumentAuthority,
    root_node: NodeRef,
    next_node: u64,
    atoms: Vec<Atom>,
    lines: Vec<ScannedLine>,
    natural_lines: Vec<PropertiesNaturalLine>,
    logical_lines: Vec<PropertiesLogicalLine>,
    properties: Vec<Property>,
    comments: Vec<PropertiesComment>,
    escapes: Vec<PropertiesEscape>,
    error_lines: Vec<PropertiesErrorLine>,
    diagnostics: Vec<Diagnostic>,
    occurrence: u64,
    recovered: bool,
    total_java_units: usize,
    total_unicode_escapes: usize,
}

impl Parser {
    fn new(
        source: SourceSnapshot,
        profile: PropertiesProfile,
        limits: PropertiesParseLimits,
    ) -> Result<Self, FatalFormationFailure> {
        let authority = DocumentAuthority::fresh();
        let root_node = authority.node_ref(0, NodeRole::PropertiesDocument);
        let atoms = build_atoms(&source)?;
        let mut parser = Self {
            source,
            profile,
            limits,
            authority,
            root_node,
            next_node: 1,
            atoms,
            lines: Vec::new(),
            natural_lines: Vec::new(),
            logical_lines: Vec::new(),
            properties: Vec::new(),
            comments: Vec::new(),
            escapes: Vec::new(),
            error_lines: Vec::new(),
            diagnostics: Vec::new(),
            occurrence: 0,
            recovered: false,
            total_java_units: 0,
            total_unicode_escapes: 0,
        };
        parser.scan_natural_lines()?;
        Ok(parser)
    }

    fn parse(mut self) -> Result<Document, FatalFormationFailure> {
        let mut line_index = 0;
        while line_index < self.lines.len() {
            if self.is_blank(line_index) {
                self.mark_line_content(line_index, PropertiesSyntaxKind::Whitespace);
                line_index += 1;
            } else if self.is_comment(line_index) {
                self.add_comment(line_index)?;
                line_index += 1;
            } else {
                line_index = self.add_logical_line(line_index)?;
            }
        }
        self.assign_duplicate_groups()?;
        let (pieces, syntax_kinds) = self.build_structural_pieces()?;
        let structural_index =
            LosslessStructuralIndex::new(self.authority.identity(), self.source.len(), pieces)
                .map_err(|_| {
                    FatalFormationFailure::resource_limit("source-coordinate-coverage", 1, 0)
                })?;
        Diagnostic::sort_deterministically(&mut self.diagnostics);
        Ok(Document {
            authority: self.authority,
            source: self.source,
            profile: self.profile,
            structural_index,
            syntax_kinds: Arc::from(syntax_kinds),
            formation_status: if self.recovered {
                FormationStatus::Recovered
            } else {
                FormationStatus::Complete
            },
            diagnostics: Arc::from(self.diagnostics),
            natural_lines: Arc::from(self.natural_lines),
            logical_lines: Arc::from(self.logical_lines),
            properties: Arc::from(self.properties),
            comments: Arc::from(self.comments),
            escapes: Arc::from(self.escapes),
            error_lines: Arc::from(self.error_lines),
            parse_limits: self.limits,
            root_node: self.root_node,
        })
    }

    fn scan_natural_lines(&mut self) -> Result<(), FatalFormationFailure> {
        let mut start = 0;
        if self.source.encoding_facts().bom().is_some()
            && self.atoms.first().is_some_and(|atom| atom.ch == '\u{feff}')
        {
            self.atoms[0].syntax = Some(PropertiesSyntaxKind::Bom);
            start = 1;
        }
        let mut cursor = start;
        while cursor < self.atoms.len() {
            let line_start = cursor;
            while cursor < self.atoms.len() && !matches!(self.atoms[cursor].ch, '\r' | '\n') {
                cursor += 1;
            }
            let content_end = cursor;
            if cursor < self.atoms.len() {
                if self.atoms[cursor].ch == '\r'
                    && self
                        .atoms
                        .get(cursor + 1)
                        .is_some_and(|atom| atom.ch == '\n')
                {
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            let end = cursor;
            self.check_limit(
                "natural-lines",
                self.lines.len().saturating_add(1),
                self.limits.max_natural_lines,
            )?;
            let scalar_count = content_end.saturating_sub(line_start);
            self.check_limit(
                "natural-line-scalars",
                scalar_count,
                self.limits.max_natural_line_scalars,
            )?;
            let span = self.atom_span(line_start, end)?;
            self.check_limit(
                "natural-line-bytes",
                span.len(),
                self.limits.max_natural_line_bytes,
            )?;
            let content_span = self.atom_span(line_start, content_end)?;
            let line_break_span = if content_end < end {
                self.mark_atoms(content_end..end, PropertiesSyntaxKind::LineBreak);
                Some(self.atom_span(content_end, end)?)
            } else {
                None
            };
            let node = self.issue_node(NodeRole::PropertiesNaturalLine)?;
            let natural_index = self.natural_lines.len();
            self.natural_lines.push(PropertiesNaturalLine {
                node,
                span,
                content_span,
                line_break_span,
            });
            self.lines.push(ScannedLine {
                atom_start: line_start,
                atom_content_end: content_end,
                atom_end: end,
                natural_index,
            });
        }
        Ok(())
    }

    fn is_blank(&self, line_index: usize) -> bool {
        let line = &self.lines[line_index];
        self.atoms[line.atom_start..line.atom_content_end]
            .iter()
            .all(|atom| is_properties_whitespace(atom.ch))
    }

    fn is_comment(&self, line_index: usize) -> bool {
        let line = &self.lines[line_index];
        let first = self.atoms[line.atom_start..line.atom_content_end]
            .iter()
            .find(|atom| !is_properties_whitespace(atom.ch));
        first.is_some_and(|atom| matches!(atom.ch, '#' | '!'))
    }

    fn mark_line_content(&mut self, line_index: usize, syntax: PropertiesSyntaxKind) {
        let line = self.lines[line_index].clone();
        self.mark_atoms(line.atom_start..line.atom_content_end, syntax);
    }

    fn add_comment(&mut self, line_index: usize) -> Result<(), FatalFormationFailure> {
        self.check_limit(
            "comments",
            self.comments.len().saturating_add(1),
            self.limits.max_comments,
        )?;
        let line = self.lines[line_index].clone();
        let marker_index = (line.atom_start..line.atom_content_end)
            .find(|index| !is_properties_whitespace(self.atoms[*index].ch))
            .expect("a comment line has a marker");
        self.mark_atoms(
            line.atom_start..marker_index,
            PropertiesSyntaxKind::Whitespace,
        );
        self.mark_atoms(
            marker_index..marker_index.saturating_add(1),
            PropertiesSyntaxKind::CommentMarker,
        );
        self.mark_atoms(
            marker_index + 1..line.atom_content_end,
            PropertiesSyntaxKind::CommentText,
        );
        let node = self.issue_node(NodeRole::PropertiesComment)?;
        self.comments.push(PropertiesComment {
            node,
            natural_line: self.natural_lines[line.natural_index].node,
            span: self.atom_span(line.atom_start, line.atom_content_end)?,
            marker: self.atoms[marker_index].ch,
        });
        Ok(())
    }

    fn add_logical_line(&mut self, first_line: usize) -> Result<usize, FatalFormationFailure> {
        self.check_limit(
            "logical-lines",
            self.logical_lines.len().saturating_add(1),
            self.limits.max_logical_lines,
        )?;
        let mut line_index = first_line;
        let mut natural_indices = Vec::new();
        let mut logical_atoms = Vec::new();
        loop {
            let line = self.lines[line_index].clone();
            natural_indices.push(line.natural_index);
            self.check_limit(
                "logical-line-natural-lines",
                natural_indices.len(),
                self.limits.max_logical_line_natural_lines,
            )?;
            let leading = if line_index == first_line {
                0
            } else {
                self.atoms[line.atom_start..line.atom_content_end]
                    .iter()
                    .take_while(|atom| is_properties_whitespace(atom.ch))
                    .count()
            };
            if leading > 0 {
                self.mark_atoms(
                    line.atom_start..line.atom_start + leading,
                    PropertiesSyntaxKind::Whitespace,
                );
            }
            let slash_run = self.atoms[line.atom_start + leading..line.atom_content_end]
                .iter()
                .rev()
                .take_while(|atom| atom.ch == '\\')
                .count();
            let has_break = line.atom_content_end < line.atom_end;
            let remove_terminal_slash = slash_run % 2 == 1;
            let logical_end = if remove_terminal_slash {
                line.atom_content_end - 1
            } else {
                line.atom_content_end
            };
            logical_atoms.extend(line.atom_start + leading..logical_end);
            self.check_limit(
                "logical-line-scalars",
                logical_atoms.len(),
                self.limits.max_logical_line_scalars,
            )?;
            if remove_terminal_slash {
                self.mark_atoms(
                    logical_end..line.atom_content_end,
                    PropertiesSyntaxKind::ContinuationMarker,
                );
            }
            if remove_terminal_slash && has_break && line_index + 1 < self.lines.len() {
                line_index += 1;
                continue;
            }
            break;
        }

        let next_line = line_index + 1;
        let natural_nodes: Arc<[NodeRef]> = natural_indices
            .iter()
            .map(|index| self.natural_lines[*index].node)
            .collect::<Vec<_>>()
            .into();
        let logical_node = self.issue_node(NodeRole::PropertiesLogicalLine)?;
        let leading = logical_atoms
            .iter()
            .take_while(|index| is_properties_whitespace(self.atoms[**index].ch))
            .count();
        self.mark_logical_positions(&logical_atoms, 0..leading, PropertiesSyntaxKind::Whitespace);
        let (key_start, key_end, value_start, had_separator) =
            self.split_property(&logical_atoms, leading);
        self.mark_logical_positions(
            &logical_atoms,
            key_start..key_end,
            PropertiesSyntaxKind::Key,
        );
        self.mark_logical_positions(
            &logical_atoms,
            key_end..value_start,
            PropertiesSyntaxKind::Separator,
        );
        self.mark_logical_positions(
            &logical_atoms,
            value_start..logical_atoms.len(),
            PropertiesSyntaxKind::Value,
        );

        let key = decode_java_string(&self.atoms, &logical_atoms[key_start..key_end]);
        let value = decode_java_string(&self.atoms, &logical_atoms[value_start..]);
        match (key, value) {
            (Ok(key), Ok(value)) => self.finish_property(
                logical_node,
                natural_nodes,
                &logical_atoms,
                key_start..key_end,
                value_start..logical_atoms.len(),
                had_separator,
                key,
                value,
                first_line,
                line_index,
            )?,
            (Err(error), _) | (_, Err(error)) => self.recover_logical_line(
                logical_node,
                natural_nodes,
                &logical_atoms,
                first_line,
                line_index,
                error,
            )?,
        }
        Ok(next_line)
    }

    fn split_property(
        &self,
        logical_atoms: &[usize],
        key_start: usize,
    ) -> (usize, usize, usize, bool) {
        let mut cursor = key_start;
        let mut escaped = false;
        while cursor < logical_atoms.len() {
            let ch = self.atoms[logical_atoms[cursor]].ch;
            if !escaped && (matches!(ch, '=' | ':') || is_properties_whitespace(ch)) {
                break;
            }
            if ch == '\\' {
                escaped = !escaped;
            } else {
                escaped = false;
            }
            cursor += 1;
        }
        let key_end = cursor;
        let had_separator = cursor < logical_atoms.len();
        while cursor < logical_atoms.len()
            && is_properties_whitespace(self.atoms[logical_atoms[cursor]].ch)
        {
            cursor += 1;
        }
        if cursor < logical_atoms.len() && matches!(self.atoms[logical_atoms[cursor]].ch, '=' | ':')
        {
            cursor += 1;
        }
        while cursor < logical_atoms.len()
            && is_properties_whitespace(self.atoms[logical_atoms[cursor]].ch)
        {
            cursor += 1;
        }
        (key_start, key_end, cursor, had_separator)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_property(
        &mut self,
        logical_node: NodeRef,
        natural_nodes: Arc<[NodeRef]>,
        logical_atoms: &[usize],
        key_range: Range<usize>,
        value_range: Range<usize>,
        had_separator: bool,
        key: DecodedJavaString,
        value: DecodedJavaString,
        first_line: usize,
        last_line: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.check_limit(
            "properties",
            self.properties.len().saturating_add(1),
            self.limits.max_properties,
        )?;
        self.check_limit(
            "java-code-units-per-string",
            key.units.len(),
            self.limits.max_java_code_units_per_string,
        )?;
        self.check_limit(
            "java-code-units-per-string",
            value.units.len(),
            self.limits.max_java_code_units_per_string,
        )?;
        let added_units = key.units.len().saturating_add(value.units.len());
        self.check_limit(
            "total-java-code-units",
            self.total_java_units.saturating_add(added_units),
            self.limits.max_total_java_code_units,
        )?;
        let added_escapes = key.escapes.len().saturating_add(value.escapes.len());
        let added_unicode_escapes = key.unicode_escapes.saturating_add(value.unicode_escapes);
        self.check_limit(
            "escapes",
            self.escapes.len().saturating_add(added_escapes),
            self.limits.max_escapes,
        )?;
        self.check_limit(
            "unicode-escapes",
            self.total_unicode_escapes
                .saturating_add(added_unicode_escapes),
            self.limits.max_unicode_escapes,
        )?;

        let property_node = self.issue_node(NodeRole::PropertiesProperty)?;
        let mut escape_nodes = Vec::with_capacity(added_escapes);
        for (in_key, spec) in key
            .escapes
            .iter()
            .map(|spec| (true, spec))
            .chain(value.escapes.iter().map(|spec| (false, spec)))
        {
            let node = self.issue_node(NodeRole::PropertiesEscape)?;
            self.atoms[spec.atom_indices[0]].syntax = Some(PropertiesSyntaxKind::EscapeMarker);
            for atom_index in &spec.atom_indices[1..] {
                self.atoms[*atom_index].syntax = Some(PropertiesSyntaxKind::EscapeBody);
            }
            let escape_start = spec.atom_indices[0];
            let escape_end = spec.atom_indices[spec.atom_indices.len() - 1] + 1;
            self.escapes.push(PropertiesEscape {
                node,
                property: property_node,
                in_key,
                kind: spec.kind,
                span: self.atom_span(escape_start, escape_end)?,
                output_start: spec.output_start,
                output_end: spec.output_end,
            });
            escape_nodes.push(node);
        }
        let value_state = if value.units.is_empty() {
            if had_separator {
                PropertiesValueState::ExplicitEmpty
            } else {
                PropertiesValueState::ImplicitEmpty
            }
        } else {
            PropertiesValueState::Present
        };
        let span = self.logical_source_span(first_line, last_line)?;
        let key_anchor =
            self.logical_anchor_span(logical_atoms, key_range.start, span.start_byte())?;
        let value_anchor =
            self.logical_anchor_span(logical_atoms, value_range.start, span.end_byte())?;
        let key_fragments = self.fragment_spans(logical_atoms, key_range)?;
        let value_fragments = self.fragment_spans(logical_atoms, value_range)?;
        self.logical_lines.push(PropertiesLogicalLine {
            node: logical_node,
            kind: PropertiesLogicalLineKind::Property,
            natural_lines: natural_nodes,
        });
        self.properties.push(Property {
            node: property_node,
            logical_line: logical_node,
            span,
            key_anchor,
            value_anchor,
            key_fragments: Arc::from(key_fragments),
            value_fragments: Arc::from(value_fragments),
            key: JavaString::from_code_units(key.units),
            value: JavaString::from_code_units(value.units),
            value_state,
            escapes: Arc::from(escape_nodes),
            duplicate_group: None,
        });
        self.total_java_units = self.total_java_units.saturating_add(added_units);
        self.total_unicode_escapes = self
            .total_unicode_escapes
            .saturating_add(added_unicode_escapes);
        Ok(())
    }

    fn recover_logical_line(
        &mut self,
        logical_node: NodeRef,
        natural_nodes: Arc<[NodeRef]>,
        logical_atoms: &[usize],
        first_line: usize,
        last_line: usize,
        error: DecodeError,
    ) -> Result<(), FatalFormationFailure> {
        self.check_limit(
            "recovery-regions",
            self.error_lines.len().saturating_add(1),
            self.limits.max_recovery_regions,
        )?;
        for atom_index in logical_atoms {
            self.atoms[*atom_index].syntax = Some(PropertiesSyntaxKind::ErrorRegion);
        }
        let span = self.logical_source_span(first_line, last_line)?;
        let error_span = self.atom_span(error.atom_start, error.atom_end)?;
        let code: Arc<str> = Arc::from("java-properties.parse.malformed-unicode-escape@1");
        let error_node = self.issue_node(NodeRole::PropertiesErrorLine)?;
        self.logical_lines.push(PropertiesLogicalLine {
            node: logical_node,
            kind: PropertiesLogicalLineKind::Error,
            natural_lines: natural_nodes.clone(),
        });
        self.error_lines.push(PropertiesErrorLine {
            node: error_node,
            logical_line: logical_node,
            natural_lines: natural_nodes,
            span,
            code: code.clone(),
        });
        self.diagnostic(
            &code,
            DiagnosticCategory::Syntax,
            error_span.start_byte(),
            error_span.end_byte(),
        )?;
        Ok(())
    }

    fn assign_duplicate_groups(&mut self) -> Result<(), FatalFormationFailure> {
        let mut groups: BTreeMap<Vec<u16>, Vec<usize>> = BTreeMap::new();
        for (index, property) in self.properties.iter().enumerate() {
            groups
                .entry(property.key.code_units().to_vec())
                .or_default()
                .push(index);
        }
        let mut next_group = 1_u32;
        for indices in groups.values().filter(|indices| indices.len() > 1) {
            self.check_limit(
                "duplicate-group-members",
                indices.len(),
                self.limits.max_duplicate_group_members,
            )?;
            let group = next_group;
            next_group = next_group.checked_add(1).ok_or_else(|| {
                FatalFormationFailure::resource_limit(
                    "duplicate-groups",
                    usize::MAX,
                    u32::MAX as usize,
                )
            })?;
            for index in indices {
                self.properties[*index].duplicate_group = Some(group);
            }
        }
        Ok(())
    }

    fn build_structural_pieces(
        &self,
    ) -> Result<(Vec<StructuralPiece>, Vec<PropertiesSyntaxKind>), FatalFormationFailure> {
        let mut pieces = Vec::new();
        let mut syntax_kinds = Vec::new();
        let mut cursor = 0;
        while cursor < self.atoms.len() {
            let syntax = self.atoms[cursor]
                .syntax
                .unwrap_or(PropertiesSyntaxKind::ErrorRegion);
            let kind = structural_kind(syntax);
            let start = cursor;
            cursor += 1;
            while cursor < self.atoms.len()
                && self.atoms[cursor]
                    .syntax
                    .unwrap_or(PropertiesSyntaxKind::ErrorRegion)
                    == syntax
                && self.atoms[cursor].raw_start == self.atoms[cursor - 1].raw_end
            {
                cursor += 1;
            }
            self.check_limit(
                "syntax-pieces",
                pieces.len().saturating_add(1),
                self.limits.common.max_token_count,
            )?;
            pieces.push(StructuralPiece::new(self.atom_span(start, cursor)?, kind));
            syntax_kinds.push(syntax);
        }
        Ok((pieces, syntax_kinds))
    }

    fn mark_atoms(&mut self, range: Range<usize>, syntax: PropertiesSyntaxKind) {
        for atom in &mut self.atoms[range] {
            atom.syntax = Some(syntax);
        }
    }

    fn mark_logical_positions(
        &mut self,
        logical_atoms: &[usize],
        range: Range<usize>,
        syntax: PropertiesSyntaxKind,
    ) {
        for position in range {
            self.atoms[logical_atoms[position]].syntax = Some(syntax);
        }
    }

    fn fragment_spans(
        &self,
        logical_atoms: &[usize],
        range: Range<usize>,
    ) -> Result<Vec<Span>, FatalFormationFailure> {
        let mut spans = Vec::new();
        let Some(first_position) = range.clone().next() else {
            return Ok(spans);
        };
        let mut fragment_start = logical_atoms[first_position];
        let mut previous = fragment_start;
        for position in range.skip(1) {
            let current = logical_atoms[position];
            if self.atoms[current].raw_start != self.atoms[previous].raw_end {
                spans.push(self.atom_span(fragment_start, previous + 1)?);
                fragment_start = current;
            }
            previous = current;
        }
        spans.push(self.atom_span(fragment_start, previous + 1)?);
        Ok(spans)
    }

    fn logical_source_span(
        &self,
        first_line: usize,
        last_line: usize,
    ) -> Result<Span, FatalFormationFailure> {
        let first = &self.lines[first_line];
        let last = &self.lines[last_line];
        self.atom_span(first.atom_start, last.atom_content_end)
    }

    fn logical_anchor_span(
        &self,
        logical_atoms: &[usize],
        position: usize,
        empty_fallback: usize,
    ) -> Result<Span, FatalFormationFailure> {
        let raw = logical_atoms.get(position).map_or_else(
            || {
                logical_atoms
                    .last()
                    .map_or(empty_fallback, |index| self.atoms[*index].raw_end)
            },
            |index| self.atoms[*index].raw_start,
        );
        self.authority
            .span(raw, raw)
            .map_err(|_| FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0))
    }

    fn atom_span(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        let raw_start = if start < self.atoms.len() {
            self.atoms[start].raw_start
        } else {
            self.source.len()
        };
        let raw_end = if start == end {
            raw_start
        } else {
            self.atoms
                .get(end - 1)
                .map_or(self.source.len(), |atom| atom.raw_end)
        };
        self.authority
            .span(raw_start, raw_end)
            .map_err(|_| FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0))
    }

    fn issue_node(&mut self, role: NodeRole) -> Result<NodeRef, FatalFormationFailure> {
        let observed = usize::try_from(self.next_node)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        self.check_limit("nodes", observed, self.limits.common.max_node_count)?;
        let node = self.authority.node_ref(self.next_node, role);
        self.next_node = self.next_node.checked_add(1).ok_or_else(|| {
            FatalFormationFailure::resource_limit("node-identity", usize::MAX, usize::MAX - 1)
        })?;
        Ok(node)
    }

    fn check_limit(
        &self,
        name: &'static str,
        observed: usize,
        limit: usize,
    ) -> Result<(), FatalFormationFailure> {
        debug_assert!(
            self.next_node >= 1,
            "the document root always owns node zero"
        );
        if observed > limit {
            Err(FatalFormationFailure::resource_limit(name, observed, limit))
        } else {
            Ok(())
        }
    }

    fn diagnostic(
        &mut self,
        code: &str,
        category: DiagnosticCategory,
        start: usize,
        end: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.check_limit(
            "diagnostics",
            self.diagnostics.len().saturating_add(1),
            self.limits.common.max_diagnostics,
        )?;
        let start_byte = u64::try_from(start).map_err(|_| {
            FatalFormationFailure::resource_limit("diagnostic-coordinate", start, u64::MAX as usize)
        })?;
        let end_byte = u64::try_from(end).map_err(|_| {
            FatalFormationFailure::resource_limit("diagnostic-coordinate", end, u64::MAX as usize)
        })?;
        self.diagnostics.push(Diagnostic::new(
            code,
            category,
            DiagnosticSeverity::Error,
            Some(DiagnosticLocation {
                snapshot: Some(self.authority.identity().as_u64()),
                start_byte,
                end_byte,
            }),
            self.occurrence,
        ));
        self.occurrence = self.occurrence.saturating_add(1);
        self.recovered = true;
        Ok(())
    }
}

fn build_atoms(source: &SourceSnapshot) -> Result<Vec<Atom>, FatalFormationFailure> {
    let text = source
        .decoded_text()
        .expect("Properties source profiles always select text decoding");
    let mut atoms = Vec::with_capacity(text.chars().count());
    for (decoded_start, ch) in text.char_indices() {
        let decoded_end = decoded_start + ch.len_utf8();
        let raw_start = source
            .raw_byte_at(DecodedOffset::Utf8Byte(decoded_start))
            .map_err(|_| {
                FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0)
            })?;
        let raw_end = source
            .raw_byte_at(DecodedOffset::Utf8Byte(decoded_end))
            .map_err(|_| {
                FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0)
            })?;
        atoms.push(Atom {
            ch,
            raw_start,
            raw_end,
            syntax: None,
        });
    }
    Ok(atoms)
}

fn decode_java_string(
    atoms: &[Atom],
    atom_indices: &[usize],
) -> Result<DecodedJavaString, DecodeError> {
    let mut units = Vec::new();
    let mut escapes = Vec::new();
    let mut unicode_escapes = 0_usize;
    let mut cursor = 0;
    while cursor < atom_indices.len() {
        let atom_index = atom_indices[cursor];
        let ch = atoms[atom_index].ch;
        if ch != '\\' {
            let mut encoded = [0_u16; 2];
            units.extend_from_slice(ch.encode_utf16(&mut encoded));
            cursor += 1;
            continue;
        }
        let Some(next_index) = atom_indices.get(cursor + 1).copied() else {
            return Err(DecodeError {
                atom_start: atom_index,
                atom_end: atom_index + 1,
            });
        };
        let next = atoms[next_index].ch;
        let output_start = units.len();
        let (kind, consumed) = match next {
            'u' => {
                if cursor + 6 > atom_indices.len() {
                    return Err(DecodeError {
                        atom_start: atom_index,
                        atom_end: atom_indices.last().copied().unwrap_or(atom_index) + 1,
                    });
                }
                let mut value = 0_u16;
                for digit_index in &atom_indices[cursor + 2..cursor + 6] {
                    let digit_index = *digit_index;
                    let Some(digit) = atoms[digit_index].ch.to_digit(16) else {
                        return Err(DecodeError {
                            atom_start: atom_index,
                            atom_end: digit_index + 1,
                        });
                    };
                    value = (value << 4) | u16::try_from(digit).expect("hex digit fits u16");
                }
                units.push(value);
                unicode_escapes = unicode_escapes.saturating_add(1);
                (PropertiesEscapeKind::Unicode, 6)
            }
            't' => {
                units.push(u16::from(b'\t'));
                (PropertiesEscapeKind::Named, 2)
            }
            'n' => {
                units.push(u16::from(b'\n'));
                (PropertiesEscapeKind::Named, 2)
            }
            'r' => {
                units.push(u16::from(b'\r'));
                (PropertiesEscapeKind::Named, 2)
            }
            'f' => {
                units.push(u16::from(0x0C_u8));
                (PropertiesEscapeKind::Named, 2)
            }
            '\\' => {
                units.push(u16::from(b'\\'));
                (PropertiesEscapeKind::Backslash, 2)
            }
            other => {
                let mut encoded = [0_u16; 2];
                units.extend_from_slice(other.encode_utf16(&mut encoded));
                (PropertiesEscapeKind::DroppedBackslash, 2)
            }
        };
        escapes.push(EscapeSpec {
            atom_indices: atom_indices[cursor..cursor + consumed].to_vec(),
            kind,
            output_start,
            output_end: units.len(),
        });
        cursor += consumed;
    }
    Ok(DecodedJavaString {
        units,
        escapes,
        unicode_escapes,
    })
}

const fn is_properties_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\u{000c}')
}

const fn structural_kind(syntax: PropertiesSyntaxKind) -> StructuralPieceKind {
    match syntax {
        PropertiesSyntaxKind::Whitespace
        | PropertiesSyntaxKind::LineBreak
        | PropertiesSyntaxKind::CommentMarker
        | PropertiesSyntaxKind::CommentText => StructuralPieceKind::Trivia,
        PropertiesSyntaxKind::ErrorRegion => StructuralPieceKind::ErrorRegion,
        PropertiesSyntaxKind::Bom
        | PropertiesSyntaxKind::Key
        | PropertiesSyntaxKind::Separator
        | PropertiesSyntaxKind::Value
        | PropertiesSyntaxKind::EscapeMarker
        | PropertiesSyntaxKind::EscapeBody
        | PropertiesSyntaxKind::ContinuationMarker => StructuralPieceKind::Token,
    }
}
