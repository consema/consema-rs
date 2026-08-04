use crate::{
    Document, IniEncodingSelection, IniEntry, IniErrorLine, IniLogicalLine, IniLogicalLineKind,
    IniParseLimits, IniPhysicalLine, IniProfile, IniQuoteStyle, IniSection, IniSyntaxKind,
    IniValueState,
};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity};
use consema_document::{
    BomKind, BomPolicy, DecodedOffset, DocumentAuthority, EncodingRequest, FatalFormationFailure,
    FormationStatus, LosslessStructuralIndex, NodeRef, NodeRole, SourceEncoding, SourceLimits,
    SourceSnapshot, Span, StructuralPiece, StructuralPieceKind,
};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

pub(crate) fn parse(
    bytes: Arc<[u8]>,
    profile: IniProfile,
    selection: IniEncodingSelection,
    limits: IniParseLimits,
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
    profile: IniProfile,
    selection: IniEncodingSelection,
) -> Result<EncodingRequest, FatalFormationFailure> {
    let encoding = match selection {
        IniEncodingSelection::ProfileDefault => SourceEncoding::Utf8,
        IniEncodingSelection::Explicit(encoding) => encoding,
    };
    if encoding == SourceEncoding::Binary {
        return Err(profile_failure("ini.profile.encoding@1"));
    }
    let mut request = EncodingRequest::new(SourceEncoding::Utf8);
    if matches!(selection, IniEncodingSelection::Explicit(_)) {
        request = request.with_caller_override(encoding);
    }
    if matches!(encoding, SourceEncoding::WindowsCodePage(_)) {
        request = request.with_bom_policy(BomPolicy::TreatAsContent);
    }
    if profile == IniProfile::PortableV1 && encoding != SourceEncoding::Utf8 {
        return Err(profile_failure("ini.profile.encoding@1"));
    }
    Ok(request)
}

fn validate_profile_encoding(
    source: &SourceSnapshot,
    profile: IniProfile,
    selection: IniEncodingSelection,
) -> Result<(), FatalFormationFailure> {
    let facts = source.encoding_facts();
    let valid = match profile {
        IniProfile::PortableV1 => facts.selected() == SourceEncoding::Utf8 && facts.bom().is_none(),
        IniProfile::WindowsV1 => match selection {
            IniEncodingSelection::ProfileDefault => {
                (facts.selected() == SourceEncoding::Utf16Le
                    && facts.bom() == Some(BomKind::Utf16Le))
                    || (facts.selected() == SourceEncoding::Utf8
                        && facts.bom().is_none()
                        && source.bytes().iter().all(u8::is_ascii))
            }
            IniEncodingSelection::Explicit(SourceEncoding::Utf16Le) => {
                facts.selected() == SourceEncoding::Utf16Le && facts.bom() == Some(BomKind::Utf16Le)
            }
            IniEncodingSelection::Explicit(encoding @ SourceEncoding::WindowsCodePage(_)) => {
                facts.selected() == encoding
                    && facts.bom_policy() == BomPolicy::TreatAsContent
                    && facts.bom().is_none()
            }
            IniEncodingSelection::Explicit(_) => false,
        },
        IniProfile::PythonConfigParserV1 => facts.selected() != SourceEncoding::Binary,
    };
    if valid {
        Ok(())
    } else {
        Err(profile_failure("ini.profile.encoding@1"))
    }
}

fn profile_failure(code: &'static str) -> FatalFormationFailure {
    FatalFormationFailure::from_diagnostic(Diagnostic::new(
        code,
        DiagnosticCategory::Encoding,
        DiagnosticSeverity::Error,
        None,
        0,
    ))
}

#[derive(Clone, Debug)]
struct ScannedLine {
    decoded_start: usize,
    decoded_content_end: usize,
    decoded_break_start: usize,
    decoded_end: usize,
    physical_index: usize,
}

#[derive(Clone, Debug)]
struct PythonEntryState {
    entry_index: usize,
    logical_index: usize,
    indent: usize,
    continuation_lines: usize,
    logical_bytes: usize,
    logical_scalars: usize,
    pending_blank_lines: Vec<usize>,
}

struct Parser {
    source: SourceSnapshot,
    profile: IniProfile,
    limits: IniParseLimits,
    authority: DocumentAuthority,
    root_node: NodeRef,
    next_node: u64,
    lines: Vec<ScannedLine>,
    physical_lines: Vec<IniPhysicalLine>,
    logical_lines: Vec<IniLogicalLine>,
    sections: Vec<IniSection>,
    entries: Vec<IniEntry>,
    entry_section_indices: Vec<usize>,
    error_lines: Vec<IniErrorLine>,
    pieces: Vec<StructuralPiece>,
    syntax_kinds: Vec<IniSyntaxKind>,
    diagnostics: Vec<Diagnostic>,
    occurrence: u64,
    recovered: bool,
    current_section: Option<usize>,
    python_entry: Option<PythonEntryState>,
}

impl Parser {
    fn new(
        source: SourceSnapshot,
        profile: IniProfile,
        limits: IniParseLimits,
    ) -> Result<Self, FatalFormationFailure> {
        let authority = DocumentAuthority::fresh();
        let root_node = authority.node_ref(0, NodeRole::IniDocument);
        let mut parser = Self {
            source,
            profile,
            limits,
            authority,
            root_node,
            next_node: 1,
            lines: Vec::new(),
            physical_lines: Vec::new(),
            logical_lines: Vec::new(),
            sections: Vec::new(),
            entries: Vec::new(),
            entry_section_indices: Vec::new(),
            error_lines: Vec::new(),
            pieces: Vec::new(),
            syntax_kinds: Vec::new(),
            diagnostics: Vec::new(),
            occurrence: 0,
            recovered: false,
            current_section: None,
            python_entry: None,
        };
        parser.scan_physical_lines()?;
        Ok(parser)
    }

    fn parse(mut self) -> Result<Document, FatalFormationFailure> {
        self.push_bom()?;
        for line_index in 0..self.lines.len() {
            self.parse_line(line_index)?;
            self.push_line_break(line_index)?;
        }
        if self.profile == IniProfile::PortableV1 && self.sections.is_empty() {
            let at = self.source.len();
            self.diagnostic(
                "ini.parse.missing-section@1",
                DiagnosticCategory::Conformance,
                at,
                at,
                true,
            )?;
        }
        self.assign_duplicate_groups()?;
        let structural_index =
            LosslessStructuralIndex::new(self.authority.identity(), self.source.len(), self.pieces)
                .map_err(|_| {
                    FatalFormationFailure::resource_limit("source-coordinate-coverage", 1, 0)
                })?;
        Diagnostic::sort_deterministically(&mut self.diagnostics);
        Ok(Document {
            authority: self.authority,
            source: self.source,
            profile: self.profile,
            structural_index,
            syntax_kinds: Arc::from(self.syntax_kinds),
            formation_status: if self.recovered {
                FormationStatus::Recovered
            } else {
                FormationStatus::Complete
            },
            diagnostics: Arc::from(self.diagnostics),
            physical_lines: Arc::from(self.physical_lines),
            logical_lines: Arc::from(self.logical_lines),
            sections: Arc::from(self.sections),
            entries: Arc::from(self.entries),
            error_lines: Arc::from(self.error_lines),
            parse_limits: self.limits,
            root_node: self.root_node,
        })
    }

    fn scan_physical_lines(&mut self) -> Result<(), FatalFormationFailure> {
        let text = self
            .source
            .decoded_text()
            .expect("INI profiles reject Binary before parsing");
        let mut start =
            if self.source.encoding_facts().bom().is_some() && text.starts_with('\u{feff}') {
                '\u{feff}'.len_utf8()
            } else {
                0
            };
        let mut decoded_lines = Vec::new();
        while start < text.len() {
            let newline = text.as_bytes()[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| start + offset);
            let (content_end, break_start, end) = if let Some(newline) = newline {
                let break_start = if newline > start && text.as_bytes()[newline - 1] == b'\r' {
                    newline - 1
                } else {
                    newline
                };
                (break_start, break_start, newline + 1)
            } else {
                (text.len(), text.len(), text.len())
            };
            let observed = decoded_lines.len().saturating_add(1);
            self.check_limit("physical-lines", observed, self.limits.max_physical_lines)?;
            decoded_lines.push((
                start,
                content_end,
                break_start,
                end,
                text[start..content_end].chars().count(),
            ));
            start = end;
        }
        for (start, content_end, break_start, end, scalar_count) in decoded_lines {
            let full_span = self.raw_span(start..end)?;
            let content_span = self.raw_span(start..content_end)?;
            self.check_limit(
                "physical-line-bytes",
                full_span.len(),
                self.limits.max_physical_line_bytes,
            )?;
            self.check_limit(
                "physical-line-scalars",
                scalar_count,
                self.limits.max_physical_line_scalars,
            )?;
            let node = self.issue_node(NodeRole::IniPhysicalLine)?;
            let line_break_span = if break_start < end {
                Some(self.raw_span(break_start..end)?)
            } else {
                None
            };
            let physical_index = self.physical_lines.len();
            self.physical_lines.push(IniPhysicalLine {
                node,
                span: full_span,
                content_span,
                line_break_span,
            });
            self.lines.push(ScannedLine {
                decoded_start: start,
                decoded_content_end: content_end,
                decoded_break_start: break_start,
                decoded_end: end,
                physical_index,
            });
        }
        Ok(())
    }

    fn parse_line(&mut self, line_index: usize) -> Result<(), FatalFormationFailure> {
        let line = self.lines[line_index].clone();
        let content = self.decoded(&line);
        if content.contains(['\0', '\r']) {
            return self.recover_line(line_index, "ini.parse.invalid-character@1");
        }
        if self.profile == IniProfile::PortableV1
            && content
                .bytes()
                .any(|byte| byte != b'\t' && !(b' '..=b'~').contains(&byte))
        {
            return self.recover_line(line_index, "ini.parse.invalid-character@1");
        }
        if content.bytes().all(is_horizontal) {
            if !content.is_empty() {
                self.push_piece(
                    line.decoded_start..line.decoded_content_end,
                    StructuralPieceKind::Trivia,
                    IniSyntaxKind::Whitespace,
                )?;
            }
            if self.profile == IniProfile::PythonConfigParserV1 {
                if let Some(state) = &mut self.python_entry {
                    state.pending_blank_lines.push(line_index);
                }
            }
            return Ok(());
        }
        let leading = leading_horizontal(content);
        let marker = content.as_bytes().get(leading).copied();
        let is_comment = match self.profile {
            IniProfile::PortableV1 | IniProfile::WindowsV1 => marker == Some(b';'),
            IniProfile::PythonConfigParserV1 => matches!(marker, Some(b';' | b'#')),
        };
        if is_comment {
            self.push_comment(&line, leading)?;
            return Ok(());
        }
        match self.profile {
            IniProfile::PortableV1 => self.parse_portable_line(line_index),
            IniProfile::WindowsV1 => self.parse_windows_line(line_index),
            IniProfile::PythonConfigParserV1 => self.parse_python_line(line_index),
        }
    }

    fn parse_portable_line(&mut self, line_index: usize) -> Result<(), FatalFormationFailure> {
        self.python_entry = None;
        let line = self.lines[line_index].clone();
        let content = self.decoded(&line).to_owned();
        if content.starts_with('[') {
            if line.decoded_break_start == line.decoded_end
                || !content.ends_with(']')
                || content.len() < 3
            {
                return self.recover_line(line_index, "ini.parse.malformed-section@1");
            }
            let name = &content[1..content.len() - 1];
            if !name.bytes().all(is_portable_name) {
                return self.recover_line(line_index, "ini.parse.invalid-character@1");
            }
            self.push_section_syntax(&line, 0, 1, content.len() - 1, content.len())?;
            self.add_section(line_index, 1..content.len() - 1, name, false)
        } else {
            let Some(delimiter) = content.find('=') else {
                return self.recover_line(line_index, "ini.parse.missing-delimiter@1");
            };
            let key = &content[..delimiter];
            let value = &content[delimiter + 1..];
            if key.is_empty() || !key.bytes().all(is_portable_name) {
                return self.recover_line(line_index, "ini.parse.invalid-character@1");
            }
            if !value.bytes().all(is_portable_value) {
                return self.recover_line(line_index, "ini.parse.invalid-character@1");
            }
            let Some(section_index) = self.current_section else {
                return self.recover_line(line_index, "ini.parse.missing-section@1");
            };
            self.push_entry_syntax(
                &line,
                0..delimiter,
                delimiter..delimiter + 1,
                delimiter + 1..content.len(),
                None,
            )?;
            self.add_entry(
                line_index,
                section_index,
                0..delimiter,
                delimiter + 1..content.len(),
                key,
                value,
                IniQuoteStyle::None,
                leading_horizontal(&content),
            )?;
            Ok(())
        }
    }

    fn parse_windows_line(&mut self, line_index: usize) -> Result<(), FatalFormationFailure> {
        self.python_entry = None;
        let line = self.lines[line_index].clone();
        let content = self.decoded(&line).to_owned();
        let (trim_start, trim_end) = trim_horizontal_bounds(&content);
        let core = &content[trim_start..trim_end];
        if core.starts_with('[') {
            if !core.ends_with(']') || core.len() < 3 {
                return self.recover_line(line_index, "ini.parse.malformed-section@1");
            }
            let name = &core[1..core.len() - 1];
            if !name.bytes().all(is_windows_name) {
                return self.recover_line(line_index, "ini.parse.invalid-character@1");
            }
            self.push_optional_whitespace(&line, 0..trim_start)?;
            self.push_section_syntax(&line, trim_start, trim_start + 1, trim_end - 1, trim_end)?;
            self.push_optional_whitespace(&line, trim_end..content.len())?;
            self.add_section(line_index, trim_start + 1..trim_end - 1, name, false)
        } else {
            let Some(delimiter) = content[trim_start..]
                .find('=')
                .map(|item| item + trim_start)
            else {
                return self.recover_line(line_index, "ini.parse.missing-delimiter@1");
            };
            let (key_start, key_end) = trim_horizontal_bounds(&content[trim_start..delimiter]);
            let key_start = key_start + trim_start;
            let key_end = key_end + trim_start;
            let key = &content[key_start..key_end];
            if key.is_empty() || !key.bytes().all(is_windows_name) {
                return self.recover_line(line_index, "ini.parse.invalid-character@1");
            }
            let Some(section_index) = self.current_section else {
                return self.recover_line(line_index, "ini.parse.missing-section@1");
            };
            let literal_range = delimiter + 1..content.len();
            let literal = &content[literal_range.clone()];
            let (value_range, quote_style) = quoted_windows_value(literal, literal_range.start);
            let value = &content[value_range.clone()];
            self.push_optional_whitespace(&line, 0..key_start)?;
            self.push_piece_local(
                &line,
                key_start..key_end,
                StructuralPieceKind::Token,
                IniSyntaxKind::EntryKey,
            )?;
            self.push_optional_whitespace(&line, key_end..delimiter)?;
            self.push_piece_local(
                &line,
                delimiter..delimiter + 1,
                StructuralPieceKind::Token,
                IniSyntaxKind::Delimiter,
            )?;
            self.push_windows_value_syntax(&line, literal_range, value_range.clone(), quote_style)?;
            self.add_entry(
                line_index,
                section_index,
                key_start..key_end,
                value_range,
                key,
                value,
                quote_style,
                leading_horizontal(&content),
            )?;
            Ok(())
        }
    }

    fn parse_python_line(&mut self, line_index: usize) -> Result<(), FatalFormationFailure> {
        let line = self.lines[line_index].clone();
        let content = self.decoded(&line).to_owned();
        let indent = leading_horizontal(&content);
        if self
            .python_entry
            .as_ref()
            .is_some_and(|state| indent > state.indent)
        {
            return self.add_python_continuation(line_index, indent);
        }
        if let Some(state) = &mut self.python_entry {
            state.pending_blank_lines.clear();
        }
        self.python_entry = None;
        let (trim_start, trim_end) = trim_horizontal_bounds(&content);
        let core = &content[trim_start..trim_end];
        if core.starts_with('[') {
            if !core.ends_with(']') || core.len() < 3 {
                return self.recover_line(line_index, "ini.parse.malformed-section@1");
            }
            let name = &core[1..core.len() - 1];
            self.push_optional_whitespace(&line, 0..trim_start)?;
            self.push_section_syntax(&line, trim_start, trim_start + 1, trim_end - 1, trim_end)?;
            self.push_optional_whitespace(&line, trim_end..content.len())?;
            return self.add_section(
                line_index,
                trim_start + 1..trim_end - 1,
                name,
                name == "DEFAULT",
            );
        }
        let delimiter =
            first_python_delimiter(&content[trim_start..]).map(|offset| offset + trim_start);
        let Some(delimiter) = delimiter else {
            let diagnostic_code = if indent > 0 {
                "ini.parse.invalid-continuation@1"
            } else {
                "ini.parse.missing-delimiter@1"
            };
            return self.recover_line(line_index, diagnostic_code);
        };
        let (relative_key_start, relative_key_end) =
            trim_horizontal_bounds(&content[trim_start..delimiter]);
        let key_start = trim_start + relative_key_start;
        let key_end = trim_start + relative_key_end;
        if key_start == key_end {
            return self.recover_line(line_index, "ini.parse.malformed-line@1");
        }
        let Some(section_index) = self.current_section else {
            return self.recover_line(line_index, "ini.parse.missing-section@1");
        };
        let (relative_value_start, relative_value_end) =
            trim_horizontal_bounds(&content[delimiter + 1..]);
        let value_start = delimiter + 1 + relative_value_start;
        let value_end = delimiter + 1 + relative_value_end;
        let key = &content[key_start..key_end];
        let value = &content[value_start..value_end];
        self.push_optional_whitespace(&line, 0..key_start)?;
        self.push_piece_local(
            &line,
            key_start..key_end,
            StructuralPieceKind::Token,
            IniSyntaxKind::EntryKey,
        )?;
        self.push_optional_whitespace(&line, key_end..delimiter)?;
        self.push_piece_local(
            &line,
            delimiter..delimiter + 1,
            StructuralPieceKind::Token,
            IniSyntaxKind::Delimiter,
        )?;
        self.push_optional_whitespace(&line, delimiter + 1..value_start)?;
        if value_start < value_end {
            self.push_piece_local(
                &line,
                value_start..value_end,
                StructuralPieceKind::Token,
                IniSyntaxKind::EntryValue,
            )?;
        }
        self.push_optional_whitespace(&line, value_end..content.len())?;
        let entry_index = self.add_entry(
            line_index,
            section_index,
            key_start..key_end,
            value_start..value_end,
            key,
            value,
            IniQuoteStyle::None,
            indent,
        )?;
        let logical_index = self.entries[entry_index].logical_line;
        let logical_index = self
            .logical_lines
            .iter()
            .position(|line| line.node == logical_index)
            .expect("new entry logical line exists");
        let physical = &self.physical_lines[line.physical_index];
        self.python_entry = Some(PythonEntryState {
            entry_index,
            logical_index,
            indent,
            continuation_lines: 0,
            logical_bytes: physical.span.len(),
            logical_scalars: content.chars().count(),
            pending_blank_lines: Vec::new(),
        });
        Ok(())
    }

    fn add_python_continuation(
        &mut self,
        line_index: usize,
        indent: usize,
    ) -> Result<(), FatalFormationFailure> {
        let line = self.lines[line_index].clone();
        let content = self.decoded(&line).to_owned();
        let (_, value_end) = trim_horizontal_bounds(&content[indent..]);
        let value_start = indent;
        let value_end = indent + value_end;
        let mut state = self
            .python_entry
            .take()
            .expect("continuation requires an active entry");
        let added_lines = state
            .pending_blank_lines
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                FatalFormationFailure::resource_limit(
                    "continuation-lines",
                    usize::MAX,
                    self.limits.max_continuation_lines,
                )
            })?;
        let continuation_lines = state
            .continuation_lines
            .checked_add(added_lines)
            .ok_or_else(|| {
                FatalFormationFailure::resource_limit(
                    "continuation-lines",
                    usize::MAX,
                    self.limits.max_continuation_lines,
                )
            })?;
        self.check_limit(
            "continuation-lines",
            continuation_lines,
            self.limits.max_continuation_lines,
        )?;

        let mut pending_bytes = 0usize;
        let mut pending_scalars = 0usize;
        for pending in &state.pending_blank_lines {
            let pending_line = &self.lines[*pending];
            let physical = &self.physical_lines[pending_line.physical_index];
            pending_bytes = pending_bytes
                .checked_add(physical.span.len())
                .ok_or_else(|| {
                    FatalFormationFailure::resource_limit(
                        "logical-line-bytes",
                        usize::MAX,
                        self.limits.max_logical_line_bytes,
                    )
                })?;
            pending_scalars = pending_scalars
                .checked_add(self.decoded(pending_line).chars().count())
                .ok_or_else(|| {
                    FatalFormationFailure::resource_limit(
                        "logical-line-scalars",
                        usize::MAX,
                        self.limits.max_logical_line_scalars,
                    )
                })?;
        }
        let physical = &self.physical_lines[line.physical_index];
        let logical_bytes = state
            .logical_bytes
            .checked_add(pending_bytes)
            .and_then(|bytes| bytes.checked_add(physical.span.len()))
            .ok_or_else(|| {
                FatalFormationFailure::resource_limit(
                    "logical-line-bytes",
                    usize::MAX,
                    self.limits.max_logical_line_bytes,
                )
            })?;
        let logical_scalars = state
            .logical_scalars
            .checked_add(pending_scalars)
            .and_then(|scalars| scalars.checked_add(content.chars().count()))
            .ok_or_else(|| {
                FatalFormationFailure::resource_limit(
                    "logical-line-scalars",
                    usize::MAX,
                    self.limits.max_logical_line_scalars,
                )
            })?;
        self.check_limit(
            "logical-line-bytes",
            logical_bytes,
            self.limits.max_logical_line_bytes,
        )?;
        self.check_limit(
            "logical-line-scalars",
            logical_scalars,
            self.limits.max_logical_line_scalars,
        )?;

        let fragment = &content[value_start..value_end];
        let value_storage_bytes = self.entries[state.entry_index]
            .value
            .len()
            .checked_add(added_lines)
            .and_then(|bytes| bytes.checked_add(fragment.len()))
            .ok_or_else(|| {
                FatalFormationFailure::resource_limit(
                    "logical-value-storage-bytes",
                    usize::MAX,
                    self.limits.max_decoded_utf8_bytes,
                )
            })?;
        self.check_limit(
            "logical-value-storage-bytes",
            value_storage_bytes,
            self.limits.max_decoded_utf8_bytes,
        )?;
        let mut joined = String::new();
        joined.try_reserve(value_storage_bytes).map_err(|_| {
            FatalFormationFailure::resource_limit(
                "logical-value-storage-bytes",
                value_storage_bytes,
                self.limits.max_decoded_utf8_bytes,
            )
        })?;
        joined.push_str(&self.entries[state.entry_index].value);
        for pending in &state.pending_blank_lines {
            let pending_line = &self.lines[*pending];
            let physical = &self.physical_lines[pending_line.physical_index];
            self.logical_lines[state.logical_index]
                .physical_lines
                .push(physical.node);
            joined.push('\n');
        }
        self.logical_lines[state.logical_index]
            .physical_lines
            .push(physical.node);
        joined.push('\n');
        joined.push_str(fragment);
        state.logical_bytes = logical_bytes;
        state.logical_scalars = logical_scalars;
        self.entries[state.entry_index].value = Arc::from(joined);
        self.entries[state.entry_index].state = if self.entries[state.entry_index].value.is_empty()
        {
            IniValueState::Empty
        } else {
            IniValueState::Present
        };
        self.push_piece_local(
            &line,
            0..indent,
            StructuralPieceKind::Trivia,
            IniSyntaxKind::ContinuationMarker,
        )?;
        if value_start < value_end {
            self.push_piece_local(
                &line,
                value_start..value_end,
                StructuralPieceKind::Token,
                IniSyntaxKind::EntryValue,
            )?;
        }
        self.push_optional_whitespace(&line, value_end..content.len())?;
        state.continuation_lines = continuation_lines;
        state.pending_blank_lines.clear();
        self.python_entry = Some(state);
        Ok(())
    }

    fn add_section(
        &mut self,
        line_index: usize,
        name_range: Range<usize>,
        name: &str,
        is_default: bool,
    ) -> Result<(), FatalFormationFailure> {
        self.check_limit(
            "sections",
            self.sections.len().saturating_add(1),
            self.limits.max_sections,
        )?;
        let line = self.lines[line_index].clone();
        let logical_index = self.add_logical(line_index, IniLogicalLineKind::Section)?;
        let role = if is_default {
            NodeRole::IniDefaultSection
        } else {
            NodeRole::IniSection
        };
        let node = self.issue_node(role)?;
        let section = IniSection {
            node,
            logical_line: self.logical_lines[logical_index].node,
            span: self.physical_lines[line.physical_index].content_span,
            name_span: self.raw_span(
                line.decoded_start + name_range.start..line.decoded_start + name_range.end,
            )?,
            name: Arc::from(name),
            comparison_name: Arc::from(self.section_comparison(name)),
            is_default,
            duplicate_group: None,
        };
        self.sections.push(section);
        self.current_section = Some(self.sections.len() - 1);
        self.python_entry = None;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_entry(
        &mut self,
        line_index: usize,
        section_index: usize,
        key_range: Range<usize>,
        value_range: Range<usize>,
        key: &str,
        value: &str,
        quote_style: IniQuoteStyle,
        _indent: usize,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_limit(
            "entries",
            self.entries.len().saturating_add(1),
            self.limits.max_entries,
        )?;
        let line = self.lines[line_index].clone();
        let logical_index = self.add_logical(line_index, IniLogicalLineKind::Entry)?;
        let node = self.issue_node(NodeRole::IniEntry)?;
        let state = if value.is_empty() {
            IniValueState::Empty
        } else {
            IniValueState::Present
        };
        let entry = IniEntry {
            node,
            logical_line: self.logical_lines[logical_index].node,
            section: self.sections[section_index].node,
            span: self.physical_lines[line.physical_index].content_span,
            key_span: self.raw_span(
                line.decoded_start + key_range.start..line.decoded_start + key_range.end,
            )?,
            value_span: self.raw_span(
                line.decoded_start + value_range.start..line.decoded_start + value_range.end,
            )?,
            key: Arc::from(key),
            comparison_key: Arc::from(self.key_comparison(key)),
            value: Arc::from(value),
            state,
            quote_style,
            duplicate_group: None,
        };
        let entry_index = self.entries.len();
        self.entries.push(entry);
        self.entry_section_indices.push(section_index);
        Ok(entry_index)
    }

    fn add_logical(
        &mut self,
        line_index: usize,
        kind: IniLogicalLineKind,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_limit(
            "logical-lines",
            self.logical_lines.len().saturating_add(1),
            self.limits.max_logical_lines,
        )?;
        let line = &self.lines[line_index];
        let physical_span = self.physical_lines[line.physical_index].span;
        let physical_node = self.physical_lines[line.physical_index].node;
        self.check_limit(
            "logical-line-bytes",
            physical_span.len(),
            self.limits.max_logical_line_bytes,
        )?;
        self.check_limit(
            "logical-line-scalars",
            self.decoded(line).chars().count(),
            self.limits.max_logical_line_scalars,
        )?;
        let node = self.issue_node(NodeRole::IniLogicalLine)?;
        let index = self.logical_lines.len();
        self.logical_lines.push(IniLogicalLine {
            node,
            kind,
            physical_lines: vec![physical_node],
        });
        Ok(index)
    }

    fn recover_line(
        &mut self,
        line_index: usize,
        code: &'static str,
    ) -> Result<(), FatalFormationFailure> {
        self.check_limit(
            "recovery-regions",
            self.error_lines.len().saturating_add(1),
            self.limits.max_recovery_regions,
        )?;
        self.python_entry = None;
        let line = self.lines[line_index].clone();
        if line.decoded_start < line.decoded_content_end {
            self.push_piece(
                line.decoded_start..line.decoded_content_end,
                StructuralPieceKind::ErrorRegion,
                IniSyntaxKind::ErrorRegion,
            )?;
        }
        let logical_index = self.add_logical(line_index, IniLogicalLineKind::Error)?;
        let node = self.issue_node(NodeRole::IniErrorLine)?;
        let physical = &self.physical_lines[line.physical_index];
        self.error_lines.push(IniErrorLine {
            node,
            logical_line: self.logical_lines[logical_index].node,
            physical_line: physical.node,
            span: physical.content_span,
            code: Arc::from(code),
        });
        self.diagnostic(
            code,
            DiagnosticCategory::Syntax,
            physical.content_span.start_byte(),
            physical.content_span.end_byte(),
            true,
        )
    }

    fn push_bom(&mut self) -> Result<(), FatalFormationFailure> {
        if self.source.encoding_facts().bom().is_some() {
            let text = self.source.decoded_text().expect("text source");
            if text.starts_with('\u{feff}') {
                self.push_piece(
                    0..'\u{feff}'.len_utf8(),
                    StructuralPieceKind::Trivia,
                    IniSyntaxKind::Bom,
                )?;
            }
        }
        Ok(())
    }

    fn push_comment(
        &mut self,
        line: &ScannedLine,
        leading: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.push_optional_whitespace(line, 0..leading)?;
        self.push_piece_local(
            line,
            leading..leading + 1,
            StructuralPieceKind::Trivia,
            IniSyntaxKind::CommentMarker,
        )?;
        let len = line.decoded_content_end - line.decoded_start;
        if leading + 1 < len {
            self.push_piece_local(
                line,
                leading + 1..len,
                StructuralPieceKind::Trivia,
                IniSyntaxKind::CommentText,
            )?;
        }
        Ok(())
    }

    fn push_section_syntax(
        &mut self,
        line: &ScannedLine,
        open: usize,
        name_start: usize,
        name_end: usize,
        close_end: usize,
    ) -> Result<(), FatalFormationFailure> {
        self.push_piece_local(
            line,
            open..name_start,
            StructuralPieceKind::Token,
            IniSyntaxKind::SectionOpen,
        )?;
        self.push_piece_local(
            line,
            name_start..name_end,
            StructuralPieceKind::Token,
            IniSyntaxKind::SectionName,
        )?;
        self.push_piece_local(
            line,
            name_end..close_end,
            StructuralPieceKind::Token,
            IniSyntaxKind::SectionClose,
        )
    }

    fn push_entry_syntax(
        &mut self,
        line: &ScannedLine,
        key: Range<usize>,
        delimiter: Range<usize>,
        value: Range<usize>,
        quote: Option<(Range<usize>, Range<usize>)>,
    ) -> Result<(), FatalFormationFailure> {
        self.push_piece_local(
            line,
            key,
            StructuralPieceKind::Token,
            IniSyntaxKind::EntryKey,
        )?;
        self.push_piece_local(
            line,
            delimiter,
            StructuralPieceKind::Token,
            IniSyntaxKind::Delimiter,
        )?;
        if let Some((open, close)) = quote {
            self.push_piece_local(line, open, StructuralPieceKind::Token, IniSyntaxKind::Quote)?;
            if value.start < value.end {
                self.push_piece_local(
                    line,
                    value,
                    StructuralPieceKind::Token,
                    IniSyntaxKind::EntryValue,
                )?;
            }
            self.push_piece_local(
                line,
                close,
                StructuralPieceKind::Token,
                IniSyntaxKind::Quote,
            )?;
        } else if value.start < value.end {
            self.push_piece_local(
                line,
                value,
                StructuralPieceKind::Token,
                IniSyntaxKind::EntryValue,
            )?;
        }
        Ok(())
    }

    fn push_windows_value_syntax(
        &mut self,
        line: &ScannedLine,
        literal: Range<usize>,
        value: Range<usize>,
        quote_style: IniQuoteStyle,
    ) -> Result<(), FatalFormationFailure> {
        if quote_style == IniQuoteStyle::None {
            return self.push_entry_syntax(line, 0..0, 0..0, literal, None);
        }
        self.push_entry_syntax(
            line,
            0..0,
            0..0,
            value.clone(),
            Some((literal.start..value.start, value.end..literal.end)),
        )
    }

    fn push_line_break(&mut self, line_index: usize) -> Result<(), FatalFormationFailure> {
        let line = self.lines[line_index].clone();
        if line.decoded_break_start < line.decoded_end {
            self.push_piece(
                line.decoded_break_start..line.decoded_end,
                StructuralPieceKind::Trivia,
                IniSyntaxKind::LineBreak,
            )?;
        }
        Ok(())
    }

    fn push_optional_whitespace(
        &mut self,
        line: &ScannedLine,
        range: Range<usize>,
    ) -> Result<(), FatalFormationFailure> {
        if range.start < range.end {
            self.push_piece_local(
                line,
                range,
                StructuralPieceKind::Trivia,
                IniSyntaxKind::Whitespace,
            )?;
        }
        Ok(())
    }

    fn push_piece_local(
        &mut self,
        line: &ScannedLine,
        range: Range<usize>,
        kind: StructuralPieceKind,
        syntax: IniSyntaxKind,
    ) -> Result<(), FatalFormationFailure> {
        if range.start == range.end {
            return Ok(());
        }
        self.push_piece(
            line.decoded_start + range.start..line.decoded_start + range.end,
            kind,
            syntax,
        )
    }

    fn push_piece(
        &mut self,
        decoded: Range<usize>,
        kind: StructuralPieceKind,
        syntax: IniSyntaxKind,
    ) -> Result<(), FatalFormationFailure> {
        let observed = self.pieces.len().saturating_add(1);
        self.check_limit(
            "syntax-pieces",
            observed,
            self.limits.common.max_token_count,
        )?;
        let span = self.raw_span(decoded)?;
        if span.is_empty() {
            return Err(FatalFormationFailure::resource_limit(
                "source-coordinate-coverage",
                1,
                0,
            ));
        }
        self.pieces.push(StructuralPiece::new(span, kind));
        self.syntax_kinds.push(syntax);
        Ok(())
    }

    fn raw_span(&self, decoded: Range<usize>) -> Result<Span, FatalFormationFailure> {
        let start = self
            .source
            .raw_byte_at(DecodedOffset::Utf8Byte(decoded.start))
            .map_err(|_| {
                FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0)
            })?;
        let end = self
            .source
            .raw_byte_at(DecodedOffset::Utf8Byte(decoded.end))
            .map_err(|_| {
                FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0)
            })?;
        self.authority
            .span(start, end)
            .map_err(|_| FatalFormationFailure::resource_limit("source-coordinate-boundary", 1, 0))
    }

    fn decoded<'a>(&'a self, line: &ScannedLine) -> &'a str {
        &self.source.decoded_text().expect("text source")
            [line.decoded_start..line.decoded_content_end]
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
        debug_assert_eq!(self.pieces.len(), self.syntax_kinds.len());
        if observed > limit {
            Err(FatalFormationFailure::resource_limit(name, observed, limit))
        } else {
            Ok(())
        }
    }

    fn diagnostic(
        &mut self,
        code: &'static str,
        category: DiagnosticCategory,
        start: usize,
        end: usize,
        recovered: bool,
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
            if recovered {
                DiagnosticSeverity::Error
            } else {
                DiagnosticSeverity::Warning
            },
            Some(DiagnosticLocation {
                snapshot: Some(self.authority.identity().as_u64()),
                start_byte,
                end_byte,
            }),
            self.occurrence,
        ));
        self.occurrence = self.occurrence.saturating_add(1);
        self.recovered |= recovered;
        Ok(())
    }

    fn section_comparison(&self, name: &str) -> String {
        match self.profile {
            IniProfile::WindowsV1 => name.to_ascii_lowercase(),
            IniProfile::PortableV1 | IniProfile::PythonConfigParserV1 => name.to_owned(),
        }
    }

    fn key_comparison(&self, key: &str) -> String {
        match self.profile {
            IniProfile::PortableV1 => key.to_owned(),
            IniProfile::WindowsV1 => key.to_ascii_lowercase(),
            IniProfile::PythonConfigParserV1 => key.to_lowercase(),
        }
    }

    fn assign_duplicate_groups(&mut self) -> Result<(), FatalFormationFailure> {
        let mut section_groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, section) in self.sections.iter().enumerate() {
            section_groups
                .entry(section.comparison_name.to_string())
                .or_default()
                .push(index);
        }
        let mut next_group = 1_u32;
        for indices in section_groups.values().filter(|indices| indices.len() > 1) {
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
            let first_name = self.sections[indices[0]].name.clone();
            for index in indices {
                self.sections[*index].duplicate_group = Some(group);
            }
            for index in indices.iter().skip(1) {
                let span = self.sections[*index].span;
                let code = if self.sections[*index].name == first_name {
                    "ini.formation.duplicate-section@1"
                } else {
                    "ini.formation.case-collision@1"
                };
                self.diagnostic(
                    code,
                    DiagnosticCategory::Semantic,
                    span.start_byte(),
                    span.end_byte(),
                    self.profile != IniProfile::WindowsV1,
                )?;
            }
        }

        let mut entry_groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let section_index = self.entry_section_indices[index];
            let section_identity = if self.profile == IniProfile::WindowsV1 {
                self.sections[section_index].comparison_name.to_string()
            } else {
                section_index.to_string()
            };
            entry_groups
                .entry((section_identity, entry.comparison_key.to_string()))
                .or_default()
                .push(index);
        }
        for indices in entry_groups.values().filter(|indices| indices.len() > 1) {
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
            let first_key = self.entries[indices[0]].key.clone();
            for index in indices {
                self.entries[*index].duplicate_group = Some(group);
            }
            for index in indices.iter().skip(1) {
                let span = self.entries[*index].span;
                let code = if self.entries[*index].key == first_key {
                    "ini.formation.duplicate-entry@1"
                } else {
                    "ini.formation.case-collision@1"
                };
                self.diagnostic(
                    code,
                    DiagnosticCategory::Semantic,
                    span.start_byte(),
                    span.end_byte(),
                    self.profile != IniProfile::WindowsV1,
                )?;
            }
        }
        Ok(())
    }
}

fn leading_horizontal(value: &str) -> usize {
    value
        .bytes()
        .take_while(|byte| is_horizontal(*byte))
        .count()
}

fn trim_horizontal_bounds(value: &str) -> (usize, usize) {
    let start = leading_horizontal(value);
    let end = value
        .bytes()
        .rposition(|byte| !is_horizontal(byte))
        .map_or(start, |index| index + 1);
    (start.min(end), end)
}

const fn is_horizontal(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
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

fn quoted_windows_value(value: &str, absolute_start: usize) -> (Range<usize>, IniQuoteStyle) {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        let style = match (first, last) {
            (b'\'', b'\'') => IniQuoteStyle::Single,
            (b'"', b'"') => IniQuoteStyle::Double,
            _ => IniQuoteStyle::None,
        };
        if style != IniQuoteStyle::None {
            return (absolute_start + 1..absolute_start + value.len() - 1, style);
        }
    }
    (
        absolute_start..absolute_start + value.len(),
        IniQuoteStyle::None,
    )
}

fn first_python_delimiter(value: &str) -> Option<usize> {
    value.bytes().position(|byte| matches!(byte, b'=' | b':'))
}
