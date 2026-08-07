//! XML formation: source facts, tokenization, native tree, safe DTD subset,
//! bounded entity expansion, recovery, and exhaustive piece coverage
//! (RFC 0012 §2-4, §6-7, §12-13).

use crate::document::{
    Document, EntityDeclarationData, QNameFacts, ReferenceFragment, XmlAttributeData, XmlCdataData,
    XmlCommentData, XmlContent, XmlDeclarationData, XmlDoctypeData, XmlElementData,
    XmlNamespaceBindingData, XmlPiData, XmlPrologItem, XmlSyntaxKind, XmlTextData,
};
use crate::entity::{ExpansionBreach, is_xml_char, predefined_value, validate_replacement_text};
use crate::namespace::{ExpandedName, NamespaceError, NamespaceScope};
use crate::{XmlEncodingSelection, XmlParseLimits, XmlProfile};
use consema_core::{Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{
    BomKind, BomPolicy, DecodedOffset, DocumentAuthority, EncodingRequest, FatalFormationFailure,
    FormationStatus, LosslessStructuralIndex, SourceEncoding, SourceLimits, SourceSnapshot, Span,
    StructuralPiece, StructuralPieceKind,
};
use std::sync::Arc;
use xmlparser::{EntityDefinition, ExternalId, StrSpan, Token, Tokenizer};

pub(crate) fn parse(
    bytes: Arc<[u8]>,
    profile: XmlProfile,
    selection: XmlEncodingSelection,
    limits: XmlParseLimits,
) -> Result<Document, FatalFormationFailure> {
    let request = encoding_request(selection)?;
    let source = Arc::new(
        SourceSnapshot::from_raw(
            bytes,
            request,
            SourceLimits {
                max_raw_bytes: limits.common.max_source_bytes,
                max_decoded_utf8_bytes: limits.max_decoded_utf8_bytes,
                max_decoded_scalars: limits.max_decoded_scalars,
            },
        )
        .map_err(FatalFormationFailure::source_error)?,
    );
    validate_profile_encoding(&source, selection)?;
    let decoded = source
        .decoded_text()
        .ok_or_else(|| source_failure("xml.source.decoding@1"))?;
    Parser::new(Arc::clone(&source), profile, limits)?.parse(decoded)
}

fn bom_len(bom: BomKind) -> usize {
    match bom {
        BomKind::Utf8 => 3,
        BomKind::Utf16Le | BomKind::Utf16Be => 2,
    }
}

/// Resolves the source encoding request under the RFC 0012 §2 table.
fn encoding_request(
    selection: XmlEncodingSelection,
) -> Result<EncodingRequest, FatalFormationFailure> {
    match selection {
        XmlEncodingSelection::ProfileDefault => {
            let mut request = EncodingRequest::new(SourceEncoding::Utf8);
            request = request.with_bom_policy(BomPolicy::DetectUnicode);
            Ok(request)
        }
        XmlEncodingSelection::Explicit(encoding) => {
            let admitted = matches!(
                encoding,
                SourceEncoding::Utf8 | SourceEncoding::Utf16Le | SourceEncoding::Utf16Be
            );
            if !admitted {
                // UTF-32, Latin-1, Windows code pages, and other IANA
                // encodings are explicit v1 Profile exclusions.
                return Err(profile_failure("xml.profile.encoding@1"));
            }
            let mut request = EncodingRequest::new(SourceEncoding::Utf8);
            request = request.with_caller_override(encoding);
            Ok(request)
        }
    }
}

fn validate_profile_encoding(
    source: &SourceSnapshot,
    selection: XmlEncodingSelection,
) -> Result<(), FatalFormationFailure> {
    let facts = source.encoding_facts();
    let valid = match selection {
        XmlEncodingSelection::ProfileDefault => matches!(
            facts.selected(),
            SourceEncoding::Utf8 | SourceEncoding::Utf16Le | SourceEncoding::Utf16Be
        ),
        XmlEncodingSelection::Explicit(SourceEncoding::Utf8) => {
            facts.selected() == SourceEncoding::Utf8
        }
        XmlEncodingSelection::Explicit(SourceEncoding::Utf16Le) => {
            facts.selected() == SourceEncoding::Utf16Le && facts.bom() == Some(BomKind::Utf16Le)
        }
        XmlEncodingSelection::Explicit(SourceEncoding::Utf16Be) => {
            facts.selected() == SourceEncoding::Utf16Be && facts.bom() == Some(BomKind::Utf16Be)
        }
        XmlEncodingSelection::Explicit(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(profile_failure("xml.profile.encoding@1"))
    }
}

fn source_failure(code: &'static str) -> FatalFormationFailure {
    FatalFormationFailure::from_diagnostic(Diagnostic::new(
        code,
        DiagnosticCategory::Encoding,
        DiagnosticSeverity::Error,
        None,
        0,
    ))
}

fn profile_failure(code: &'static str) -> FatalFormationFailure {
    FatalFormationFailure::from_diagnostic(Diagnostic::new(
        code,
        DiagnosticCategory::Conformance,
        DiagnosticSeverity::Error,
        None,
        0,
    ))
}

fn namespace_code(error: &NamespaceError) -> &'static str {
    match error {
        NamespaceError::UnboundPrefix { .. } => "xml.namespace.unbound-prefix@1",
        NamespaceError::ReservedPrefix { .. } => "xml.namespace.reserved-prefix@1",
        NamespaceError::IllegalXmlRebinding { .. } => "xml.namespace.xml-rebinding@1",
        NamespaceError::IllegalDefaultXmlns => "xml.namespace.default-xmlns@1",
    }
}

/// Skips XML declaration spaces (ASCII ` `, `\t`, `\n`, `\r`) forward.
fn skip_declaration_spaces(text: &str, mut cursor: usize) -> usize {
    while let Some(byte) = text.as_bytes().get(cursor).copied() {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            cursor += 1;
        } else {
            break;
        }
    }
    cursor
}

/// One attribute seen before start-tag finalization.
struct PendingAttribute {
    qname: QNameFacts,
    span: Span,
    value_span: Span,
    fragments: Arc<[ReferenceFragment]>,
    normalized: Arc<str>,
    single_quote: bool,
}

/// One namespace declaration seen before start-tag finalization.
struct PendingDeclaration {
    qname: QNameFacts,
    uri: Arc<str>,
    uri_span: Span,
}

struct Frame {
    start: usize,
    span: Span,
    qname: QNameFacts,
    expanded: Option<ExpandedName>,
    namespace_error: Option<NamespaceError>,
    scope: NamespaceScope,
    namespaces: Vec<XmlNamespaceBindingData>,
    attributes: Vec<XmlAttributeData>,
    children: Vec<usize>,
    pending_declarations: Vec<PendingDeclaration>,
    pending_attributes: Vec<PendingAttribute>,
}

struct Parser {
    source: Arc<SourceSnapshot>,
    authority: DocumentAuthority,
    limits: XmlParseLimits,
    diagnostics: Vec<Diagnostic>,
    pieces: Vec<StructuralPiece>,
    syntax_kinds: Vec<XmlSyntaxKind>,
    nodes: Vec<XmlContent>,
    parent_of: Vec<Option<usize>>,
    next_ordinal: u64,
    entity_state: crate::entity::EntityExpansionState,
    /// Admitted internal general entities in declaration order; lookups are
    /// linear over a bounded, low thousands of declarations.
    entities: Vec<EntityDeclarationData>,
    stack: Vec<Frame>,
    prolog: Vec<XmlPrologItem>,
    epilog: Vec<XmlPrologItem>,
    declaration: Option<XmlDeclarationData>,
    doctype: Option<XmlDoctypeData>,
    doctype_name: Option<QNameFacts>,
    doctype_span_start: Option<usize>,
    external_subset_recovered: bool,
    dtd_subset_start: Option<usize>,
    root: Option<usize>,
    recovered: bool,
    error_regions: usize,
}

impl Parser {
    fn new(
        source: Arc<SourceSnapshot>,
        profile: XmlProfile,
        limits: XmlParseLimits,
    ) -> Result<Self, FatalFormationFailure> {
        if !matches!(profile, XmlProfile::SafeV1) {
            return Err(profile_failure("xml.profile.unknown@1"));
        }
        Ok(Self {
            source,
            authority: DocumentAuthority::fresh(),
            limits,
            diagnostics: Vec::new(),
            pieces: Vec::new(),
            syntax_kinds: Vec::new(),
            nodes: Vec::new(),
            parent_of: Vec::new(),
            next_ordinal: 0,
            entity_state: crate::entity::EntityExpansionState::new(),
            entities: Vec::new(),
            stack: Vec::new(),
            prolog: Vec::new(),
            epilog: Vec::new(),
            declaration: None,
            doctype: None,
            doctype_name: None,
            doctype_span_start: None,
            external_subset_recovered: false,
            dtd_subset_start: None,
            root: None,
            recovered: false,
            error_regions: 0,
        })
    }

    fn parse(mut self, decoded: &str) -> Result<Document, FatalFormationFailure> {
        self.cover_bom(decoded)?;
        let mut tokenizer = Tokenizer::from(decoded);
        loop {
            match tokenizer.next() {
                None => break,
                Some(Ok(token)) => {
                    self.token(token, decoded)?;
                }
                Some(Err(_)) => {
                    // xmlparser reports errors as row/col; the tokenizer's
                    // stream position is the deterministic decoded offset.
                    let pos = tokenizer.stream().pos();
                    let end = pos.min(decoded.len());
                    let start = end.saturating_sub(1);
                    self.recover_error_region(start, end, decoded)?;
                    let next = Self::find_next_markup(decoded, end);
                    match next {
                        Some(markup) => {
                            tokenizer = Tokenizer::from_fragment(decoded, markup..decoded.len());
                        }
                        None => break,
                    }
                }
            }
        }
        self.finish()
    }

    /// Covers a leading BOM as trivia; xmlparser skips it in decoded text.
    fn cover_bom(&mut self, _decoded: &str) -> Result<(), FatalFormationFailure> {
        if let Some(bom) = self.source.encoding_facts().bom() {
            let len = bom_len(bom);
            if len > 0 {
                let span = self.span(0, len)?;
                self.push_piece(span, XmlSyntaxKind::Bom, StructuralPieceKind::Trivia);
            }
        }
        Ok(())
    }

    fn token(&mut self, token: Token<'_>, decoded: &str) -> Result<(), FatalFormationFailure> {
        match token {
            Token::Declaration {
                version,
                encoding,
                standalone,
                span,
            } => self.declaration(version, encoding, standalone, span),
            Token::ProcessingInstruction {
                target,
                content,
                span,
            } => self.processing_instruction(target, content, span),
            Token::Comment { text, span } => self.comment(text, span),
            Token::DtdStart {
                name,
                external_id,
                span,
            } => self.doctype_start(name, external_id, span, decoded),
            Token::EmptyDtd {
                name,
                external_id,
                span,
            } => self.doctype_empty(name, external_id, span),
            Token::EntityDeclaration {
                name,
                definition,
                span,
            } => self.entity_declaration(name, definition, span),
            Token::DtdEnd { span } => self.dtd_end(span, decoded),
            Token::ElementStart {
                prefix,
                local,
                span,
            } => self.element_start(prefix, local, span),
            Token::Attribute {
                prefix,
                local,
                value,
                span,
            } => self.attribute(prefix, local, value, span, decoded),
            Token::ElementEnd { end, span } => self.element_end(end, span),
            Token::Text { text } => self.text(text),
            Token::Cdata { text, span } => self.cdata(text, span),
        }
    }

    fn declaration(
        &mut self,
        version: StrSpan<'_>,
        encoding: Option<StrSpan<'_>>,
        standalone: Option<bool>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let declaration_open = self
            .raw_span_offset(span.start(), span.start() + 5)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(
            declaration_open,
            XmlSyntaxKind::DeclarationOpen,
            StructuralPieceKind::Token,
        );
        let standalone_facts = self.declaration_parts(span, version, encoding, standalone)?;
        if version.as_str() != "1.0" {
            self.recover(
                "xml.declaration.version@1",
                self.raw_span(version)?,
                DiagnosticCategory::Syntax,
            );
        }
        let encoding_facts = match encoding {
            Some(encoding_span) => {
                let encoding_raw = self.raw_span(encoding_span)?;
                let upper = encoding_span.as_str().to_ascii_uppercase();
                let selected = self.source.encoding_facts().selected();
                let agrees = match selected {
                    SourceEncoding::Utf8 => upper == "UTF-8",
                    SourceEncoding::Utf16Le => matches!(upper.as_str(), "UTF-16" | "UTF-16LE"),
                    SourceEncoding::Utf16Be => matches!(upper.as_str(), "UTF-16" | "UTF-16BE"),
                    _ => false,
                };
                if !agrees {
                    self.recover(
                        "xml.declaration.conflict@1",
                        encoding_raw,
                        DiagnosticCategory::Encoding,
                    );
                }
                Some((encoding_raw, Arc::from(encoding_span.as_str())))
            }
            None => None,
        };
        let declared = XmlDeclarationData {
            span: raw,
            version_span: self.raw_span(version)?,
            version: Arc::from(version.as_str()),
            encoding: encoding_facts,
            standalone: standalone_facts,
        };
        if self.declaration.is_some() {
            self.recover(
                "xml.declaration.duplicate@1",
                raw,
                DiagnosticCategory::Syntax,
            );
        }
        self.declaration = Some(declared);
        Ok(())
    }

    /// Pushes declaration part pieces and locates the standalone value span.
    ///
    /// The declaration grammar is fixed (`<?xml` S version Eq value
    /// (S encoding Eq value)? (S standalone Eq value)? S? `?>`), so the walk
    /// below is deterministic in decoded space; the tokenizer already proved
    /// the grammar. `=`/quote/space bytes between parts remain gaps and are
    /// covered as trivia by the final piece assembly.
    ///
    /// The scan cursor is relative to the declaration span; every raw-offset
    /// conversion adds `span.start()` back. The decoded text retains a
    /// leading BOM as U+FEFF (which xmlparser skips inside its stream), so
    /// the declaration span does not start at decoded byte 0 and a cursor
    /// based on `span.start()` would silently miss every name/value part.
    fn declaration_parts(
        &mut self,
        span: StrSpan<'_>,
        version: StrSpan<'_>,
        encoding: Option<StrSpan<'_>>,
        standalone: Option<bool>,
    ) -> Result<Option<(Span, bool)>, FatalFormationFailure> {
        let text = span.as_str();
        let mut cursor = 5; // past `<?xml`, relative to the declaration span
        let mut push_name_value = |name: &str,
                                   name_start: usize,
                                   value: StrSpan<'_>|
         -> Result<(), FatalFormationFailure> {
            if let Some(name_raw) = self.raw_span_offset(
                span.start() + name_start,
                span.start() + name_start + name.len(),
            )? {
                self.push_piece(
                    name_raw,
                    XmlSyntaxKind::DeclarationName,
                    StructuralPieceKind::Token,
                );
            }
            let value_raw = self.raw_span(value)?;
            self.push_piece(
                value_raw,
                XmlSyntaxKind::DeclarationValue,
                StructuralPieceKind::Token,
            );
            Ok(())
        };
        cursor = skip_declaration_spaces(text, cursor);
        if text[cursor..].starts_with("version") {
            push_name_value("version", cursor, version)?;
            cursor = version.end() - span.start() + 1; // past the closing quote
        }
        if let Some(encoding) = encoding {
            cursor = skip_declaration_spaces(text, cursor);
            if text[cursor..].starts_with("encoding") {
                push_name_value("encoding", cursor, encoding)?;
                cursor = encoding.end() - span.start() + 1;
            }
        }
        cursor = skip_declaration_spaces(text, cursor);
        let standalone_facts = if text[cursor..].starts_with("standalone") {
            if let Some(name_raw) = self.raw_span_offset(
                span.start() + cursor,
                span.start() + cursor + "standalone".len(),
            )? {
                self.push_piece(
                    name_raw,
                    XmlSyntaxKind::DeclarationName,
                    StructuralPieceKind::Token,
                );
            }
            let rest = &text[cursor + "standalone".len()..];
            let Some(eq) = rest.find('=').map(|at| cursor + "standalone".len() + at) else {
                return Ok(None);
            };
            let value_start = skip_declaration_spaces(text, eq + 1);
            let quote = text.as_bytes().get(value_start).copied();
            let Some(quote) = quote.filter(|b| *b == b'"' || *b == b'\'') else {
                return Ok(None);
            };
            let value_end = text[value_start + 1..]
                .find(quote as char)
                .map(|at| value_start + 1 + at);
            let Some(value_end) = value_end else {
                return Ok(None);
            };
            let value_span = self
                .raw_span_offset(span.start() + value_start + 1, span.start() + value_end)?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            self.push_piece(
                value_span,
                XmlSyntaxKind::DeclarationValue,
                StructuralPieceKind::Token,
            );
            Some((value_span, standalone.unwrap_or(false)))
        } else {
            None
        };
        if text.ends_with("?>") {
            if let Some(close) = self.raw_span_offset(span.end() - 2, span.end())? {
                self.push_piece(
                    close,
                    XmlSyntaxKind::DeclarationClose,
                    StructuralPieceKind::Token,
                );
            }
        }
        Ok(standalone_facts)
    }

    fn processing_instruction(
        &mut self,
        target: StrSpan<'_>,
        content: Option<StrSpan<'_>>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let target_raw = self.raw_span(target)?;
        if target.as_str().eq_ignore_ascii_case("xml") {
            self.recover("xml.pi.target@1", target_raw, DiagnosticCategory::Syntax);
        }
        let content_facts = match content {
            Some(value) => {
                let value_raw = self.raw_span(value)?;
                Self::limit(
                    "xml.limit.pi@1",
                    value.as_str().len(),
                    self.limits.max_pi_length,
                )?;
                Some((value_raw, Arc::from(value.as_str())))
            }
            None => None,
        };
        if self.dtd_subset_start.is_some() {
            // A PI inside the internal subset is admitted DTD markup, never a
            // prolog/epilog or element-content occurrence.
            self.push_piece(raw, XmlSyntaxKind::DtdMarkup, StructuralPieceKind::Token);
            return Ok(());
        }
        let open = self
            .raw_span_offset(span.start(), span.start() + 2)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(
            open,
            XmlSyntaxKind::ProcessingInstructionOpen,
            StructuralPieceKind::Token,
        );
        self.push_piece(
            target_raw,
            XmlSyntaxKind::ProcessingInstructionTarget,
            StructuralPieceKind::Token,
        );
        if let Some((content_raw, _)) = &content_facts {
            self.push_piece(
                *content_raw,
                XmlSyntaxKind::ProcessingInstructionContent,
                StructuralPieceKind::Token,
            );
        }
        let close = self
            .raw_span_offset(span.end().saturating_sub(2), span.end())?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(
            close,
            XmlSyntaxKind::ProcessingInstructionClose,
            StructuralPieceKind::Token,
        );
        let item = XmlPiData {
            ordinal: self.ordinal(),
            span: raw,
            target_span: target_raw,
            target: Arc::from(target.as_str()),
            content: content_facts,
        };
        if self.stack.is_empty() {
            if self.root.is_none() {
                self.prolog.push(XmlPrologItem::ProcessingInstruction(item));
            } else {
                self.epilog.push(XmlPrologItem::ProcessingInstruction(item));
            }
        } else {
            self.push_content(XmlContent::ProcessingInstruction(item));
        }
        Ok(())
    }

    fn comment(
        &mut self,
        text: StrSpan<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let value = text.as_str();
        if value.contains("--") || value.ends_with('-') {
            self.recover(
                "xml.comment.content@1",
                self.raw_span(text)?,
                DiagnosticCategory::Syntax,
            );
        }
        Self::limit(
            "xml.limit.comment@1",
            value.len(),
            self.limits.max_comment_length,
        )?;
        if self.dtd_subset_start.is_some() {
            // A comment inside the internal subset is admitted DTD markup,
            // never a prolog/epilog or element-content occurrence.
            self.push_piece(raw, XmlSyntaxKind::DtdMarkup, StructuralPieceKind::Trivia);
            return Ok(());
        }
        let open = self
            .raw_span_offset(span.start(), span.start() + 4)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(
            open,
            XmlSyntaxKind::CommentOpen,
            StructuralPieceKind::Trivia,
        );
        let text_raw = self.raw_span(text)?;
        self.push_piece(
            text_raw,
            XmlSyntaxKind::CommentText,
            StructuralPieceKind::Trivia,
        );
        let close = self
            .raw_span_offset(text.end(), span.end())?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(
            close,
            XmlSyntaxKind::CommentClose,
            StructuralPieceKind::Trivia,
        );
        let item = XmlCommentData {
            ordinal: self.ordinal(),
            span: raw,
            text_span: text_raw,
            text: Arc::from(value),
        };
        if self.stack.is_empty() {
            if self.root.is_none() {
                self.prolog.push(XmlPrologItem::Comment(item));
            } else {
                self.epilog.push(XmlPrologItem::Comment(item));
            }
        } else {
            self.push_content(XmlContent::Comment(item));
        }
        Ok(())
    }

    fn doctype_start(
        &mut self,
        name: StrSpan<'_>,
        external_id: Option<ExternalId<'_>>,
        span: StrSpan<'_>,
        _decoded: &str,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        self.push_doctype_open(raw)?;
        self.doctype_common(name, raw)?;
        if external_id.is_some() {
            self.external_subset_recovered = true;
            self.recover(
                "xml.dtd.external-subset@1",
                raw,
                DiagnosticCategory::Conformance,
            );
        }
        self.doctype_span_start = Some(raw.start_byte());
        self.dtd_subset_start = Some(span.end());
        Ok(())
    }

    fn doctype_empty(
        &mut self,
        name: StrSpan<'_>,
        external_id: Option<ExternalId<'_>>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        self.push_doctype_open(raw)?;
        self.doctype_common(name, raw)?;
        if external_id.is_some() {
            self.external_subset_recovered = true;
            self.recover(
                "xml.dtd.external-subset@1",
                raw,
                DiagnosticCategory::Conformance,
            );
        }
        self.doctype_span_start = Some(raw.start_byte());
        self.build_doctype(raw)?;
        Ok(())
    }

    /// Assembles the immutable DOCTYPE facts once its end is known.
    fn build_doctype(&mut self, end: Span) -> Result<(), FatalFormationFailure> {
        let start = self
            .doctype_span_start
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        let span = self.span(start, end.end_byte())?;
        let name = self
            .doctype_name
            .clone()
            .ok_or_else(|| profile_failure("xml.dtd.name@1"))?;
        // Clone: the declarations must stay live for reference resolution
        // inside the document element after the DTD closes.
        let entities = self.entities.clone();
        self.doctype = Some(XmlDoctypeData {
            span,
            name,
            entities: Arc::from(entities),
            recovered: self.external_subset_recovered,
        });
        Ok(())
    }

    /// Pushes the `<!DOCTYPE` opening piece for a DTD start span.
    fn push_doctype_open(&mut self, raw: Span) -> Result<(), FatalFormationFailure> {
        let open = self.span(raw.start_byte(), raw.start_byte() + 9)?;
        self.push_piece(open, XmlSyntaxKind::DoctypeOpen, StructuralPieceKind::Token);
        Ok(())
    }

    fn doctype_common(
        &mut self,
        name: StrSpan<'_>,
        raw: Span,
    ) -> Result<(), FatalFormationFailure> {
        if self.doctype.is_some() {
            self.recover(
                "xml.dtd.multiple-doctype@1",
                raw,
                DiagnosticCategory::Syntax,
            );
        }
        let qname = self.qname_facts(name)?;
        Self::limit(
            "xml.limit.qname@1",
            qname.span.len(),
            self.limits.max_qname_length,
        )?;
        self.push_piece(
            qname.span,
            XmlSyntaxKind::DoctypeName,
            StructuralPieceKind::Token,
        );
        self.doctype_name = Some(qname);
        Ok(())
    }

    fn entity_declaration(
        &mut self,
        name: StrSpan<'_>,
        definition: EntityDefinition<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        self.push_piece(raw, XmlSyntaxKind::DtdMarkup, StructuralPieceKind::Token);
        let text = span.as_str();
        // A parameter entity declaration is spelled `<!ENTITY % name ...`.
        let is_parameter = text.as_bytes().get(8..).is_some_and(|rest| {
            rest.iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace())
                == Some(b'%')
        });
        if is_parameter {
            self.recover(
                "xml.dtd.parameter-entity@1",
                raw,
                DiagnosticCategory::Conformance,
            );
            return Ok(());
        }
        let declared_name = Arc::from(name.as_str());
        match definition {
            EntityDefinition::ExternalId(_) => {
                self.recover(
                    "xml.dtd.external-entity@1",
                    raw,
                    DiagnosticCategory::Conformance,
                );
            }
            EntityDefinition::EntityValue(value) => {
                let value_text = value.as_str();
                Self::limit(
                    "xml.limit.entity-replacement@1",
                    value_text.len(),
                    self.limits.max_attribute_value_length,
                )?;
                match validate_replacement_text(value_text) {
                    Err(crate::entity::ReplacementError::ContainsMarkup) => {
                        self.recover("xml.entity.markup@1", raw, DiagnosticCategory::Conformance);
                        return Ok(());
                    }
                    Err(crate::entity::ReplacementError::IllegalCharacter { .. }) => {
                        self.recover(
                            "xml.entity.illegal-character@1",
                            raw,
                            DiagnosticCategory::Syntax,
                        );
                        return Ok(());
                    }
                    Ok(()) => {}
                }
                if value_text.contains('%') {
                    // A `%` inside an entity value is a parameter-entity
                    // reference, which the Profile excludes.
                    self.recover(
                        "xml.dtd.parameter-entity@1",
                        raw,
                        DiagnosticCategory::Conformance,
                    );
                    return Ok(());
                }
                if predefined_value(&declared_name).is_some()
                    || declared_name.as_ref() == "xml"
                    || declared_name.as_ref() == "xmlns"
                {
                    self.recover(
                        "xml.entity.reserved-name@1",
                        raw,
                        DiagnosticCategory::Conformance,
                    );
                    return Ok(());
                }
                if self
                    .entities
                    .iter()
                    .any(|entity| entity.name == declared_name)
                {
                    self.recover("xml.entity.duplicate@1", raw, DiagnosticCategory::Syntax);
                    return Ok(());
                }
                let declared = EntityDeclarationData {
                    span: raw,
                    name: Arc::clone(&declared_name),
                    replacement_span: self.raw_span(value)?,
                    replacement: Arc::from(value_text),
                };
                if let Err(breach) = self.entity_state.record_declaration(
                    value_text.len(),
                    value_text.chars().count(),
                    self.limits.entity_limits(),
                ) {
                    self.entity_limit(breach, raw);
                    return Ok(());
                }
                self.entities.push(declared);
            }
        }
        Ok(())
    }

    fn dtd_end(&mut self, span: StrSpan<'_>, decoded: &str) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        self.push_piece(raw, XmlSyntaxKind::DoctypeClose, StructuralPieceKind::Token);
        if let Some(start) = self.dtd_subset_start {
            let end = span.start();
            let subset = &decoded[start..end];
            self.scan_excluded_dtd_markup(subset)?;
            Self::limit("xml.limit.dtd@1", subset.len(), self.limits.max_dtd_bytes)?;
            self.dtd_subset_start = None;
        }
        self.build_doctype(raw)?;
        Ok(())
    }

    /// Scans the internal subset raw text for excluded declarations.
    ///
    /// Comments are skipped as a whole: their text is character data, so
    /// `<!-- <!ELEMENT x> -->` must not be misread as a declaration.
    fn scan_excluded_dtd_markup(&mut self, subset: &str) -> Result<(), FatalFormationFailure> {
        const MARKERS: [&str; 4] = ["<!ELEMENT", "<!ATTLIST", "<!NOTATION", "<!["];
        let mut search = subset;
        let mut base = 0usize;
        loop {
            let comment_at = search.find("<!--");
            let marker = MARKERS
                .iter()
                .filter_map(|marker| search.find(marker).map(|at| (at, *marker)))
                .min_by_key(|(at, _)| *at);
            let (at, marker) = match (comment_at, marker) {
                (Some(comment_at), Some((marker_at, _marker))) if comment_at < marker_at => {
                    let Some(relative_end) = search[comment_at + 4..].find("-->") else {
                        // An unterminated comment is already a tokenizer
                        // recovery case; nothing further to scan.
                        return Ok(());
                    };
                    let skip = comment_at + 4 + relative_end + 3;
                    base += skip;
                    search = &search[skip..];
                    continue;
                }
                (_, None) => return Ok(()),
                (_, Some((marker_at, marker))) => (marker_at, marker),
            };
            let absolute = base + at;
            let span = self
                .raw_span_offset(absolute, absolute + marker.len())?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            self.recover(
                if marker == "<![" {
                    "xml.dtd.conditional-section@1"
                } else {
                    "xml.dtd.validation-declaration@1"
                },
                span,
                DiagnosticCategory::Conformance,
            );
            let next = at + marker.len();
            base += next;
            search = &search[next..];
        }
    }

    fn element_start(
        &mut self,
        prefix: StrSpan<'_>,
        local: StrSpan<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let tag_open = self
            .raw_span_offset(span.start(), span.start() + 1)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(tag_open, XmlSyntaxKind::TagOpen, StructuralPieceKind::Token);
        self.push_qname_parts(prefix, local)?;
        let qname = self.qname_facts_pair(prefix, local)?;
        Self::limit(
            "xml.limit.qname@1",
            qname.span.len(),
            self.limits.max_qname_length,
        )?;
        if self.nodes.len() >= self.limits.common.max_node_count {
            return Err(profile_failure("xml.limit.node@1"));
        }
        if self.nodes.len() >= self.limits.max_element_count {
            return Err(profile_failure("xml.limit.element@1"));
        }
        if self.stack.len() >= self.limits.common.max_nesting_depth {
            return Err(profile_failure("xml.limit.depth@1"));
        }
        // Element-name resolution is deferred to start-tag finalization so
        // that declarations on this very element are in scope (Namespaces 1.0
        // applies declarations to the whole element regardless of order).
        let scope = self
            .stack
            .last()
            .map_or_else(NamespaceScope::new, |frame| frame.scope.clone());
        self.stack.push(Frame {
            start: raw.start_byte(),
            span: raw,
            qname,
            expanded: None,
            namespace_error: None,
            scope,
            namespaces: Vec::new(),
            attributes: Vec::new(),
            children: Vec::new(),
            pending_declarations: Vec::new(),
            pending_attributes: Vec::new(),
        });
        Ok(())
    }

    fn attribute(
        &mut self,
        prefix: StrSpan<'_>,
        local: StrSpan<'_>,
        value: StrSpan<'_>,
        span: StrSpan<'_>,
        decoded: &str,
    ) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let Some(frame) = self.stack.last_mut() else {
            return Err(profile_failure("xml.syntax.attribute-outside-element@1"));
        };
        let declaration_count = frame.pending_declarations.len() + frame.namespaces.len();
        let attribute_count = frame.pending_attributes.len() + frame.attributes.len();
        if attribute_count >= self.limits.max_attribute_count
            || declaration_count >= self.limits.max_namespace_declaration_count
        {
            return Err(profile_failure("xml.limit.attribute@1"));
        }
        let qname = self.qname_facts_pair(prefix, local)?;
        let is_declaration = qname.prefix.as_deref() == Some("xmlns")
            || (qname.prefix.is_none() && qname.local.as_ref() == "xmlns");
        // The attribute name is one unit; `xmlns`/`xmlns:p` names are the
        // NamespaceDeclaration kind. QName part pieces are used on element
        // and end-tag names, not here.
        if is_declaration {
            self.push_piece(
                qname.span,
                XmlSyntaxKind::NamespaceDeclaration,
                StructuralPieceKind::Token,
            );
        } else {
            self.push_piece(
                qname.span,
                XmlSyntaxKind::AttributeName,
                StructuralPieceKind::Token,
            );
        }
        // `=` and the two quote characters are decoded-space offsets; the raw
        // span conversion keeps UTF-16 sources exact.
        let eq_relative = decoded[local.end()..value.start()]
            .find('=')
            .map(|at| local.end() + at);
        if let Some(eq) = eq_relative {
            let raw_eq = self
                .raw_span_offset(eq, eq + 1)?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            self.push_piece(raw_eq, XmlSyntaxKind::Equals, StructuralPieceKind::Token);
        }
        let quote_start = value.start().saturating_sub(1);
        let open_quote = self
            .raw_span_offset(quote_start, quote_start + 1)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(open_quote, XmlSyntaxKind::Quote, StructuralPieceKind::Token);
        // The opening quote is decoded text right before the value span, so
        // single-quote detection is correct for UTF-8 and UTF-16 alike.
        let single_quote = decoded.as_bytes().get(quote_start) == Some(&b'\'');
        let close_quote = self
            .raw_span_offset(value.end(), value.end() + 1)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        let value_raw = self.raw_span(value)?;
        let (fragments, normalized) = self.value_fragments(value)?;
        self.push_piece(
            close_quote,
            XmlSyntaxKind::Quote,
            StructuralPieceKind::Token,
        );
        // The stack cannot have been popped while a start tag is open; the
        // top binding proved the frame exists and the same binding serves
        // both the limit check and the final push.
        let Some(frame) = self.stack.last_mut() else {
            return Err(profile_failure("xml.syntax.attribute-outside-element@1"));
        };
        if is_declaration {
            Self::limit(
                "xml.limit.namespace-uri@1",
                normalized.len(),
                self.limits.max_namespace_uri_length,
            )?;
            frame.pending_declarations.push(PendingDeclaration {
                qname,
                uri: Arc::from(normalized),
                uri_span: value_raw,
            });
            return Ok(());
        }
        Self::limit(
            "xml.limit.attribute-value@1",
            normalized.len(),
            self.limits.max_attribute_value_length,
        )?;
        frame.pending_attributes.push(PendingAttribute {
            qname,
            span: raw,
            value_span: value_raw,
            fragments: Arc::from(fragments),
            normalized: Arc::from(normalized),
            single_quote,
        });
        Ok(())
    }

    /// Resolves element and attribute names once the whole start tag has
    /// been read, so declarations on this element apply to every attribute.
    fn finalize_start_tag(&mut self) {
        let (pending_declarations, pending_attributes) = match self.stack.last_mut() {
            Some(frame) => (
                std::mem::take(&mut frame.pending_declarations),
                std::mem::take(&mut frame.pending_attributes),
            ),
            None => return,
        };
        let mut scope = self
            .stack
            .last()
            .map_or_else(NamespaceScope::new, |frame| frame.scope.clone());
        let mut namespaces = Vec::new();
        for declaration in pending_declarations {
            let prefix = if declaration.qname.prefix.as_deref() == Some("xmlns") {
                Some(Arc::clone(&declaration.qname.local))
            } else {
                None
            };
            match scope.declare(prefix.clone(), Arc::clone(&declaration.uri)) {
                Ok(child_scope) => {
                    scope = child_scope;
                    let binding = XmlNamespaceBindingData {
                        ordinal: self.ordinal(),
                        span: declaration.qname.span,
                        prefix,
                        uri_span: declaration.uri_span,
                        uri: declaration.uri,
                    };
                    namespaces.push(binding);
                }
                Err(error) => {
                    self.recover(
                        namespace_code(&error),
                        declaration.qname.span,
                        DiagnosticCategory::Semantic,
                    );
                }
            }
        }
        let Some(element_qname) = self.stack.last().map(|frame| frame.qname.clone()) else {
            return;
        };
        let (expanded, namespace_error) = match scope.resolve_element(&element_qname.qname()) {
            Ok(expanded) => (Some(expanded), None),
            Err(error) => (None, Some(error)),
        };
        if let Some(error) = &namespace_error {
            self.recover(
                namespace_code(error),
                element_qname.span,
                DiagnosticCategory::Semantic,
            );
        }
        let mut attributes = Vec::new();
        for pending in pending_attributes {
            let (expanded, namespace_error) = match scope.resolve_attribute(&pending.qname.qname())
            {
                Ok(expanded) => (Some(expanded), None),
                Err(error) => {
                    self.recover(
                        namespace_code(&error),
                        pending.qname.span,
                        DiagnosticCategory::Semantic,
                    );
                    (None, Some(error))
                }
            };
            let mut duplicate = false;
            if let Some(expanded) = expanded.as_ref() {
                duplicate = attributes
                    .iter()
                    .filter_map(|attribute: &XmlAttributeData| attribute.expanded.as_ref())
                    .any(|existing| existing == expanded)
                    || namespaces.iter().any(|binding| {
                        NamespaceScope::declaration_expanded_name(binding.prefix.as_deref())
                            == *expanded
                    });
            }
            if duplicate {
                self.recover(
                    "xml.namespace.duplicate-attribute@1",
                    pending.qname.span,
                    DiagnosticCategory::Semantic,
                );
            }
            let attribute = XmlAttributeData {
                ordinal: self.ordinal(),
                span: pending.span,
                qname: pending.qname,
                expanded,
                namespace_error,
                single_quote: pending.single_quote,
                value_span: pending.value_span,
                fragments: pending.fragments,
                normalized_value: pending.normalized,
            };
            attributes.push(attribute);
        }
        let Some(frame) = self.stack.last_mut() else {
            return;
        };
        frame.scope = scope;
        frame.namespaces.extend(namespaces);
        frame.expanded = expanded;
        frame.namespace_error = namespace_error;
        frame.attributes.extend(attributes);
    }

    fn element_end(
        &mut self,
        end: xmlparser::ElementEnd<'_>,
        span: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        match end {
            xmlparser::ElementEnd::Open => {
                let raw = self.raw_span(span)?;
                self.push_piece(raw, XmlSyntaxKind::TagClose, StructuralPieceKind::Token);
                self.finalize_start_tag();
                let extended = self
                    .stack
                    .last()
                    .map(|frame| self.span(frame.start, raw.end_byte()))
                    .transpose()?;
                if let (Some(frame), Some(extended)) = (self.stack.last_mut(), extended) {
                    frame.span = extended;
                }
                Ok(())
            }
            xmlparser::ElementEnd::Empty => {
                let raw = self.raw_span(span)?;
                self.push_piece(
                    raw,
                    XmlSyntaxKind::EmptyElementClose,
                    StructuralPieceKind::Token,
                );
                let extended = self
                    .stack
                    .last()
                    .map(|frame| self.span(frame.start, raw.end_byte()))
                    .transpose()?;
                if let (Some(frame), Some(extended)) = (self.stack.last_mut(), extended) {
                    frame.span = extended;
                }
                self.finalize_start_tag();
                self.close_frame(raw);
                Ok(())
            }
            xmlparser::ElementEnd::Close(prefix, local) => {
                let raw = self.raw_span(span)?;
                let end_open = self
                    .raw_span_offset(span.start(), span.start() + 2)?
                    .ok_or_else(|| profile_failure("xml.source.span@1"))?;
                self.push_piece(
                    end_open,
                    XmlSyntaxKind::EndTagOpen,
                    StructuralPieceKind::Token,
                );
                self.push_qname_parts(prefix, local)?;
                let tag_close = self
                    .raw_span_offset(span.end().saturating_sub(1), span.end())?
                    .ok_or_else(|| profile_failure("xml.source.span@1"))?;
                self.push_piece(
                    tag_close,
                    XmlSyntaxKind::TagClose,
                    StructuralPieceKind::Token,
                );
                let end_qname = self.qname_facts_pair(prefix, local)?;
                if let Some(frame) = self.stack.last() {
                    if frame.qname.qname() != end_qname.qname() {
                        self.recover(
                            "xml.tree.mismatched-end-tag@1",
                            end_qname.span,
                            DiagnosticCategory::Syntax,
                        );
                    }
                }
                self.close_frame(raw);
                Ok(())
            }
        }
    }

    fn close_frame(&mut self, end_tag_span: Span) {
        let Some(frame) = self.stack.pop() else {
            // An extra end tag cannot close any proven element; it is a
            // recovery case at a deterministic markup boundary. Recovery
            // always publishes a diagnostic so no content vanishes silently.
            self.recover(
                "xml.tree.extra-end-tag@1",
                end_tag_span,
                DiagnosticCategory::Syntax,
            );
            return;
        };
        let index = self.nodes.len();
        let element = XmlElementData {
            index,
            span: frame.span,
            qname: frame.qname,
            expanded: frame.expanded,
            namespace_error: frame.namespace_error,
            scope: frame.scope,
            namespaces: frame.namespaces,
            attributes: frame.attributes,
            children: frame.children,
        };
        // Every child content item attached to this element now knows its
        // parent arena index. The table mirrors the previous linear-scan
        // semantics: one owner per index, and the root element or content
        // dropped by a mixed-content budget stay `None`.
        for &child in &element.children {
            self.parent_of[child] = Some(index);
        }
        self.parent_of.push(None);
        self.nodes.push(XmlContent::Element(element));
        if let Some(parent) = self.stack.last_mut() {
            if parent.children.len() >= self.limits.max_mixed_content_items {
                // Child elements respect the same hard mixed-content budget
                // as text/CDATA/comment/PI; dropping publishes a diagnostic
                // and never passes silently.
                self.recover(
                    "xml.limit.mixed-content@1",
                    self.nodes[index].span(),
                    DiagnosticCategory::Conformance,
                );
            } else {
                parent.children.push(index);
            }
        } else if self.root.is_none() {
            self.root = Some(index);
        } else {
            self.recover(
                "xml.tree.multiple-roots@1",
                self.nodes[index].span(),
                DiagnosticCategory::Syntax,
            );
        }
    }

    fn text(&mut self, text: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(text)?;
        let value = text.as_str();
        let whitespace_only = value.chars().all(|c| c.is_ascii_whitespace());
        if self.stack.is_empty() {
            if whitespace_only {
                self.push_whitespace_pieces(text)?;
                let item = XmlPrologItem::Whitespace(raw);
                if self.root.is_none() {
                    self.prolog.push(item);
                } else {
                    self.epilog.push(item);
                }
                return Ok(());
            }
            // Non-whitespace character data outside the document element is
            // recovered; the piece is an error region and the literal text is
            // still preserved as an orphan text occurrence.
            self.recover(
                "xml.syntax.text-outside-root@1",
                raw,
                DiagnosticCategory::Syntax,
            );
            self.push_piece(
                raw,
                XmlSyntaxKind::ErrorRegion,
                StructuralPieceKind::ErrorRegion,
            );
            let ordinal = self.ordinal();
            self.push_content(XmlContent::Text(XmlTextData {
                ordinal,
                span: raw,
                fragments: Arc::from([ReferenceFragment::Literal {
                    span: raw,
                    text: Arc::from(value),
                }]),
            }));
            return Ok(());
        }
        if whitespace_only {
            self.push_whitespace_pieces(text)?;
        } else {
            let fragments = self.text_fragments(text, XmlSyntaxKind::Text)?;
            Self::limit("xml.limit.text@1", value.len(), self.limits.max_text_length)?;
            let item = XmlTextData {
                ordinal: self.ordinal(),
                span: raw,
                fragments: Arc::from(fragments),
            };
            self.push_content(XmlContent::Text(item));
            return Ok(());
        }
        let item = XmlTextData {
            ordinal: self.ordinal(),
            span: raw,
            fragments: Arc::from([ReferenceFragment::Literal {
                span: raw,
                text: Arc::from(value),
            }]),
        };
        self.push_content(XmlContent::Text(item));
        Ok(())
    }

    fn cdata(&mut self, text: StrSpan<'_>, span: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let raw = self.raw_span(span)?;
        let open = self
            .raw_span_offset(span.start(), span.start() + 9)?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(open, XmlSyntaxKind::CdataOpen, StructuralPieceKind::Token);
        let text_raw = self.raw_span(text)?;
        self.push_piece(
            text_raw,
            XmlSyntaxKind::CdataText,
            StructuralPieceKind::Token,
        );
        let close = self
            .raw_span_offset(text.end(), span.end())?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        self.push_piece(close, XmlSyntaxKind::CdataClose, StructuralPieceKind::Token);
        let value = text.as_str();
        Self::limit(
            "xml.limit.cdata@1",
            value.len(),
            self.limits.max_cdata_length,
        )?;
        let item = XmlCdataData {
            ordinal: self.ordinal(),
            span: raw,
            text_span: text_raw,
            text: Arc::from(value),
        };
        self.push_content(XmlContent::Cdata(item));
        Ok(())
    }

    fn push_content(&mut self, item: XmlContent) {
        if let Some(frame) = self.stack.last_mut() {
            if frame.children.len() >= self.limits.max_mixed_content_items {
                // The item is dropped under the hard budget, never silently:
                // recovery always publishes a diagnostic and the source bytes
                // stay covered by their structural piece.
                self.recover(
                    "xml.limit.mixed-content@1",
                    item.span(),
                    DiagnosticCategory::Conformance,
                );
                return;
            }
            frame.children.push(self.nodes.len());
        }
        // The parent table stays index-parallel with the node arena; the
        // owning element fills the entry when it closes.
        self.parent_of.push(None);
        self.nodes.push(item);
    }

    /// Splits one whitespace-only text run into Whitespace and LineBreak
    /// pieces; CRLF counts as one line break.
    fn push_whitespace_pieces(&mut self, text: StrSpan<'_>) -> Result<(), FatalFormationFailure> {
        let bytes = text.as_str().as_bytes();
        let mut index = 0usize;
        while index < bytes.len() {
            let line_break = matches!(bytes[index], b'\n' | b'\r');
            let run_start = index;
            index += if line_break {
                if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                }
            } else {
                1
            };
            while index < bytes.len() && matches!(bytes[index], b'\n' | b'\r') == line_break {
                index += 1;
            }
            let span = self
                .raw_span_offset(text.start() + run_start, text.start() + index)?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            self.push_piece(
                span,
                if line_break {
                    XmlSyntaxKind::LineBreak
                } else {
                    XmlSyntaxKind::Whitespace
                },
                StructuralPieceKind::Trivia,
            );
        }
        Ok(())
    }

    /// Splits one text or attribute-value occurrence into reference fragments.
    ///
    /// Each literal emits a `literal_kind` piece (Text in character data,
    /// AttributeValue in attribute values) and each admitted reference emits
    /// its own EntityReference/CharacterReference piece. Failing references
    /// recover with a diagnostic and emit no piece; their spans become
    /// error-region gaps in the final assembly.
    fn text_fragments(
        &mut self,
        text: StrSpan<'_>,
        literal_kind: XmlSyntaxKind,
    ) -> Result<Vec<ReferenceFragment>, FatalFormationFailure> {
        let bytes = text.as_str();
        if !bytes.contains('&') {
            // Fast path: a single literal covers the whole run; the piece
            // and fragment are identical to the tail logic below.
            let span = self
                .raw_span_offset(text.start(), text.end())?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            self.push_piece(span, literal_kind, StructuralPieceKind::Token);
            return Ok(vec![ReferenceFragment::Literal {
                span,
                text: Arc::from(bytes),
            }]);
        }
        let mut fragments = Vec::new();
        let mut cursor = 0usize;
        let mut index = 0usize;
        while index < bytes.len() {
            let Some(relative) = bytes[index..].find('&') else {
                break;
            };
            let at = index + relative;
            if at > cursor {
                let literal = &bytes[cursor..at];
                let span = self
                    .raw_span_offset(text.start() + cursor, text.start() + at)?
                    .ok_or_else(|| profile_failure("xml.source.span@1"))?;
                self.push_piece(span, literal_kind, StructuralPieceKind::Token);
                fragments.push(ReferenceFragment::Literal {
                    span,
                    text: Arc::from(literal),
                });
            }
            let semi = bytes[at + 1..].find(';').map(|semi| at + 1 + semi);
            let Some(semi) = semi else {
                // Unterminated reference: recover and keep the rest literal.
                let span = self
                    .raw_span_offset(text.start() + at, text.end())?
                    .ok_or_else(|| profile_failure("xml.source.span@1"))?;
                self.recover(
                    "xml.reference.malformed@1",
                    span,
                    DiagnosticCategory::Syntax,
                );
                self.push_piece(span, literal_kind, StructuralPieceKind::Token);
                fragments.push(ReferenceFragment::Literal {
                    span,
                    text: Arc::from(&bytes[at..]),
                });
                cursor = bytes.len();
                index = bytes.len();
                continue;
            };
            let body = &bytes[at + 1..semi];
            let ref_span = self
                .raw_span_offset(text.start() + at, text.start() + semi + 1)?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            if let Some(fragment) = self.resolve_reference(body, ref_span, 0) {
                let kind = match fragment {
                    ReferenceFragment::CharacterReference { .. } => {
                        XmlSyntaxKind::CharacterReference
                    }
                    ReferenceFragment::PredefinedEntity { .. }
                    | ReferenceFragment::GeneralEntity { .. } => XmlSyntaxKind::EntityReference,
                    ReferenceFragment::Literal { .. } => literal_kind,
                };
                self.push_piece(ref_span, kind, StructuralPieceKind::Token);
                fragments.push(fragment);
            }
            cursor = semi + 1;
            index = semi + 1;
        }
        if cursor < bytes.len() {
            let literal = &bytes[cursor..];
            let span = self
                .raw_span_offset(text.start() + cursor, text.end())?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            self.push_piece(span, literal_kind, StructuralPieceKind::Token);
            fragments.push(ReferenceFragment::Literal {
                span,
                text: Arc::from(literal),
            });
        }
        Ok(fragments)
    }

    /// Resolves one `&…;` reference body into a fragment.
    fn resolve_reference(
        &mut self,
        body: &str,
        ref_span: Span,
        depth: usize,
    ) -> Option<ReferenceFragment> {
        if let Some(digits) = body.strip_prefix('#') {
            let (is_hex, value) = if let Some(hex) = digits
                .strip_prefix('x')
                .or_else(|| digits.strip_prefix('X'))
            {
                (
                    !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()),
                    u32::from_str_radix(hex, 16).ok(),
                )
            } else {
                (
                    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()),
                    digits.parse::<u32>().ok(),
                )
            };
            let resolved = if is_hex {
                value.and_then(char::from_u32)
            } else {
                None
            }
            .filter(|c| is_xml_char(*c));
            if let Some(resolved) = resolved {
                Some(ReferenceFragment::CharacterReference {
                    span: ref_span,
                    resolved,
                })
            } else {
                self.recover(
                    "xml.reference.invalid-character@1",
                    ref_span,
                    DiagnosticCategory::Syntax,
                );
                None
            }
        } else if let Some(value) = predefined_value(body) {
            Some(ReferenceFragment::PredefinedEntity {
                span: ref_span,
                name: Arc::from(body),
                resolved: Arc::from(value),
            })
        } else {
            let Some(declared) = self
                .entities
                .iter()
                .find(|entity| entity.name.as_ref() == body)
                .cloned()
            else {
                self.recover(
                    "xml.entity.unknown@1",
                    ref_span,
                    DiagnosticCategory::Conformance,
                );
                return None;
            };
            let limits = self.limits.entity_limits();
            if let Err(breach) = self.entity_state.enter_reference(
                declared.replacement.len(),
                declared.replacement.chars().count(),
                limits,
            ) {
                self.entity_limit(breach, ref_span);
                return None;
            }
            let nested = self.resolve_nested(&declared.replacement, ref_span, depth + 1);
            self.entity_state.leave_reference();
            if let Ok(resolved) = nested {
                Some(ReferenceFragment::GeneralEntity {
                    span: ref_span,
                    name: Arc::from(body),
                    resolved: Arc::from(resolved),
                    declaration_span: declared.span,
                })
            } else {
                self.recover(
                    "xml.entity.cyclic@1",
                    ref_span,
                    DiagnosticCategory::Conformance,
                );
                None
            }
        }
    }

    /// Resolves nested references inside one replacement text.
    ///
    /// Unknown references, cycles, or limit breaches inside replacement text
    /// produce no partial native text; the outer reference is rejected.
    fn resolve_nested(
        &mut self,
        replacement: &str,
        source_span: Span,
        depth: usize,
    ) -> Result<String, ()> {
        if depth > self.limits.max_entity_expansion_depth {
            return Err(());
        }
        let mut out = String::new();
        let mut cursor = 0usize;
        let mut index = 0usize;
        while index < replacement.len() {
            let Some(relative) = replacement[index..].find('&') else {
                break;
            };
            let at = index + relative;
            out.push_str(&replacement[cursor..at]);
            let Some(semi) = replacement[at + 1..].find(';').map(|semi| at + 1 + semi) else {
                return Err(());
            };
            let body = &replacement[at + 1..semi];
            let fragment = self.resolve_reference(body, source_span, depth);
            match fragment {
                Some(ReferenceFragment::CharacterReference { resolved, .. }) => {
                    out.push(resolved);
                }
                Some(
                    ReferenceFragment::PredefinedEntity { resolved, .. }
                    | ReferenceFragment::GeneralEntity { resolved, .. },
                ) => {
                    out.push_str(&resolved);
                }
                Some(ReferenceFragment::Literal { text, .. }) => out.push_str(&text),
                None => return Err(()),
            }
            cursor = semi + 1;
            index = semi + 1;
        }
        out.push_str(&replacement[cursor..]);
        Ok(out)
    }

    /// Splits an attribute value into fragments and applies XML 1.0 CDATA
    /// normalization to the semantic value.
    fn value_fragments(
        &mut self,
        value: StrSpan<'_>,
    ) -> Result<(Vec<ReferenceFragment>, String), FatalFormationFailure> {
        let fragments = self.text_fragments(value, XmlSyntaxKind::AttributeValue)?;
        let mut normalized = String::new();
        for fragment in &fragments {
            match fragment {
                ReferenceFragment::Literal { text, .. } => {
                    for c in text.chars() {
                        normalized.push(if c == '\t' || c == '\n' || c == '\r' || c == ' ' {
                            ' '
                        } else {
                            c
                        });
                    }
                }
                ReferenceFragment::CharacterReference { resolved, .. } => {
                    normalized.push(*resolved);
                }
                ReferenceFragment::PredefinedEntity { resolved, .. }
                | ReferenceFragment::GeneralEntity { resolved, .. } => {
                    for c in resolved.chars() {
                        normalized.push(if c == '\t' || c == '\n' || c == '\r' || c == ' ' {
                            ' '
                        } else {
                            c
                        });
                    }
                }
            }
        }
        Ok((fragments, normalized))
    }

    /// Records a recovery diagnostic with its exact failing span.
    ///
    /// The failing span lies inside token-covered bytes, so it is not pushed
    /// as an additional structural piece (pieces must stay non-overlapping);
    /// the diagnostic location carries the error region fact.
    fn recover(&mut self, code: &'static str, span: Span, category: DiagnosticCategory) {
        self.recovered = true;
        if self.error_regions >= self.limits.max_recovery_regions {
            return;
        }
        self.error_regions += 1;
        self.diagnostics.push(Diagnostic::new(
            code,
            category,
            DiagnosticSeverity::Error,
            Some(span.diagnostic_location()),
            self.diagnostics.len() as u64,
        ));
    }

    fn entity_limit(&mut self, breach: ExpansionBreach, span: Span) {
        let code = match breach {
            ExpansionBreach::Amplification => "xml.entity.amplification@1",
            _ => "xml.entity.limit@1",
        };
        self.recover(code, span, DiagnosticCategory::Conformance);
    }

    fn recover_error_region(
        &mut self,
        start: usize,
        end: usize,
        _decoded: &str,
    ) -> Result<(), FatalFormationFailure> {
        self.recovered = true;
        if self.error_regions >= self.limits.max_recovery_regions {
            return Ok(());
        }
        self.error_regions += 1;
        let raw_start = self.raw_offset(start)?;
        let raw_end = self.raw_offset(end)?;
        let span = self.span(raw_start, raw_end)?;
        self.push_piece(
            span,
            XmlSyntaxKind::ErrorRegion,
            StructuralPieceKind::ErrorRegion,
        );
        self.diagnostics.push(Diagnostic::new(
            "xml.syntax.well-formedness@1",
            DiagnosticCategory::Syntax,
            DiagnosticSeverity::Error,
            Some(span.diagnostic_location()),
            self.diagnostics.len() as u64,
        ));
        Ok(())
    }

    fn find_next_markup(decoded: &str, from: usize) -> Option<usize> {
        decoded[from..].find('<').map(|at| from + at)
    }

    fn finish(mut self) -> Result<Document, FatalFormationFailure> {
        if !self.stack.is_empty() {
            self.recovered = true;
            self.diagnostics.push(Diagnostic::new(
                "xml.tree.unclosed-element@1",
                DiagnosticCategory::Syntax,
                DiagnosticSeverity::Error,
                None,
                self.diagnostics.len() as u64,
            ));
        }
        if self.root.is_none() {
            self.recovered = true;
            self.diagnostics.push(Diagnostic::new(
                "xml.tree.missing-root@1",
                DiagnosticCategory::Syntax,
                DiagnosticSeverity::Error,
                None,
                self.diagnostics.len() as u64,
            ));
        }
        if let (Some(root), Some(doctype_name)) = (self.root, self.doctype_name.as_ref()) {
            let XmlContent::Element(root_data) = &self.nodes[root] else {
                return Err(profile_failure("xml.tree.root@1"));
            };
            if root_data.qname.qname() != doctype_name.qname() {
                self.recover(
                    "xml.doctype.root-mismatch@1",
                    root_data.qname.span,
                    DiagnosticCategory::Syntax,
                );
            }
        }
        let status = if self.recovered {
            FormationStatus::Recovered
        } else {
            FormationStatus::Complete
        };
        let source_len = self.source.len();
        // Pair every piece with its kind before any ordering, so sorting can
        // never desynchronize the two parallel arrays.
        let mut paired: Vec<(StructuralPiece, XmlSyntaxKind)> = std::mem::take(&mut self.pieces)
            .into_iter()
            .zip(std::mem::take(&mut self.syntax_kinds))
            .collect();
        paired.sort_by_key(|(piece, _)| piece.span().start_byte());
        let mut final_pieces = Vec::with_capacity(paired.len() + 8);
        let mut final_kinds = Vec::with_capacity(paired.len() + 8);
        let mut next = 0usize;
        for (piece, kind) in paired {
            let start = piece.span().start_byte();
            if start > next {
                let gap = self.span(next, start)?;
                // In a Complete document the tokenizer only skips whitespace;
                // in a Recovered document the gap is unproven content.
                if self.recovered {
                    self.push_piece(
                        gap,
                        XmlSyntaxKind::ErrorRegion,
                        StructuralPieceKind::ErrorRegion,
                    );
                } else {
                    self.push_piece(gap, XmlSyntaxKind::Whitespace, StructuralPieceKind::Trivia);
                }
            }
            next = piece.span().end_byte();
            final_pieces.push(piece);
            final_kinds.push(kind);
        }
        if next < source_len {
            let gap = self.span(next, source_len)?;
            if self.recovered {
                self.push_piece(
                    gap,
                    XmlSyntaxKind::ErrorRegion,
                    StructuralPieceKind::ErrorRegion,
                );
            } else {
                self.push_piece(gap, XmlSyntaxKind::Whitespace, StructuralPieceKind::Trivia);
            }
        }
        // Gap pieces were pushed in increasing offset order; append them to
        // the final arrays, then pair and sort the complete set once for
        // deterministic output with kinds never desynchronized from pieces.
        for (piece, kind) in std::mem::take(&mut self.pieces)
            .into_iter()
            .zip(std::mem::take(&mut self.syntax_kinds))
        {
            final_pieces.push(piece);
            final_kinds.push(kind);
        }
        let mut paired: Vec<(StructuralPiece, XmlSyntaxKind)> =
            final_pieces.into_iter().zip(final_kinds).collect();
        paired.sort_by_key(|(piece, _)| piece.span().start_byte());
        let mut structural = Vec::with_capacity(paired.len());
        let mut paired_kinds = Vec::with_capacity(paired.len());
        for (piece, kind) in &paired {
            structural.push(*piece);
            paired_kinds.push(*kind);
        }
        let index = LosslessStructuralIndex::new(self.authority.identity(), source_len, structural)
            .map_err(|_| profile_failure("xml.source.coverage@1"))?;
        let mut diagnostics = std::mem::take(&mut self.diagnostics);
        Diagnostic::sort_deterministically(&mut diagnostics);
        Ok(Document::from_formed(
            self.authority,
            crate::document::Formed {
                source: Arc::clone(&self.source),
                status,
                declaration: self.declaration,
                doctype: self.doctype,
                prolog: std::mem::take(&mut self.prolog),
                root: self.root,
                epilog: std::mem::take(&mut self.epilog),
                syntax: Some(index),
                syntax_kinds: paired_kinds,
                diagnostics,
                nodes: std::mem::take(&mut self.nodes),
                parent_of: std::mem::take(&mut self.parent_of),
                parse_limits: self.limits,
            },
        ))
    }

    fn qname_facts(&self, span: StrSpan<'_>) -> Result<QNameFacts, FatalFormationFailure> {
        let text = span.as_str();
        let raw = self.raw_span(span)?;
        let Some(colon) = text.find(':') else {
            return Ok(QNameFacts {
                prefix: None,
                local: Arc::from(text),
                span: raw,
                prefix_span: None,
                local_span: raw,
            });
        };
        let (prefix, local) = text.split_at(colon);
        let local = &local[1..];
        Ok(QNameFacts {
            prefix: Some(Arc::from(prefix)),
            local: Arc::from(local),
            span: raw,
            prefix_span: Some(
                self.raw_span_offset(span.start(), span.start() + colon)?
                    .ok_or_else(|| profile_failure("xml.source.span@1"))?,
            ),
            local_span: self
                .raw_span_offset(span.start() + colon + 1, span.end())?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?,
        })
    }

    /// Pushes the QName part pieces for one element or end-tag name.
    fn push_qname_parts(
        &mut self,
        prefix: StrSpan<'_>,
        local: StrSpan<'_>,
    ) -> Result<(), FatalFormationFailure> {
        if prefix.is_empty() {
            let local_raw = self.raw_span(local)?;
            self.push_piece(
                local_raw,
                XmlSyntaxKind::LocalName,
                StructuralPieceKind::Token,
            );
        } else {
            let prefix_raw = self.raw_span(prefix)?;
            let colon = self
                .raw_span_offset(prefix.end(), local.start())?
                .ok_or_else(|| profile_failure("xml.source.span@1"))?;
            let local_raw = self.raw_span(local)?;
            self.push_piece(
                prefix_raw,
                XmlSyntaxKind::Prefix,
                StructuralPieceKind::Token,
            );
            self.push_piece(colon, XmlSyntaxKind::Colon, StructuralPieceKind::Token);
            self.push_piece(
                local_raw,
                XmlSyntaxKind::LocalName,
                StructuralPieceKind::Token,
            );
        }
        Ok(())
    }

    fn qname_facts_pair(
        &self,
        prefix: StrSpan<'_>,
        local: StrSpan<'_>,
    ) -> Result<QNameFacts, FatalFormationFailure> {
        let has_prefix = !prefix.is_empty();
        let start = if has_prefix {
            prefix.start()
        } else {
            local.start()
        };
        let span = self
            .raw_span_offset(start, local.end())?
            .ok_or_else(|| profile_failure("xml.source.span@1"))?;
        Ok(QNameFacts {
            prefix: if has_prefix {
                Some(Arc::from(prefix.as_str()))
            } else {
                None
            },
            local: Arc::from(local.as_str()),
            span,
            prefix_span: if has_prefix {
                Some(self.raw_span(prefix)?)
            } else {
                None
            },
            local_span: self.raw_span(local)?,
        })
    }

    fn ordinal(&mut self) -> u64 {
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        ordinal
    }

    fn limit(code: &'static str, value: usize, max: usize) -> Result<(), FatalFormationFailure> {
        if value > max {
            return Err(profile_failure(code));
        }
        Ok(())
    }

    fn raw_span(&self, span: StrSpan<'_>) -> Result<Span, FatalFormationFailure> {
        self.raw_span_offset(span.start(), span.end())?
            .ok_or_else(|| profile_failure("xml.source.span@1"))
    }

    /// Converts one decoded UTF-8 byte offset to a raw source byte offset.
    ///
    /// A UTF-8 source is stored by `SourceSnapshot` byte-identical to its
    /// decoded text (`DecodedStorage::RawUtf8` keeps the raw bytes as the
    /// decoded text, BOM included), so decoded offsets are raw offsets and
    /// the conversion is the identity. Other encodings transcode at
    /// construction and must resolve through the source's checkpoint index.
    ///
    /// The fast path matters for formation cost: `raw_byte_at` re-validates
    /// the entire source on every call (an O(source-length) `from_utf8`
    /// pass), and the parser performs one span conversion per structural
    /// piece — Θ(pieces) lookups × O(source) validation is the O(n²)
    /// formation shape measured in task #53 (per-lookup cost grew exactly
    /// with source size and consumed ~99% of parse time at 20,000 elements).
    /// Every offset this parser resolves is a tokenizer span or a boundary
    /// derived from ASCII structural markup (`<`, `>`, `=`, quotes, `&`, `;`,
    /// `:`), so the boundary validation in `raw_byte_at` can never fire for
    /// UTF-8 sources and the identity shortcut is behavior-preserving.
    fn raw_offset(&self, decoded: usize) -> Result<usize, FatalFormationFailure> {
        if self.source.encoding_facts().selected() == SourceEncoding::Utf8 {
            return Ok(decoded);
        }
        self.source
            .raw_byte_at(DecodedOffset::Utf8Byte(decoded))
            .map_err(|_| profile_failure("xml.source.span@1"))
    }

    fn raw_span_offset(
        &self,
        start: usize,
        end: usize,
    ) -> Result<Option<Span>, FatalFormationFailure> {
        let start_raw = self.raw_offset(start)?;
        let end_raw = self.raw_offset(end)?;
        Ok(Some(self.span(start_raw, end_raw)?))
    }

    fn span(&self, start: usize, end: usize) -> Result<Span, FatalFormationFailure> {
        self.authority
            .span(start, end)
            .map_err(|_| profile_failure("xml.source.span@1"))
    }

    fn push_piece(&mut self, span: Span, kind: XmlSyntaxKind, structural: StructuralPieceKind) {
        self.pieces.push(StructuralPiece::new(span, structural));
        self.syntax_kinds.push(kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::text_semantic;
    use crate::{XmlEncodingSelection, XmlParseLimits, XmlProfile};
    use consema_document::{FormationStatus, SourceEncoding};

    fn parse_utf8(source: &[u8]) -> Result<Document, FatalFormationFailure> {
        parse(
            Arc::from(source),
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
    }

    fn root(document: &Document) -> &XmlElementData {
        let XmlContent::Element(data) =
            &document.nodes()[document.root().expect("root").data().index]
        else {
            panic!("root is an element");
        };
        data
    }

    #[test]
    fn well_formed_document_is_complete_and_byte_exact() {
        let source = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<service name=\"catalog\">\n  <port>8080</port>\n</service>\n";
        let document = parse_utf8(source).expect("well-formed XML forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.render(), source);
        assert!(document.diagnostics().is_empty());
        let root = root(&document);
        assert_eq!(root.qname.local.as_ref(), "service");
        assert_eq!(root.expanded.as_ref().expect("resolved").namespace, None);
        assert_eq!(root.attributes.len(), 1);
        assert_eq!(root.attributes[0].normalized_value.as_ref(), "catalog");
        let port = root
            .children
            .iter()
            .copied()
            .find(|&index| matches!(document.nodes()[index], XmlContent::Element(_)))
            .expect("port element child");
        let XmlContent::Element(port_data) = &document.nodes()[port] else {
            panic!("child is element");
        };
        let XmlContent::Text(text_data) = &document.nodes()[port_data.children[0]] else {
            panic!("grandchild is text");
        };
        assert_eq!(text_semantic(text_data), "8080");
    }

    #[test]
    fn default_namespace_applies_to_elements_only() {
        let source = br#"<root xmlns="urn:app" version="1"><child/></root>"#;
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        let root = root(&document);
        assert_eq!(
            root.expanded
                .as_ref()
                .expect("resolved")
                .namespace
                .as_deref(),
            Some("urn:app")
        );
        assert_eq!(root.attributes.len(), 1);
        assert_eq!(
            root.attributes[0]
                .expanded
                .as_ref()
                .expect("resolved")
                .namespace,
            None,
            "unprefixed attributes never get the default namespace"
        );
        let XmlContent::Element(child) = &document.nodes()[root.children[0]] else {
            panic!("child is element");
        };
        assert_eq!(
            child
                .expanded
                .as_ref()
                .expect("resolved")
                .namespace
                .as_deref(),
            Some("urn:app"),
            "default namespace is inherited by elements"
        );
    }

    #[test]
    fn prefixed_names_resolve_through_bindings() {
        let source =
            br#"<p:root xmlns:p="urn:one"><p:child xmlns:q="urn:two" q:attr="x"/></p:root>"#;
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        let root = root(&document);
        assert_eq!(
            root.expanded
                .as_ref()
                .expect("resolved")
                .namespace
                .as_deref(),
            Some("urn:one")
        );
        let XmlContent::Element(child) = &document.nodes()[root.children[0]] else {
            panic!("child is element");
        };
        assert_eq!(
            child
                .expanded
                .as_ref()
                .expect("resolved")
                .namespace
                .as_deref(),
            Some("urn:one"),
            "parent bindings stay in scope"
        );
        let attribute = &child.attributes[0];
        assert_eq!(
            attribute
                .expanded
                .as_ref()
                .expect("resolved")
                .namespace
                .as_deref(),
            Some("urn:two")
        );
    }

    #[test]
    fn unbound_prefix_is_recovered_not_fatal() {
        let source = br"<p:root/>";
        let document = parse_utf8(source).expect("recovered document forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.namespace.unbound-prefix@1")
        );
        assert_eq!(document.render(), source);
    }

    #[test]
    fn duplicate_expanded_attributes_are_recovered() {
        let source = br#"<root xmlns:p="urn:u" xmlns:q="urn:u" p:a="1" q:a="2"/>"#;
        let document = parse_utf8(source).expect("recovered document forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.namespace.duplicate-attribute@1")
        );
    }

    #[test]
    fn predefined_and_character_references_resolve() {
        let source = br"<root>a &lt; b &amp; c &#x41; &#65;</root>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        let root = root(&document);
        let XmlContent::Text(text_data) = &document.nodes()[root.children[0]] else {
            panic!("child is text");
        };
        assert_eq!(text_semantic(text_data), "a < b & c A A");
        assert_eq!(
            text_data.fragments.len(),
            8,
            "two literals and six references"
        );
    }

    #[test]
    fn internal_entities_expand_with_provenance() {
        let source = br#"<!DOCTYPE root [<!ENTITY greeting "hello &name;"><!ENTITY name "world">]>
<root>&greeting;</root>"#;
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        let root = root(&document);
        let XmlContent::Text(text_data) = &document.nodes()[root.children[0]] else {
            panic!("child is text");
        };
        assert_eq!(text_semantic(text_data), "hello world");
        let ReferenceFragment::GeneralEntity {
            name,
            declaration_span,
            ..
        } = &text_data.fragments[0]
        else {
            panic!("general entity fragment");
        };
        assert_eq!(name.as_ref(), "greeting");
        assert!(!declaration_span.is_empty());
    }

    #[test]
    fn external_and_parameter_entities_are_rejected_as_recovered() {
        let external = br#"<!DOCTYPE root SYSTEM "http://evil.example/x.dtd"><root/>"#;
        let document = parse_utf8(external).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.dtd.external-subset@1")
        );

        let parameter = br#"<!DOCTYPE root [<!ENTITY % p "x">]><root/>"#;
        let document = parse_utf8(parameter).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.dtd.parameter-entity@1")
        );

        let external_entity =
            br#"<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///etc/passwd">]><root/&ext;>"#;
        let document = parse_utf8(external_entity).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.dtd.external-entity@1")
        );
    }

    #[test]
    fn unknown_entity_is_recovered_with_no_partial_text() {
        let source = br"<root>before &unknown; after</root>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.entity.unknown@1")
        );
        let root = root(&document);
        let XmlContent::Text(text_data) = &document.nodes()[root.children[0]] else {
            panic!("child is text");
        };
        let semantic = text_semantic(text_data);
        assert_eq!(
            semantic, "before  after",
            "unknown reference resolves to nothing"
        );
    }

    // Entity amplification and expansion limits are covered by
    // crates/consema-conformance/tests/xml_hardening.rs
    // (`billion_laughs_variants_are_bounded_by_document_wide_accounting` and
    // `deep_reference_nesting_hits_the_depth_limit`), which keeps the
    // stronger billion-laughs and linear-amplification closure.

    #[test]
    fn mismatched_end_tag_is_recovered() {
        let source = br"<a><b></a>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(document.diagnostics().iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "xml.tree.mismatched-end-tag@1" | "xml.syntax.well-formedness@1"
            )
        }));
    }

    // UTF-16 BOM round-trip coverage (LE and BE, non-BMP content and names)
    // lives in crates/consema-conformance/tests/xml_encoding_corpus.rs
    // (`utf16le_and_be_bom_documents_round_trip`), which keeps the stronger
    // both-endianness version; this module only retains unit-level UTF-16
    // facts such as utf16_single_quoted_attribute_is_detected below.

    #[test]
    fn utf16_without_bom_is_rejected_by_profile() {
        let text = "<root/>";
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let result = parse(
            Arc::from(bytes),
            XmlProfile::SafeV1,
            XmlEncodingSelection::Explicit(SourceEncoding::Utf16Le),
            XmlParseLimits::default(),
        );
        assert!(
            result.is_err(),
            "UTF-16 without BOM must fail even with explicit endianness"
        );
    }

    #[test]
    fn mixed_content_keeps_source_order() {
        let source = br"<root>a<child/>b<![CDATA[c]]><!--d--><?pi e?>f</root>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        let root = root(&document);
        assert_eq!(root.children.len(), 7);
        let kinds: Vec<&str> = root
            .children
            .iter()
            .map(|&index| match &document.nodes()[index] {
                XmlContent::Element(_) => "element",
                XmlContent::Text(_) => "text",
                XmlContent::Cdata(_) => "cdata",
                XmlContent::Comment(_) => "comment",
                XmlContent::ProcessingInstruction(_) => "pi",
                XmlContent::ErrorRegion(_) => "error",
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["text", "element", "text", "cdata", "comment", "pi", "text"]
        );
    }

    #[test]
    fn missing_root_is_recovered() {
        let source = br#"<?xml version="1.0"?><!-- nothing -->"#;
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.tree.missing-root@1")
        );
    }

    #[test]
    fn piece_coverage_is_exhaustive() {
        let source = br#"<?xml version="1.0"?><root a="1">  <b/>text</root>"#;
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        let index = document.lossless_structural_index().expect("index");
        let pieces = index.pieces();
        assert_eq!(pieces.first().map(|p| p.span().start_byte()), Some(0));
        assert_eq!(
            pieces.last().map(|p| p.span().end_byte()),
            Some(source.len())
        );
        let mut next = 0;
        for piece in pieces {
            assert_eq!(piece.span().start_byte(), next, "no holes");
            next = piece.span().end_byte();
        }
        assert_eq!(next, source.len());
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            pieces.len(),
            "kinds parallel pieces"
        );
    }

    #[test]
    fn crlf_line_endings_are_preserved_raw_and_normalized_semantically() {
        let source = b"<root>line1\r\nline2</root>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.render(), source);
        let root = root(&document);
        let XmlContent::Text(text_data) = &document.nodes()[root.children[0]] else {
            panic!("child is text");
        };
        assert_eq!(text_semantic(text_data), "line1\nline2");
    }

    #[test]
    fn fine_grained_kinds_cover_every_document_part() {
        let source = br#"<?xml version="1.0" standalone="yes"?>
<!DOCTYPE p:root [<!ENTITY e "x"><!-- <!ELEMENT nope> --><?pi dtd?>]>
<p:root xmlns:p="urn:p" p:a="v &amp; w">t &lt; u &#65;<b/>
  <![CDATA[c]]><!--h--><?tail after?></p:root>"#;
        let document = parse_utf8(source).expect("forms");
        assert_eq!(
            document.status(),
            FormationStatus::Complete,
            "diagnostics: {:?}",
            document
                .diagnostics()
                .iter()
                .map(|diagnostic| &diagnostic.code)
                .collect::<Vec<_>>()
        );
        assert!(
            document.diagnostics().is_empty(),
            "no spurious recovery; diagnostics: {:?}",
            document
                .diagnostics()
                .iter()
                .map(|diagnostic| &diagnostic.code)
                .collect::<Vec<_>>()
        );
        let kinds: Vec<&str> = document
            .lossless_syntax_kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        for expected in [
            "declaration-open",
            "declaration-name",
            "declaration-value",
            "declaration-close",
            "doctype-open",
            "doctype-name",
            "dtd-markup",
            "doctype-close",
            "tag-open",
            "prefix",
            "colon",
            "local-name",
            "attribute-name",
            "equals",
            "quote",
            "attribute-value",
            "namespace-declaration",
            "text",
            "entity-reference",
            "character-reference",
            "cdata-open",
            "cdata-text",
            "cdata-close",
            "comment-open",
            "comment-text",
            "comment-close",
            "processing-instruction-open",
            "processing-instruction-target",
            "processing-instruction-content",
            "processing-instruction-close",
            "end-tag-open",
            "tag-close",
            "whitespace",
            "line-break",
        ] {
            assert!(
                kinds.contains(&expected),
                "kind {expected} never emitted; kinds: {kinds:?}"
            );
        }
        assert!(!kinds.contains(&"bom"), "no BOM in a BOM-less document");
        assert!(
            !kinds.contains(&"error-region"),
            "a Complete document has no error regions"
        );
    }

    #[test]
    fn element_span_covers_the_full_start_tag() {
        let source = br#"<root a="1">x</root>"#;
        let document = parse_utf8(source).expect("forms");
        let root = root(&document);
        assert_eq!(root.span.start_byte(), 0, "span starts at the opening <");
        // The start tag ends just past its first `>`; deriving the expected
        // end from the input keeps the assertion robust against edits.
        let start_tag_end = source
            .iter()
            .position(|byte| *byte == b'>')
            .expect("start tag contains >")
            + 1;
        assert_eq!(
            root.span.end_byte(),
            start_tag_end,
            "span ends after the start-tag >"
        );
    }

    #[test]
    fn end_tag_pieces_cover_open_name_and_close() {
        let source = br"<p:a>x</p:a>";
        let document = parse_utf8(source).expect("forms");
        let kinds: Vec<&str> = document
            .lossless_syntax_kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        let tail: Vec<&str> = kinds[kinds.len() - 5..].to_vec();
        assert_eq!(
            tail,
            vec!["end-tag-open", "prefix", "colon", "local-name", "tag-close"]
        );
    }

    #[test]
    fn utf16_single_quoted_attribute_is_detected() {
        let text = "<root a='x'/>";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let document = parse(
            Arc::from(bytes),
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
        .expect("UTF-16LE forms");
        let root = root(&document);
        assert_eq!(root.attributes.len(), 1);
        assert!(
            root.attributes[0].single_quote,
            "UTF-16 single-quoted attribute must be detected"
        );
    }

    #[test]
    fn extra_end_tag_publishes_a_diagnostic() {
        // The second `</a>` errors inside the tokenizer; the third is
        // re-tokenized as a fragment and reaches the empty element stack,
        // where the extra end tag must publish its own diagnostic.
        let source = br"<a></a></a></a>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document.diagnostics().iter().any(|diagnostic| {
                matches!(
                    diagnostic.code.as_str(),
                    "xml.tree.extra-end-tag@1" | "xml.syntax.well-formedness@1"
                )
            }),
            "extra end tag must not vanish silently"
        );
    }

    // The mixed-content item budget is covered by
    // crates/consema-conformance/tests/xml_hardening.rs
    // (`mixed_content_limit_publishes_diagnostics_for_every_drop`), which
    // asserts a diagnostic for every dropped item on a stronger input.

    #[test]
    fn dtd_comment_text_is_not_misread_as_excluded_markup() {
        let source = br"<!DOCTYPE root [<!-- <!ELEMENT not-a-decl> -->]><root/>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(
            document.status(),
            FormationStatus::Complete,
            "a comment mentioning <!ELEMENT inside the subset is still well-formed"
        );
        assert!(
            document.diagnostics().is_empty(),
            "no spurious validation-declaration recovery"
        );
        let kinds: Vec<&str> = document
            .lossless_syntax_kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        assert!(kinds.contains(&"dtd-markup"), "subset comment is DtdMarkup");
    }

    #[test]
    fn excluded_dtd_markup_outside_comments_is_recovered() {
        let source = br"<!DOCTYPE root [<!ELEMENT x EMPTY>]><root/>";
        let document = parse_utf8(source).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "xml.dtd.validation-declaration@1")
        );
    }

    /// Asserts that the four declaration pieces cover exactly the expected
    /// decoded text. The mapping goes through `decoded_position` so the check
    /// holds for UTF-8 and UTF-16 sources alike (raw bytes of a UTF-16 piece
    /// are not themselves UTF-8 text).
    fn assert_declaration_piece_bytes(document: &Document, expected: &[(&str, &str)]) {
        let decoded = document
            .source()
            .decoded_text()
            .expect("decoded text exists");
        let kinds = document.lossless_syntax_kinds();
        let index = document
            .lossless_structural_index()
            .expect("structural index");
        let mut expected: Vec<(&str, &str)> = expected.to_vec();
        for (kind, piece) in kinds.iter().zip(index.pieces()) {
            let Some((_, wanted)) = expected.iter().find(|(name, _)| *name == kind.as_str()) else {
                continue;
            };
            let start = document
                .source()
                .decoded_position(piece.span().start_byte())
                .expect("piece start is a decoded boundary")
                .decoded_utf8_byte;
            let end = document
                .source()
                .decoded_position(piece.span().end_byte())
                .expect("piece end is a decoded boundary")
                .decoded_utf8_byte;
            let text = &decoded[start..end];
            assert_eq!(
                text,
                *wanted,
                "{} piece covers [{}, {}) in raw bytes",
                kind.as_str(),
                piece.span().start_byte(),
                piece.span().end_byte()
            );
            expected.retain(|(name, _)| *name != kind.as_str());
        }
        assert!(
            expected.is_empty(),
            "missing declaration pieces: {expected:?}"
        );
    }

    #[test]
    fn declaration_pieces_stay_byte_exact_with_utf8_bom() {
        let source = b"\xEF\xBB\xBF<?xml version=\"1.0\"?><root/>";
        let document = parse_utf8(source).expect("BOM document forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.render(), source);
        // Direct raw-byte check: with a UTF-8 BOM the raw slice of a piece
        // span is the piece's exact decoded text.
        let kinds = document.lossless_syntax_kinds();
        let index = document.lossless_structural_index().expect("index");
        let raw = document.render();
        let mut expected = std::collections::BTreeMap::<&str, &str>::new();
        expected.insert("bom", "\u{feff}");
        expected.insert("declaration-open", "<?xml");
        expected.insert("declaration-name", "version");
        expected.insert("declaration-value", "1.0");
        expected.insert("declaration-close", "?>");
        for (kind, piece) in kinds.iter().zip(index.pieces()) {
            let span = piece.span();
            let text = std::str::from_utf8(&raw[span.start_byte()..span.end_byte()])
                .expect("piece bytes are UTF-8");
            if let Some(wanted) = expected.get(kind.as_str()) {
                assert_eq!(
                    text,
                    *wanted,
                    "{} piece covers [{}, {})",
                    kind.as_str(),
                    span.start_byte(),
                    span.end_byte()
                );
                expected.remove(kind.as_str());
            }
        }
        assert!(expected.is_empty(), "missing pieces: {expected:?}");
    }

    #[test]
    fn declaration_pieces_stay_byte_exact_with_utf16_boms() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-16\" standalone=\"yes\"?><root/>";
        let mut le = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        let mut be = vec![0xFE, 0xFF];
        for unit in text.encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        for (bytes, label) in [(&le, "UTF-16LE"), (&be, "UTF-16BE")] {
            let document = parse(
                Arc::from(bytes.as_slice()),
                XmlProfile::SafeV1,
                XmlEncodingSelection::ProfileDefault,
                XmlParseLimits::default(),
            )
            .unwrap_or_else(|_| panic!("{label} BOM document forms"));
            assert_eq!(document.status(), FormationStatus::Complete, "{label}");
            assert_eq!(document.render(), bytes.as_slice(), "{label}");
            assert_declaration_piece_bytes(
                &document,
                &[
                    ("declaration-open", "<?xml"),
                    ("declaration-name", "version"),
                    ("declaration-value", "1.0"),
                    ("declaration-close", "?>"),
                ],
            );
        }
    }

    #[test]
    fn declaration_pieces_stay_byte_exact_with_utf16_bom_and_full_attributes() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-16\" standalone=\"yes\"?><root/>";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let document = parse(
            Arc::from(bytes.as_slice()),
            XmlProfile::SafeV1,
            XmlEncodingSelection::ProfileDefault,
            XmlParseLimits::default(),
        )
        .expect("UTF-16LE BOM document forms");
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(document.render(), bytes.as_slice());
        assert_declaration_piece_bytes(
            &document,
            &[("declaration-open", "<?xml"), ("declaration-close", "?>")],
        );
        // Every declaration pseudo-attribute name and value keeps its exact
        // span in declaration order.
        let decoded = document
            .source()
            .decoded_text()
            .expect("decoded text exists");
        let kinds = document.lossless_syntax_kinds();
        let index = document.lossless_structural_index().expect("index");
        let mut names = Vec::new();
        let mut values = Vec::new();
        for (kind, piece) in kinds.iter().zip(index.pieces()) {
            let start = document
                .source()
                .decoded_position(piece.span().start_byte())
                .expect("piece start is a decoded boundary")
                .decoded_utf8_byte;
            let end = document
                .source()
                .decoded_position(piece.span().end_byte())
                .expect("piece end is a decoded boundary")
                .decoded_utf8_byte;
            match kind.as_str() {
                "declaration-name" => names.push(&decoded[start..end]),
                "declaration-value" => values.push(&decoded[start..end]),
                _ => {}
            }
        }
        assert_eq!(names, ["version", "encoding", "standalone"]);
        assert_eq!(values, ["1.0", "UTF-16", "yes"]);
    }

    #[test]
    fn standalone_value_span_points_at_the_value() {
        let source = br#"<?xml version="1.0" standalone="yes"?><root/>"#;
        let document = parse_utf8(source).expect("forms");
        let declaration = document.declaration().expect("declaration");
        let (span, value) = declaration.standalone.expect("standalone");
        assert!(value, "yes is true");
        let source_text = std::str::from_utf8(document.render()).expect("utf-8");
        assert_eq!(
            &source_text[span.start_byte()..span.end_byte()],
            "yes",
            "standalone span covers exactly the value"
        );
    }

    #[test]
    fn whitespace_runs_split_into_whitespace_and_line_break_kinds() {
        let source = b"<root>\n  <a/>\r\n</root>";
        let document = parse_utf8(source).expect("forms");
        let kinds: Vec<&str> = document
            .lossless_syntax_kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        assert!(
            kinds
                .windows(2)
                .any(|pair| pair == ["line-break", "whitespace"]),
            "line break and space runs get distinct kinds: {kinds:?}"
        );
    }

    #[test]
    fn many_small_elements_formation_scales_linearly() {
        // Regression net for task #53: formation was quadratic because every
        // span conversion re-validated the whole UTF-8 source (one full
        // `from_utf8` pass per lookup, ~42 lookups per element, ~99% of
        // parse time at 20k elements). Measured pre-fix on this machine:
        // 5k elements ≈ 2.4 s, 10k ≈ 20-28 s, 20k ≈ 47-97 s. The parser
        // performs the same work post-fix in ~0.5-1.5 s at 20k (release).
        // The bound below is deliberately generous (10k elements, 20 s) so
        // debug-mode CI noise cannot flip it, while the pre-fix cost in
        // debug (several minutes) would fail it by a wide margin.
        let mut xml = Vec::with_capacity(10_000 * 48 + 16);
        xml.extend_from_slice(b"<root>\r\n");
        for i in 0..10_000 {
            xml.extend_from_slice(b"<item><name>n");
            xml.extend_from_slice(i.to_string().as_bytes());
            xml.extend_from_slice(b"</name><value>v");
            xml.extend_from_slice(i.to_string().as_bytes());
            xml.extend_from_slice(b"</value></item>\r\n");
        }
        xml.extend_from_slice(b"</root>\r\n");
        let start = std::time::Instant::now();
        let document = parse_utf8(&xml).expect("the many-small-elements corpus forms");
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 20,
            "10k-element formation must stay linear: took {elapsed:?}"
        );
        assert_eq!(document.status(), FormationStatus::Complete);
        assert_eq!(
            document.nodes().len(),
            60_002,
            "1 root + 3 elements and 2 text nodes per item + one whitespace \
             node per item and one after <root> (6 * 10_000 + 2)"
        );
        assert_eq!(document.render(), xml, "lossless render stays byte-exact");
    }
}
