use crate::{
    Document, ElementEntity, Entity, EntityKind, EntryEntity, InternalItemKind, ItemEntity,
    KeyEntity, TableFlavor, TomlDate, TomlDateTime, TomlOffset, TomlProfile, TomlSyntaxKind,
    TomlTime,
};
use consema_core::{
    BinaryFloat64, Diagnostic, DiagnosticCategory, DiagnosticLocation, DiagnosticSeverity,
};
use consema_document::{
    DocumentAuthority, FatalFormationFailure, LosslessStructuralIndex, ParseLimits, SourceSnapshot,
    StructuralPiece, StructuralPieceKind,
};
use std::ops::Range;
use std::sync::Arc;
use toml_edit::{Array, ArrayOfTables, ImDocument, InlineTable, Item, Table, Value};

pub(crate) fn parse(
    source_bytes: Arc<[u8]>,
    profile: TomlProfile,
    limits: ParseLimits,
) -> Result<Document, FatalFormationFailure> {
    if source_bytes.len() > limits.max_source_bytes {
        return Err(FatalFormationFailure::resource_limit(
            "source_bytes",
            source_bytes.len(),
            limits.max_source_bytes,
        ));
    }
    let source =
        SourceSnapshot::from_utf8(source_bytes).map_err(FatalFormationFailure::source_error)?;
    let authority = DocumentAuthority::fresh();
    let source_text = source
        .decoded_text()
        .expect("TOML parser constructs a UTF-8 source");
    let (pieces, syntax_kinds) = tokenize(source_text, &authority, limits.max_token_count)?;
    preflight_delimiter_nesting(source_text, &pieces, limits.max_nesting_depth)?;
    let structural_index = LosslessStructuralIndex::new(authority.identity(), source.len(), pieces)
        .expect("TOML tokenizer creates exact source coverage");
    let parsed = ImDocument::parse(source_text.to_owned()).map_err(syntax_failure)?;

    let (root, entities) = {
        let mut builder = EntityBuilder {
            authority: &authority,
            source_len: source.len(),
            limits,
            entities: Vec::new(),
        };
        let root = builder.build_table(parsed.as_table(), true, 0, Some(0..source.len()))?;
        (root, Arc::from(builder.entities))
    };

    Ok(Document {
        authority,
        source,
        profile,
        structural_index,
        syntax_kinds: Arc::from(syntax_kinds),
        diagnostics: Arc::from([]),
        entities,
        root,
        parse_limits: limits,
    })
}

fn syntax_failure(error: toml_edit::TomlError) -> FatalFormationFailure {
    let primary = error.span().map(|span| DiagnosticLocation {
        snapshot: None,
        start_byte: span.start as u64,
        end_byte: span.end as u64,
    });
    let mut diagnostic = Diagnostic::new(
        "toml.parse.syntax@1",
        DiagnosticCategory::Syntax,
        DiagnosticSeverity::Error,
        primary,
        0,
    );
    diagnostic
        .arguments
        .insert("parser_reason".to_owned(), error.message().to_owned());
    FatalFormationFailure::from_diagnostic(diagnostic)
}

struct EntityBuilder<'a> {
    authority: &'a DocumentAuthority,
    source_len: usize,
    limits: ParseLimits,
    entities: Vec<Entity>,
}

impl EntityBuilder<'_> {
    fn add(&mut self, entity: Entity) -> Result<usize, FatalFormationFailure> {
        let observed = self.entities.len().saturating_add(1);
        if observed > self.limits.max_node_count {
            return Err(FatalFormationFailure::resource_limit(
                "node_count",
                observed,
                self.limits.max_node_count,
            ));
        }
        let index = self.entities.len();
        self.entities.push(entity);
        Ok(index)
    }

    fn check_depth(&self, depth: usize) -> Result<(), FatalFormationFailure> {
        if depth > self.limits.max_nesting_depth {
            Err(FatalFormationFailure::resource_limit(
                "nesting_depth",
                depth,
                self.limits.max_nesting_depth,
            ))
        } else {
            Ok(())
        }
    }

    fn span(&self, range: Range<usize>) -> consema_document::Span {
        debug_assert!(range.start <= range.end && range.end <= self.source_len);
        self.authority
            .span(range.start, range.end)
            .expect("validated backend range")
    }

    fn build_item(
        &mut self,
        item: &Item,
        depth: usize,
        fallback: Range<usize>,
    ) -> Result<usize, FatalFormationFailure> {
        match item {
            Item::Value(value) => self.build_value(value, depth, fallback),
            Item::Table(table) => self.build_table(table, false, depth, Some(fallback)),
            Item::ArrayOfTables(array) => self.build_array_of_tables(array, depth, fallback),
            Item::None => unreachable!("parsed TOML never exposes placeholder items"),
        }
    }

    fn build_value(
        &mut self,
        value: &Value,
        depth: usize,
        fallback: Range<usize>,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_depth(depth)?;
        let range = value.span().unwrap_or(fallback);
        match value {
            Value::Array(array) => self.build_array(array, depth, range),
            Value::InlineTable(table) => self.build_inline_table(table, depth, range),
            Value::String(formatted) => self.add_item(
                range,
                InternalItemKind::String(Arc::from(formatted.value().as_str())),
            ),
            Value::Integer(formatted) => {
                self.add_item(range, InternalItemKind::Integer(*formatted.value()))
            }
            Value::Float(formatted) => self.add_item(
                range,
                InternalItemKind::Float(BinaryFloat64::from_bits(formatted.value().to_bits())),
            ),
            Value::Boolean(formatted) => {
                self.add_item(range, InternalItemKind::Boolean(*formatted.value()))
            }
            Value::Datetime(formatted) => self.add_item(
                range,
                InternalItemKind::DateTime(convert_datetime(*formatted.value())),
            ),
        }
    }

    fn add_item(
        &mut self,
        range: Range<usize>,
        kind: InternalItemKind,
    ) -> Result<usize, FatalFormationFailure> {
        self.add(Entity {
            span: self.span(range),
            kind: EntityKind::Item(ItemEntity { kind }),
        })
    }

    fn reserve_item(&mut self, range: Range<usize>) -> Result<usize, FatalFormationFailure> {
        self.add_item(range, InternalItemKind::Array(Vec::new()))
    }

    fn replace_item(&mut self, index: usize, kind: InternalItemKind) {
        self.entities[index].kind = EntityKind::Item(ItemEntity { kind });
    }

    fn build_table(
        &mut self,
        table: &Table,
        root: bool,
        depth: usize,
        fallback: Option<Range<usize>>,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_depth(depth)?;
        let table_range = if root {
            0..self.source_len
        } else {
            table.span().or(fallback.clone()).unwrap_or(0..0)
        };
        let item_index = self.reserve_item(table_range)?;
        let mut entries = Vec::new();
        for (ordinal, (name, item)) in table.iter().enumerate() {
            let key = table.key(name).expect("iterator key is addressable");
            let key_range = key
                .span()
                .or_else(|| item.span())
                .or_else(|| fallback.clone())
                .unwrap_or(0..0);
            let key_index = self.add(Entity {
                span: self.span(key_range.clone()),
                kind: EntityKind::Key(KeyEntity {
                    name: Arc::from(name),
                }),
            })?;
            let child_index = self.build_item(item, depth.saturating_add(1), key_range.clone())?;
            let child_span = self.entities[child_index].span;
            let entry_range = key_range.start.min(child_span.start_byte())
                ..key_range.end.max(child_span.end_byte());
            let entry_index = self.add(Entity {
                span: self.span(entry_range),
                kind: EntityKind::Entry(EntryEntity {
                    ordinal,
                    key: key_index,
                    item: child_index,
                }),
            })?;
            entries.push(entry_index);
        }
        let flavor = if root {
            TableFlavor::Root
        } else if table.is_dotted() {
            TableFlavor::Dotted
        } else if table.is_implicit() {
            TableFlavor::Implicit
        } else {
            TableFlavor::Standard
        };
        self.replace_item(item_index, InternalItemKind::Table { flavor, entries });
        Ok(item_index)
    }

    fn build_inline_table(
        &mut self,
        table: &InlineTable,
        depth: usize,
        range: Range<usize>,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_depth(depth)?;
        let item_index = self.reserve_item(range)?;
        let mut entries = Vec::new();
        for (ordinal, (name, value)) in table.iter().enumerate() {
            let key = table.key(name).expect("iterator key is addressable");
            let key_range = key.span().or_else(|| value.span()).unwrap_or(0..0);
            let key_index = self.add(Entity {
                span: self.span(key_range.clone()),
                kind: EntityKind::Key(KeyEntity {
                    name: Arc::from(name),
                }),
            })?;
            let child_index =
                self.build_value(value, depth.saturating_add(1), key_range.clone())?;
            let child_span = self.entities[child_index].span;
            let entry_range = key_range.start.min(child_span.start_byte())
                ..key_range.end.max(child_span.end_byte());
            let entry_index = self.add(Entity {
                span: self.span(entry_range),
                kind: EntityKind::Entry(EntryEntity {
                    ordinal,
                    key: key_index,
                    item: child_index,
                }),
            })?;
            entries.push(entry_index);
        }
        self.replace_item(item_index, InternalItemKind::InlineTable(entries));
        Ok(item_index)
    }

    fn build_array(
        &mut self,
        array: &Array,
        depth: usize,
        range: Range<usize>,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_depth(depth)?;
        let item_index = self.reserve_item(range)?;
        let mut elements = Vec::new();
        for (ordinal, value) in array.iter().enumerate() {
            let value_range = value.span().unwrap_or(0..0);
            let child_index =
                self.build_value(value, depth.saturating_add(1), value_range.clone())?;
            let element_index = self.add(Entity {
                span: self.span(value_range),
                kind: EntityKind::Element(ElementEntity {
                    ordinal,
                    item: child_index,
                }),
            })?;
            elements.push(element_index);
        }
        self.replace_item(item_index, InternalItemKind::Array(elements));
        Ok(item_index)
    }

    fn build_array_of_tables(
        &mut self,
        array: &ArrayOfTables,
        depth: usize,
        fallback: Range<usize>,
    ) -> Result<usize, FatalFormationFailure> {
        self.check_depth(depth)?;
        let range = array.span().unwrap_or(fallback);
        let item_index = self.reserve_item(range)?;
        let mut elements = Vec::new();
        for (ordinal, table) in array.iter().enumerate() {
            let table_range = table.span().unwrap_or(0..0);
            let child_index = self.build_table(
                table,
                false,
                depth.saturating_add(1),
                Some(table_range.clone()),
            )?;
            let element_index = self.add(Entity {
                span: self.span(table_range),
                kind: EntityKind::Element(ElementEntity {
                    ordinal,
                    item: child_index,
                }),
            })?;
            elements.push(element_index);
        }
        self.replace_item(item_index, InternalItemKind::ArrayOfTables(elements));
        Ok(item_index)
    }
}

fn convert_datetime(value: toml_edit::Datetime) -> TomlDateTime {
    TomlDateTime {
        date: value.date.map(|date| TomlDate {
            year: date.year,
            month: date.month,
            day: date.day,
        }),
        time: value.time.map(|time| TomlTime {
            hour: time.hour,
            minute: time.minute,
            second: time.second,
            nanosecond: time.nanosecond,
        }),
        offset: value.offset.map(|offset| match offset {
            toml_edit::Offset::Z => TomlOffset::Z,
            toml_edit::Offset::Custom { minutes } => TomlOffset::CustomMinutes(minutes),
        }),
    }
}

fn tokenize(
    source: &str,
    authority: &DocumentAuthority,
    max_count: usize,
) -> Result<(Vec<StructuralPiece>, Vec<TomlSyntaxKind>), FatalFormationFailure> {
    let bytes = source.as_bytes();
    let mut pieces = Vec::new();
    let mut syntax_kinds = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (end, kind, syntax_kind) = if matches!(bytes[cursor], b' ' | b'\t') {
            let mut end = cursor + 1;
            while end < bytes.len() && matches!(bytes[end], b' ' | b'\t') {
                end += 1;
            }
            (end, StructuralPieceKind::Trivia, TomlSyntaxKind::Whitespace)
        } else if matches!(bytes[cursor], b'\r' | b'\n') {
            let end = if bytes[cursor] == b'\r' && bytes.get(cursor + 1) == Some(&b'\n') {
                cursor + 2
            } else {
                cursor + 1
            };
            (end, StructuralPieceKind::Trivia, TomlSyntaxKind::Newline)
        } else if bytes[cursor] == b'#' {
            let mut end = cursor + 1;
            while end < bytes.len() && !matches!(bytes[end], b'\r' | b'\n') {
                end += 1;
            }
            (end, StructuralPieceKind::Trivia, TomlSyntaxKind::Comment)
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            (
                string_end(bytes, cursor),
                StructuralPieceKind::Token,
                TomlSyntaxKind::String,
            )
        } else if is_punctuation(bytes[cursor]) {
            (
                cursor + 1,
                StructuralPieceKind::Token,
                punctuation_kind(bytes[cursor]),
            )
        } else {
            let mut end = cursor + 1;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && bytes[end] != b'#'
                && !is_punctuation(bytes[end])
                && !matches!(bytes[end], b'\'' | b'"')
            {
                end += 1;
            }
            (end, StructuralPieceKind::Token, TomlSyntaxKind::Bare)
        };
        let observed = pieces.len().saturating_add(1);
        if observed > max_count {
            return Err(FatalFormationFailure::resource_limit(
                "token_count",
                observed,
                max_count,
            ));
        }
        pieces.push(StructuralPiece::new(
            authority
                .span(cursor, end)
                .expect("tokenizer produces ordered ranges"),
            kind,
        ));
        syntax_kinds.push(syntax_kind);
        cursor = end;
    }
    Ok((pieces, syntax_kinds))
}

fn preflight_delimiter_nesting(
    source: &str,
    pieces: &[StructuralPiece],
    max_depth: usize,
) -> Result<(), FatalFormationFailure> {
    let mut depth = 0usize;
    for piece in pieces {
        if piece.kind() != StructuralPieceKind::Token {
            continue;
        }
        let span = piece.span();
        let token = &source[span.start_byte()..span.end_byte()];
        match token {
            "[" | "{" => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return Err(FatalFormationFailure::resource_limit(
                        "nesting_depth",
                        depth,
                        max_depth,
                    ));
                }
            }
            "]" | "}" => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn is_punctuation(byte: u8) -> bool {
    matches!(byte, b'=' | b'[' | b']' | b'{' | b'}' | b',' | b'.')
}

fn punctuation_kind(byte: u8) -> TomlSyntaxKind {
    match byte {
        b'=' => TomlSyntaxKind::Equals,
        b'[' => TomlSyntaxKind::LeftBracket,
        b']' => TomlSyntaxKind::RightBracket,
        b'{' => TomlSyntaxKind::LeftBrace,
        b'}' => TomlSyntaxKind::RightBrace,
        b',' => TomlSyntaxKind::Comma,
        b'.' => TomlSyntaxKind::Dot,
        _ => unreachable!("caller filtered the byte before syntax-kind dispatch"),
    }
}

fn string_end(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let triple = bytes.get(start..start.saturating_add(3)) == Some(&[quote, quote, quote]);
    let mut cursor = start + if triple { 3 } else { 1 };
    while cursor < bytes.len() {
        if quote == b'"' && bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
            continue;
        }
        if triple {
            if bytes.get(cursor..cursor.saturating_add(3)) == Some(&[quote, quote, quote]) {
                return cursor + 3;
            }
        } else if bytes[cursor] == quote {
            return cursor + 1;
        }
        cursor += 1;
    }
    bytes.len()
}
