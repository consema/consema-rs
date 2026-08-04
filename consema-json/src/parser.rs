use crate::{
    Document, ElementEntity, Entity, InternalValueKind, JsonProfile, JsonSyntaxKind, MemberEntity,
    SemanticUnavailable, ValueEntity,
};
use consema_core::{BigInteger, Decimal, Diagnostic, DiagnosticCategory, DiagnosticSeverity};
use consema_document::{
    DocumentAuthority, FatalFormationFailure, FormationStatus, LosslessStructuralIndex,
    ParseLimits, SourceSnapshot, StructuralPiece, StructuralPieceKind,
};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Colon,
    Comma,
    String,
    Number,
    True,
    False,
    Null,
}

#[derive(Clone, Copy, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Debug)]
struct Lexeme {
    start: usize,
    end: usize,
    class: LexemeClass,
}

#[derive(Clone, Copy, Debug)]
enum LexemeClass {
    Token(TokenKind),
    Trivia(JsonSyntaxKind),
    Error,
}

impl LexemeClass {
    const fn syntax_kind(self) -> JsonSyntaxKind {
        match self {
            Self::Token(TokenKind::LeftBrace) => JsonSyntaxKind::LeftBrace,
            Self::Token(TokenKind::RightBrace) => JsonSyntaxKind::RightBrace,
            Self::Token(TokenKind::LeftBracket) => JsonSyntaxKind::LeftBracket,
            Self::Token(TokenKind::RightBracket) => JsonSyntaxKind::RightBracket,
            Self::Token(TokenKind::Colon) => JsonSyntaxKind::Colon,
            Self::Token(TokenKind::Comma) => JsonSyntaxKind::Comma,
            Self::Token(TokenKind::String) => JsonSyntaxKind::String,
            Self::Token(TokenKind::Number) => JsonSyntaxKind::Number,
            Self::Token(TokenKind::True) => JsonSyntaxKind::True,
            Self::Token(TokenKind::False) => JsonSyntaxKind::False,
            Self::Token(TokenKind::Null) => JsonSyntaxKind::Null,
            Self::Trivia(kind) => kind,
            Self::Error => JsonSyntaxKind::ErrorRegion,
        }
    }
}

pub(crate) fn parse(
    bytes: Arc<[u8]>,
    profile: JsonProfile,
    limits: ParseLimits,
) -> Result<Document, FatalFormationFailure> {
    if bytes.len() > limits.max_source_bytes {
        return Err(FatalFormationFailure::resource_limit(
            "source-bytes",
            bytes.len(),
            limits.max_source_bytes,
        ));
    }
    let source = SourceSnapshot::from_utf8(bytes).map_err(FatalFormationFailure::source_error)?;
    let authority = DocumentAuthority::fresh();
    let mut diagnostics = DiagnosticSink::new(limits.max_diagnostics);
    let Lexed {
        lexemes,
        tokens,
        recovered: lex_recovered,
    } = lex(
        source.bytes(),
        profile,
        &authority,
        limits,
        &mut diagnostics,
    )?;
    let syntax_kinds = lexemes
        .iter()
        .map(|lexeme| lexeme.class.syntax_kind())
        .collect::<Vec<_>>();
    let pieces = lexemes
        .iter()
        .map(|lexeme| {
            let kind = match lexeme.class {
                LexemeClass::Token(_) => StructuralPieceKind::Token,
                LexemeClass::Trivia(_) => StructuralPieceKind::Trivia,
                LexemeClass::Error => StructuralPieceKind::ErrorRegion,
            };
            StructuralPiece::new(
                authority
                    .span(lexeme.start, lexeme.end)
                    .expect("lexer emits ordered ranges"),
                kind,
            )
        })
        .collect();
    let structural_index = LosslessStructuralIndex::new(authority.identity(), source.len(), pieces)
        .expect("lexer partitions every source byte exactly once");

    let mut parser = Parser {
        source: source
            .decoded_text()
            .expect("JSON parser constructs a UTF-8 source"),
        profile,
        authority: &authority,
        tokens: &tokens,
        position: 0,
        entities: Vec::new(),
        diagnostics: &mut diagnostics,
        recovered: lex_recovered,
        limits,
    };
    let root = parser.parse_value(0)?;
    if parser.position < parser.tokens.len() {
        let token = parser.tokens[parser.position];
        parser.syntax_diagnostic(
            "json.syntax.trailing-content@1",
            token.start,
            parser.tokens.last().map_or(token.end, |item| item.end),
        );
        parser.recovered = true;
    }
    let formation_status = if parser.recovered {
        FormationStatus::Recovered
    } else {
        FormationStatus::Complete
    };
    let entities = std::mem::take(&mut parser.entities);
    drop(parser);
    let mut diagnostics = diagnostics.finish();
    Diagnostic::sort_deterministically(&mut diagnostics);
    Ok(Document {
        authority,
        source,
        profile,
        structural_index,
        syntax_kinds: Arc::from(syntax_kinds),
        formation_status,
        diagnostics: Arc::from(diagnostics),
        entities: Arc::from(entities),
        root,
        parse_limits: limits,
    })
}

struct Lexed {
    lexemes: Vec<Lexeme>,
    tokens: Vec<Token>,
    recovered: bool,
}

fn lex(
    bytes: &[u8],
    profile: JsonProfile,
    authority: &DocumentAuthority,
    limits: ParseLimits,
    diagnostics: &mut DiagnosticSink,
) -> Result<Lexed, FatalFormationFailure> {
    let mut lexemes = Vec::new();
    let mut tokens = Vec::new();
    let mut offset = 0;
    let mut recovered = false;
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        lexemes.push(Lexeme {
            start: 0,
            end: 3,
            class: LexemeClass::Trivia(JsonSyntaxKind::Bom),
        });
        if profile == JsonProfile::StrictV1 {
            diagnostics.push(Diagnostic::new(
                "json.strict.leading-bom@1",
                DiagnosticCategory::Conformance,
                DiagnosticSeverity::Warning,
                Some(
                    authority
                        .span(0, 3)
                        .expect("valid BOM span")
                        .diagnostic_location(),
                ),
                0,
            ));
        }
        offset = 3;
    }
    while offset < bytes.len() {
        let start = offset;
        let class = match bytes[offset] {
            b' ' | b'\t' | b'\r' | b'\n' => {
                offset += 1;
                while offset < bytes.len() && matches!(bytes[offset], b' ' | b'\t' | b'\r' | b'\n')
                {
                    offset += 1;
                }
                LexemeClass::Trivia(JsonSyntaxKind::Whitespace)
            }
            b'/' if bytes.get(offset + 1) == Some(&b'/') => {
                offset += 2;
                while offset < bytes.len() && !matches!(bytes[offset], b'\r' | b'\n') {
                    offset += 1;
                }
                if !profile.permits_jsonc_extensions() {
                    recovered = true;
                    diagnostics.push(source_diagnostic(
                        authority,
                        "json.strict.comment-not-allowed@1",
                        DiagnosticCategory::Conformance,
                        start,
                        offset,
                    ));
                }
                LexemeClass::Trivia(JsonSyntaxKind::LineComment)
            }
            b'/' if bytes.get(offset + 1) == Some(&b'*') => {
                offset += 2;
                let mut closed = false;
                while offset + 1 < bytes.len() {
                    if bytes[offset] == b'*' && bytes[offset + 1] == b'/' {
                        offset += 2;
                        closed = true;
                        break;
                    }
                    offset += 1;
                }
                if closed {
                    if !profile.permits_jsonc_extensions() {
                        recovered = true;
                        diagnostics.push(source_diagnostic(
                            authority,
                            "json.strict.comment-not-allowed@1",
                            DiagnosticCategory::Conformance,
                            start,
                            offset,
                        ));
                    }
                    LexemeClass::Trivia(JsonSyntaxKind::BlockComment)
                } else {
                    offset = bytes.len();
                    recovered = true;
                    diagnostics.push(source_diagnostic(
                        authority,
                        "json.syntax.unterminated-block-comment@1",
                        DiagnosticCategory::Syntax,
                        start,
                        offset,
                    ));
                    LexemeClass::Error
                }
            }
            b'{' => single_token(TokenKind::LeftBrace, &mut offset),
            b'}' => single_token(TokenKind::RightBrace, &mut offset),
            b'[' => single_token(TokenKind::LeftBracket, &mut offset),
            b']' => single_token(TokenKind::RightBracket, &mut offset),
            b':' => single_token(TokenKind::Colon, &mut offset),
            b',' => single_token(TokenKind::Comma, &mut offset),
            b'"' => {
                offset += 1;
                let mut escaped = false;
                let mut closed = false;
                while offset < bytes.len() {
                    let octet = bytes[offset];
                    offset += 1;
                    if escaped {
                        escaped = false;
                    } else if octet == b'\\' {
                        escaped = true;
                    } else if octet == b'"' {
                        closed = true;
                        break;
                    }
                }
                if closed {
                    LexemeClass::Token(TokenKind::String)
                } else {
                    recovered = true;
                    diagnostics.push(source_diagnostic(
                        authority,
                        "json.syntax.unterminated-string@1",
                        DiagnosticCategory::Syntax,
                        start,
                        offset,
                    ));
                    LexemeClass::Error
                }
            }
            b'-' | b'0'..=b'9' => {
                offset += 1;
                while offset < bytes.len()
                    && matches!(
                        bytes[offset],
                        b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E'
                    )
                {
                    offset += 1;
                }
                if valid_json_number(&bytes[start..offset]) {
                    LexemeClass::Token(TokenKind::Number)
                } else {
                    recovered = true;
                    diagnostics.push(source_diagnostic(
                        authority,
                        "json.syntax.invalid-number@1",
                        DiagnosticCategory::Syntax,
                        start,
                        offset,
                    ));
                    LexemeClass::Error
                }
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                offset += 1;
                while offset < bytes.len()
                    && matches!(bytes[offset], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
                {
                    offset += 1;
                }
                match &bytes[start..offset] {
                    b"true" => LexemeClass::Token(TokenKind::True),
                    b"false" => LexemeClass::Token(TokenKind::False),
                    b"null" => LexemeClass::Token(TokenKind::Null),
                    _ => {
                        recovered = true;
                        diagnostics.push(source_diagnostic(
                            authority,
                            "json.syntax.unexpected-word@1",
                            DiagnosticCategory::Syntax,
                            start,
                            offset,
                        ));
                        LexemeClass::Error
                    }
                }
            }
            _ => {
                let width = utf8_width(bytes[offset]);
                offset = (offset + width).min(bytes.len());
                recovered = true;
                diagnostics.push(source_diagnostic(
                    authority,
                    "json.syntax.unexpected-character@1",
                    DiagnosticCategory::Syntax,
                    start,
                    offset,
                ));
                LexemeClass::Error
            }
        };
        lexemes.push(Lexeme {
            start,
            end: offset,
            class,
        });
        if let LexemeClass::Token(kind) = class {
            tokens.push(Token {
                kind,
                start,
                end: offset,
            });
        }
        if lexemes.len() > limits.max_token_count {
            return Err(FatalFormationFailure::resource_limit(
                "token-count",
                lexemes.len(),
                limits.max_token_count,
            ));
        }
    }
    Ok(Lexed {
        lexemes,
        tokens,
        recovered,
    })
}

fn single_token(kind: TokenKind, offset: &mut usize) -> LexemeClass {
    *offset += 1;
    LexemeClass::Token(kind)
}

const fn utf8_width(leading: u8) -> usize {
    match leading {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

fn valid_json_number(bytes: &[u8]) -> bool {
    let mut index = 0;
    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'0') => index += 1,
        Some(b'1'..=b'9') => {
            index += 1;
            while matches!(bytes.get(index), Some(b'0'..=b'9')) {
                index += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == fraction_start {
            return false;
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let exponent_start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == exponent_start {
            return false;
        }
    }
    index == bytes.len()
}

struct Parser<'a> {
    source: &'a str,
    profile: JsonProfile,
    authority: &'a DocumentAuthority,
    tokens: &'a [Token],
    position: usize,
    entities: Vec<Entity>,
    diagnostics: &'a mut DiagnosticSink,
    recovered: bool,
    limits: ParseLimits,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<usize, FatalFormationFailure> {
        if depth > self.limits.max_nesting_depth {
            return Err(FatalFormationFailure::resource_limit(
                "nesting-depth",
                depth,
                self.limits.max_nesting_depth,
            ));
        }
        let Some(token) = self.peek() else {
            let offset = self.source.len();
            self.syntax_diagnostic("json.syntax.missing-value@1", offset, offset);
            self.recovered = true;
            return self.alloc_value(
                offset,
                offset,
                None,
                false,
                InternalValueKind::Unavailable(SemanticUnavailable::Missing),
            );
        };
        match token.kind {
            TokenKind::Null => {
                self.position += 1;
                self.alloc_scalar(token, InternalValueKind::Null)
            }
            TokenKind::True => {
                self.position += 1;
                self.alloc_scalar(token, InternalValueKind::Boolean(true))
            }
            TokenKind::False => {
                self.position += 1;
                self.alloc_scalar(token, InternalValueKind::Boolean(false))
            }
            TokenKind::Number => {
                self.position += 1;
                let text = &self.source[token.start..token.end];
                let kind = if text.contains(['.', 'e', 'E']) {
                    InternalValueKind::Decimal(
                        Decimal::parse_json_number(text).expect("lexer validated number"),
                    )
                } else {
                    InternalValueKind::Integer(
                        BigInteger::parse_decimal(text).expect("lexer validated number"),
                    )
                };
                self.alloc_scalar(token, kind)
            }
            TokenKind::String => {
                self.position += 1;
                if let Ok(value) = decode_json_string(&self.source[token.start..token.end]) {
                    self.alloc_scalar(token, InternalValueKind::String(value))
                } else {
                    self.syntax_diagnostic(
                        "json.syntax.invalid-string-escape@1",
                        token.start,
                        token.end,
                    );
                    self.recovered = true;
                    self.alloc_value(
                        token.start,
                        token.end,
                        Some((token.start, token.end)),
                        true,
                        InternalValueKind::Unavailable(SemanticUnavailable::InvalidLiteral),
                    )
                }
            }
            TokenKind::LeftBrace => self.parse_object(depth),
            TokenKind::LeftBracket => self.parse_array(depth),
            _ => {
                self.position += 1;
                self.syntax_diagnostic("json.syntax.expected-value@1", token.start, token.end);
                self.recovered = true;
                self.alloc_value(
                    token.start,
                    token.end,
                    None,
                    false,
                    InternalValueKind::Unavailable(SemanticUnavailable::ErrorRegion),
                )
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<usize, FatalFormationFailure> {
        let open = self.consume(TokenKind::LeftBrace).expect("caller checked");
        let mut members = Vec::new();
        let mut names = HashMap::<String, usize>::new();
        loop {
            if let Some(close) = self.consume(TokenKind::RightBrace) {
                let end = close.end;
                return self.alloc_value(
                    open.start,
                    end,
                    None,
                    true,
                    InternalValueKind::Object(members),
                );
            }
            if self.peek().is_none() {
                break;
            }
            let ordinal = members.len();
            let key = if self
                .peek()
                .is_some_and(|token| token.kind == TokenKind::String)
            {
                self.parse_value(depth + 1)?
            } else {
                let offset = self.current_offset();
                self.syntax_diagnostic("json.syntax.expected-object-key@1", offset, offset);
                self.recovered = true;
                self.alloc_value(
                    offset,
                    offset,
                    None,
                    false,
                    InternalValueKind::Unavailable(SemanticUnavailable::Missing),
                )?
            };
            if self.consume(TokenKind::Colon).is_none() {
                let offset = self.current_offset();
                self.syntax_diagnostic("json.syntax.missing-colon@1", offset, offset);
                self.recovered = true;
            }
            let value = self.parse_value(depth + 1)?;
            let member_start = self.entities[key].span().start_byte();
            let member_end = self.entities[value].span().end_byte();
            let member = self.alloc_entity(Entity::Member(MemberEntity {
                span: self
                    .authority
                    .span(member_start, member_end)
                    .expect("member range"),
                key,
                value,
                ordinal,
            }))?;
            members.push(member);
            if let InternalValueKind::String(name) = &self.value_entity(key).kind {
                if let Some(first) = names.insert(name.clone(), member) {
                    let first_span = self.entities[first].span();
                    let mut diagnostic = source_diagnostic(
                        self.authority,
                        "json.object.duplicate-member@1",
                        DiagnosticCategory::Semantic,
                        self.entities[member].span().start_byte(),
                        self.entities[member].span().end_byte(),
                    );
                    diagnostic.arguments.insert("name".to_owned(), name.clone());
                    diagnostic.related.push(consema_core::RelatedLocation {
                        role: "first-member".to_owned(),
                        location: first_span.diagnostic_location(),
                    });
                    self.diagnostics.push(diagnostic);
                }
            }
            if self.consume(TokenKind::Comma).is_some() {
                if self
                    .peek()
                    .is_some_and(|token| token.kind == TokenKind::RightBrace)
                    && !self.profile.permits_jsonc_extensions()
                {
                    let close = self.peek().expect("checked close");
                    self.syntax_diagnostic(
                        "json.strict.trailing-comma@1",
                        close.start.saturating_sub(1),
                        close.start,
                    );
                    self.recovered = true;
                }
                continue;
            }
            if self
                .peek()
                .is_some_and(|token| token.kind == TokenKind::RightBrace)
            {
                continue;
            }
            let offset = self.current_offset();
            self.syntax_diagnostic("json.syntax.missing-comma@1", offset, offset);
            self.recovered = true;
            if self.peek().is_some_and(|token| {
                !matches!(token.kind, TokenKind::String | TokenKind::RightBrace)
            }) {
                self.position += 1;
            }
        }
        let end = self.source.len();
        self.syntax_diagnostic("json.syntax.missing-object-close@1", end, end);
        self.recovered = true;
        self.alloc_value(
            open.start,
            end,
            None,
            false,
            InternalValueKind::Object(members),
        )
    }

    fn parse_array(&mut self, depth: usize) -> Result<usize, FatalFormationFailure> {
        let open = self
            .consume(TokenKind::LeftBracket)
            .expect("caller checked");
        let mut elements = Vec::new();
        loop {
            if let Some(close) = self.consume(TokenKind::RightBracket) {
                return self.alloc_value(
                    open.start,
                    close.end,
                    None,
                    true,
                    InternalValueKind::Array(elements),
                );
            }
            if self.peek().is_none() {
                let end = self.source.len();
                self.syntax_diagnostic("json.syntax.missing-array-close@1", end, end);
                self.recovered = true;
                return self.alloc_value(
                    open.start,
                    end,
                    None,
                    false,
                    InternalValueKind::Array(elements),
                );
            }
            let ordinal = elements.len();
            let value = self.parse_value(depth + 1)?;
            let span = self.entities[value].span();
            let element = self.alloc_entity(Entity::Element(ElementEntity {
                span,
                value,
                ordinal,
            }))?;
            elements.push(element);
            if self.consume(TokenKind::Comma).is_some() {
                if self
                    .peek()
                    .is_some_and(|token| token.kind == TokenKind::RightBracket)
                    && !self.profile.permits_jsonc_extensions()
                {
                    let close = self.peek().expect("checked close");
                    self.syntax_diagnostic(
                        "json.strict.trailing-comma@1",
                        close.start.saturating_sub(1),
                        close.start,
                    );
                    self.recovered = true;
                }
                continue;
            }
            if self
                .peek()
                .is_some_and(|token| token.kind == TokenKind::RightBracket)
            {
                continue;
            }
            let offset = self.current_offset();
            self.syntax_diagnostic("json.syntax.missing-comma@1", offset, offset);
            self.recovered = true;
        }
    }

    fn alloc_scalar(
        &mut self,
        token: Token,
        kind: InternalValueKind,
    ) -> Result<usize, FatalFormationFailure> {
        self.alloc_value(
            token.start,
            token.end,
            Some((token.start, token.end)),
            true,
            kind,
        )
    }

    fn alloc_value(
        &mut self,
        start: usize,
        end: usize,
        literal: Option<(usize, usize)>,
        complete: bool,
        kind: InternalValueKind,
    ) -> Result<usize, FatalFormationFailure> {
        self.alloc_entity(Entity::Value(ValueEntity {
            span: self.authority.span(start, end).expect("parser range"),
            literal_span: literal
                .map(|(start, end)| self.authority.span(start, end).expect("literal range")),
            complete,
            kind,
        }))
    }

    fn alloc_entity(&mut self, entity: Entity) -> Result<usize, FatalFormationFailure> {
        if self.entities.len() >= self.limits.max_node_count {
            return Err(FatalFormationFailure::resource_limit(
                "node-count",
                self.entities.len().saturating_add(1),
                self.limits.max_node_count,
            ));
        }
        let index = self.entities.len();
        self.entities.push(entity);
        Ok(index)
    }

    fn value_entity(&self, index: usize) -> &ValueEntity {
        match &self.entities[index] {
            Entity::Value(value) => value,
            _ => unreachable!("key is value entity"),
        }
    }

    fn peek(&self) -> Option<Token> {
        self.tokens.get(self.position).copied()
    }

    fn consume(&mut self, kind: TokenKind) -> Option<Token> {
        let token = self.peek()?;
        if token.kind == kind {
            self.position += 1;
            Some(token)
        } else {
            None
        }
    }

    fn current_offset(&self) -> usize {
        self.peek().map_or(self.source.len(), |token| token.start)
    }

    fn syntax_diagnostic(&mut self, code: &str, start: usize, end: usize) {
        self.diagnostics.push(source_diagnostic(
            self.authority,
            code,
            DiagnosticCategory::Syntax,
            start,
            end,
        ));
    }
}

fn decode_json_string(literal: &str) -> Result<String, ()> {
    let inner = literal
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .ok_or(())?;
    let mut output = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' {
            match chars.next().ok_or(())? {
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                '/' => output.push('/'),
                'b' => output.push('\u{0008}'),
                'f' => output.push('\u{000c}'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                'u' => {
                    let first = read_hex_quad(&mut chars)?;
                    let scalar = if (0xd800..=0xdbff).contains(&first) {
                        if chars.next() != Some('\\') || chars.next() != Some('u') {
                            return Err(());
                        }
                        let second = read_hex_quad(&mut chars)?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(());
                        }
                        0x1_0000
                            + ((u32::from(first) - 0xd800) << 10)
                            + (u32::from(second) - 0xdc00)
                    } else if (0xdc00..=0xdfff).contains(&first) {
                        return Err(());
                    } else {
                        u32::from(first)
                    };
                    output.push(char::from_u32(scalar).ok_or(())?);
                }
                _ => return Err(()),
            }
        } else if character <= '\u{001f}' {
            return Err(());
        } else {
            output.push(character);
        }
    }
    Ok(output)
}

fn read_hex_quad(iterator: &mut impl Iterator<Item = char>) -> Result<u16, ()> {
    let mut value = 0_u16;
    for _ in 0..4 {
        value = value
            .checked_mul(16)
            .and_then(|current| {
                iterator
                    .next()?
                    .to_digit(16)
                    .map(|digit| current + digit as u16)
            })
            .ok_or(())?;
    }
    Ok(value)
}

fn source_diagnostic(
    authority: &DocumentAuthority,
    code: &str,
    category: DiagnosticCategory,
    start: usize,
    end: usize,
) -> Diagnostic {
    Diagnostic::new(
        code,
        category,
        DiagnosticSeverity::Error,
        Some(
            authority
                .span(start, end)
                .expect("diagnostic range")
                .diagnostic_location(),
        ),
        0,
    )
}

struct DiagnosticSink {
    diagnostics: Vec<Diagnostic>,
    max: usize,
    occurrence: u64,
    truncated: bool,
}

impl DiagnosticSink {
    const fn new(max: usize) -> Self {
        Self {
            diagnostics: Vec::new(),
            max,
            occurrence: 0,
            truncated: false,
        }
    }

    fn push(&mut self, mut diagnostic: Diagnostic) {
        diagnostic.occurrence = self.occurrence;
        self.occurrence = self.occurrence.saturating_add(1);
        if self.diagnostics.len() < self.max {
            self.diagnostics.push(diagnostic);
        } else if !self.truncated {
            self.truncated = true;
            self.diagnostics.push(Diagnostic::new(
                "core.diagnostic.truncated@1",
                DiagnosticCategory::Resource,
                DiagnosticSeverity::Warning,
                None,
                self.occurrence,
            ));
        }
    }

    fn finish(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_grammar_is_bounded() {
        for valid in ["0", "-0", "1.25", "1e2", "-1.2E-3"] {
            assert!(valid_json_number(valid.as_bytes()), "{valid}");
        }
        for invalid in ["01", "+1", "1.", "1e", "--1"] {
            assert!(!valid_json_number(invalid.as_bytes()), "{invalid}");
        }
    }

    #[test]
    fn string_decoder_rejects_isolated_surrogate() {
        assert_eq!(decode_json_string(r#""\uD800""#), Err(()));
        assert_eq!(decode_json_string(r#""\uD83D\uDE00""#), Ok("😀".to_owned()));
    }
}
