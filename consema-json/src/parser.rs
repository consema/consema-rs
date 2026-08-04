use crate::{
    Document, ElementEntity, Entity, InternalValueKind, JsonProfile, JsonSyntaxKind, MemberEntity,
    SemanticUnavailable, ValueEntity,
};
use consema_core::{
    BigInteger, BinaryFloat64, Decimal, Diagnostic, DiagnosticCategory, DiagnosticSeverity,
};
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
    Identifier,
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
            Self::Token(TokenKind::Identifier) => JsonSyntaxKind::Identifier,
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
    if profile.is_json5() {
        return lex_json5(
            std::str::from_utf8(bytes).expect("source snapshot validated UTF-8"),
            authority,
            limits,
            diagnostics,
        );
    }
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

fn lex_json5(
    source: &str,
    authority: &DocumentAuthority,
    limits: ParseLimits,
    diagnostics: &mut DiagnosticSink,
) -> Result<Lexed, FatalFormationFailure> {
    let mut lexemes = Vec::new();
    let mut tokens = Vec::new();
    let mut offset = 0;
    let mut recovered = false;
    if source.starts_with('\u{feff}') {
        lexemes.push(Lexeme {
            start: 0,
            end: '\u{feff}'.len_utf8(),
            class: LexemeClass::Trivia(JsonSyntaxKind::Bom),
        });
        offset = '\u{feff}'.len_utf8();
    }
    while offset < source.len() {
        let start = offset;
        let character = char_at(source, offset);
        let class = if is_json5_whitespace(character) {
            offset += character.len_utf8();
            while offset < source.len() && is_json5_whitespace(char_at(source, offset)) {
                offset += char_at(source, offset).len_utf8();
            }
            LexemeClass::Trivia(JsonSyntaxKind::Whitespace)
        } else if source[start..].starts_with("//") {
            offset += 2;
            while offset < source.len() && !is_json5_line_terminator(char_at(source, offset)) {
                offset += char_at(source, offset).len_utf8();
            }
            LexemeClass::Trivia(JsonSyntaxKind::LineComment)
        } else if source[start..].starts_with("/*") {
            offset += 2;
            let mut closed = false;
            while offset < source.len() {
                if source[offset..].starts_with("*/") {
                    offset += 2;
                    closed = true;
                    break;
                }
                offset += char_at(source, offset).len_utf8();
            }
            if closed {
                LexemeClass::Trivia(JsonSyntaxKind::BlockComment)
            } else {
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
        } else {
            match character {
                '{' => single_token(TokenKind::LeftBrace, &mut offset),
                '}' => single_token(TokenKind::RightBrace, &mut offset),
                '[' => single_token(TokenKind::LeftBracket, &mut offset),
                ']' => single_token(TokenKind::RightBracket, &mut offset),
                ':' => single_token(TokenKind::Colon, &mut offset),
                ',' => single_token(TokenKind::Comma, &mut offset),
                '\'' | '"' => {
                    let quote = character;
                    offset += quote.len_utf8();
                    let mut closed = false;
                    while offset < source.len() {
                        let current = char_at(source, offset);
                        offset += current.len_utf8();
                        if current == '\\' {
                            if offset < source.len() {
                                let escaped = char_at(source, offset);
                                offset += escaped.len_utf8();
                                if escaped == '\r' && source[offset..].starts_with('\n') {
                                    offset += 1;
                                }
                            }
                        } else if current == quote {
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
                '+' | '-' | '.' | '0'..='9'
                    if character != '.'
                        || source[start + 1..]
                            .chars()
                            .next()
                            .is_some_and(|next| next.is_ascii_digit()) =>
                {
                    offset = scan_json5_number_candidate(source, start);
                    if valid_json5_number(&source[start..offset]) {
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
                _ if character == '\\' || is_json5_identifier_start(character) => {
                    let (end, valid) = scan_json5_identifier(source, start);
                    offset = end;
                    if valid {
                        LexemeClass::Token(TokenKind::Identifier)
                    } else {
                        recovered = true;
                        diagnostics.push(source_diagnostic(
                            authority,
                            "json5.syntax.invalid-identifier@1",
                            DiagnosticCategory::Syntax,
                            start,
                            offset,
                        ));
                        LexemeClass::Error
                    }
                }
                _ => {
                    offset += character.len_utf8();
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

fn char_at(source: &str, offset: usize) -> char {
    source[offset..]
        .chars()
        .next()
        .expect("offset is inside source and on a scalar boundary")
}

const fn is_json5_line_terminator(character: char) -> bool {
    matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

const fn is_json5_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            | '\u{000a}'
            | '\u{000b}'
            | '\u{000c}'
            | '\u{000d}'
            | '\u{0020}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

fn is_json5_identifier_start(character: char) -> bool {
    matches!(character, '$' | '_') || unicode_id_start::is_id_start(character)
}

fn is_json5_identifier_continue(character: char) -> bool {
    matches!(character, '$' | '_' | '\u{200c}' | '\u{200d}')
        || unicode_id_start::is_id_continue(character)
}

fn scan_json5_identifier(source: &str, start: usize) -> (usize, bool) {
    let mut offset = start;
    let mut first = true;
    let mut valid = true;
    while offset < source.len() {
        let character = char_at(source, offset);
        let (decoded, width) = if character == '\\' {
            if let Some(decoded) = decode_identifier_escape(&source[offset..]) {
                (decoded, 6)
            } else {
                valid = false;
                offset = scan_json5_invalid_word(source, offset);
                break;
            }
        } else {
            (character, character.len_utf8())
        };
        let permitted = if first {
            is_json5_identifier_start(decoded)
        } else {
            is_json5_identifier_continue(decoded)
        };
        if !permitted {
            if first || character == '\\' {
                valid = false;
                offset = scan_json5_invalid_word(source, offset);
            }
            break;
        }
        offset += width;
        first = false;
    }
    (offset, valid && !first)
}

fn scan_json5_invalid_word(source: &str, start: usize) -> usize {
    let mut offset = start;
    while offset < source.len() {
        let character = char_at(source, offset);
        if is_json5_whitespace(character)
            || matches!(
                character,
                '{' | '}' | '[' | ']' | ':' | ',' | '/' | '\'' | '"'
            )
        {
            break;
        }
        offset += character.len_utf8();
    }
    offset.max(start + 1)
}

fn decode_identifier_escape(source: &str) -> Option<char> {
    let bytes = source.as_bytes();
    if bytes.get(..2) != Some(b"\\u") || bytes.len() < 6 {
        return None;
    }
    let mut value = 0_u32;
    for byte in &bytes[2..6] {
        value = value.checked_mul(16)? + char::from(*byte).to_digit(16)?;
    }
    char::from_u32(value)
}

fn scan_json5_number_candidate(source: &str, start: usize) -> usize {
    let mut offset = start;
    while offset < source.len() {
        let character = char_at(source, offset);
        if !(character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.' | '_')) {
            break;
        }
        offset += character.len_utf8();
    }
    offset
}

fn valid_json5_number(text: &str) -> bool {
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    if matches!(unsigned, "Infinity" | "NaN") {
        return true;
    }
    if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    let bytes = unsigned.as_bytes();
    let mut index = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == start {
            return false;
        }
    } else {
        match bytes.get(index) {
            Some(b'0') => {
                index += 1;
                if matches!(bytes.get(index), Some(b'0'..=b'9')) {
                    return false;
                }
            }
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
            while matches!(bytes.get(index), Some(b'0'..=b'9')) {
                index += 1;
            }
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
                let kind = if self.profile.is_json5() {
                    parse_json5_number(text).expect("lexer validated JSON5 number")
                } else if text.contains(['.', 'e', 'E']) {
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
                if let Ok(decoded) =
                    decode_json_string(&self.source[token.start..token.end], self.profile)
                {
                    if decoded.has_unescaped_line_separator {
                        self.diagnostics.push(source_warning(
                            self.authority,
                            "json5.string.unescaped-line-separator@1",
                            DiagnosticCategory::Conformance,
                            token.start,
                            token.end,
                        ));
                    }
                    self.alloc_scalar(token, InternalValueKind::String(decoded.value))
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
            TokenKind::Identifier if self.profile.is_json5() => {
                self.position += 1;
                let text = decode_json5_identifier(&self.source[token.start..token.end])
                    .expect("lexer validated identifier");
                let kind = match text.as_str() {
                    "null" => InternalValueKind::Null,
                    "true" => InternalValueKind::Boolean(true),
                    "false" => InternalValueKind::Boolean(false),
                    "Infinity" => InternalValueKind::BinaryFloat64(BinaryFloat64::from_bits(
                        0x7ff0_0000_0000_0000,
                    )),
                    "NaN" => InternalValueKind::BinaryFloat64(BinaryFloat64::from_bits(
                        0x7ff8_0000_0000_0000,
                    )),
                    _ => {
                        self.syntax_diagnostic(
                            "json.syntax.expected-value@1",
                            token.start,
                            token.end,
                        );
                        self.recovered = true;
                        InternalValueKind::Unavailable(SemanticUnavailable::ErrorRegion)
                    }
                };
                self.alloc_scalar(token, kind)
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
            let key = if self.peek().is_some_and(|token| {
                token.kind == TokenKind::String
                    || (self.profile.is_json5() && token.kind == TokenKind::Identifier)
            }) {
                self.parse_object_key(depth + 1)?
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
                !matches!(
                    token.kind,
                    TokenKind::String | TokenKind::Identifier | TokenKind::RightBrace
                )
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

    fn parse_object_key(&mut self, depth: usize) -> Result<usize, FatalFormationFailure> {
        let token = self.peek().expect("caller checked object key");
        if token.kind == TokenKind::String {
            return self.parse_value(depth);
        }
        debug_assert!(self.profile.is_json5() && token.kind == TokenKind::Identifier);
        self.position += 1;
        let name = decode_json5_identifier(&self.source[token.start..token.end])
            .expect("lexer validated identifier");
        self.alloc_scalar(token, InternalValueKind::String(name))
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

struct DecodedString {
    value: String,
    has_unescaped_line_separator: bool,
}

fn decode_json_string(literal: &str, profile: JsonProfile) -> Result<DecodedString, ()> {
    let quote = literal.chars().next().ok_or(())?;
    if quote != '"' && !(profile.is_json5() && quote == '\'') {
        return Err(());
    }
    let inner = literal
        .strip_prefix(quote)
        .and_then(|text| text.strip_suffix(quote))
        .ok_or(())?;
    let mut output = String::new();
    let mut has_unescaped_line_separator = false;
    let mut chars = inner.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' {
            match chars.next().ok_or(())? {
                '"' => output.push('"'),
                '\'' if profile.is_json5() => output.push('\''),
                '\\' => output.push('\\'),
                '/' => output.push('/'),
                'b' => output.push('\u{0008}'),
                'f' => output.push('\u{000c}'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                'v' if profile.is_json5() => output.push('\u{000b}'),
                '0' if profile.is_json5() => {
                    if chars.peek().is_some_and(char::is_ascii_digit) {
                        return Err(());
                    }
                    output.push('\0');
                }
                'x' if profile.is_json5() => {
                    let value = read_hex_pair(&mut chars)?;
                    output.push(char::from(value));
                }
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
                '\n' | '\u{2028}' | '\u{2029}' if profile.is_json5() => {}
                '\r' if profile.is_json5() => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                }
                escaped
                    if profile.is_json5()
                        && !escaped.is_ascii_digit()
                        && !is_json5_line_terminator(escaped) =>
                {
                    output.push(escaped);
                }
                _ => return Err(()),
            }
        } else if character <= '\u{001f}' {
            return Err(());
        } else {
            if matches!(character, '\u{2028}' | '\u{2029}') {
                has_unescaped_line_separator = true;
            }
            output.push(character);
        }
    }
    Ok(DecodedString {
        value: output,
        has_unescaped_line_separator,
    })
}

fn read_hex_pair(iterator: &mut impl Iterator<Item = char>) -> Result<u8, ()> {
    let mut value = 0_u8;
    for _ in 0..2 {
        value = value
            .checked_mul(16)
            .and_then(|current| {
                iterator
                    .next()?
                    .to_digit(16)
                    .map(|digit| current + digit as u8)
            })
            .ok_or(())?;
    }
    Ok(value)
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

fn decode_json5_identifier(literal: &str) -> Result<String, ()> {
    let mut output = String::new();
    let mut offset = 0;
    let mut first = true;
    while offset < literal.len() {
        let character = char_at(literal, offset);
        let (decoded, width) = if character == '\\' {
            (decode_identifier_escape(&literal[offset..]).ok_or(())?, 6)
        } else {
            (character, character.len_utf8())
        };
        let permitted = if first {
            is_json5_identifier_start(decoded)
        } else {
            is_json5_identifier_continue(decoded)
        };
        if !permitted {
            return Err(());
        }
        output.push(decoded);
        offset += width;
        first = false;
    }
    if first { Err(()) } else { Ok(output) }
}

fn parse_json5_number(text: &str) -> Result<InternalValueKind, ()> {
    let (negative, unsigned) = if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    match unsigned {
        "Infinity" => {
            let bits = if negative {
                0xfff0_0000_0000_0000
            } else {
                0x7ff0_0000_0000_0000
            };
            return Ok(InternalValueKind::BinaryFloat64(BinaryFloat64::from_bits(
                bits,
            )));
        }
        "NaN" => {
            let bits = if negative {
                0xfff8_0000_0000_0000
            } else {
                0x7ff8_0000_0000_0000
            };
            return Ok(InternalValueKind::BinaryFloat64(BinaryFloat64::from_bits(
                bits,
            )));
        }
        _ => {}
    }
    if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        let mut magnitude = Vec::new();
        for digit in hex.bytes() {
            multiply_add_magnitude(
                &mut magnitude,
                16,
                char::from(digit).to_digit(16).ok_or(())? as u8,
            );
        }
        let sign = if negative { -1 } else { 1 };
        return BigInteger::from_sign_and_magnitude(sign, &magnitude)
            .map(InternalValueKind::Integer)
            .map_err(|_| ());
    }
    let mut normalized = if negative {
        format!("-{unsigned}")
    } else {
        unsigned.to_owned()
    };
    let sign_width = usize::from(negative);
    if normalized[sign_width..].starts_with('.') {
        normalized.insert(sign_width, '0');
    }
    let exponent = normalized.find(['e', 'E']).unwrap_or(normalized.len());
    if normalized[..exponent].ends_with('.') {
        normalized.insert(exponent, '0');
    }
    if normalized.contains(['.', 'e', 'E']) {
        Decimal::parse_json_number(&normalized)
            .map(InternalValueKind::Decimal)
            .map_err(|_| ())
    } else {
        BigInteger::parse_decimal(&normalized)
            .map(InternalValueKind::Integer)
            .map_err(|_| ())
    }
}

fn multiply_add_magnitude(bytes: &mut Vec<u8>, multiplier: u16, addend: u8) {
    let mut carry = u16::from(addend);
    for octet in bytes.iter_mut().rev() {
        let value = u16::from(*octet) * multiplier + carry;
        *octet = value as u8;
        carry = value >> 8;
    }
    while carry != 0 {
        bytes.insert(0, carry as u8);
        carry >>= 8;
    }
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

fn source_warning(
    authority: &DocumentAuthority,
    code: &str,
    category: DiagnosticCategory,
    start: usize,
    end: usize,
) -> Diagnostic {
    Diagnostic::new(
        code,
        category,
        DiagnosticSeverity::Warning,
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
        assert!(decode_json_string(r#""\uD800""#, JsonProfile::StrictV1).is_err());
        assert_eq!(
            decode_json_string(r#""\uD83D\uDE00""#, JsonProfile::StrictV1)
                .unwrap()
                .value,
            "😀"
        );
    }

    #[test]
    fn json5_number_grammar_is_exact() {
        for valid in [
            "+1", "1.", ".5", "1.e2", "0xdecaf", "-0X1", "Infinity", "+NaN",
        ] {
            assert!(valid_json5_number(valid), "{valid}");
        }
        for invalid in ["01", ".", "0x", "1e", "0b1", "1_0", "+true"] {
            assert!(!valid_json5_number(invalid), "{invalid}");
        }
    }

    #[test]
    fn json5_invalid_escape_after_identifier_start_recovers_without_panicking() {
        for source in [r"{a\u0021:1}", r"{π\u0021:1}"] {
            let document = parse(
                source.as_bytes().into(),
                JsonProfile::Json5StandardV1,
                ParseLimits::default(),
            )
            .unwrap();
            assert_eq!(document.render(), source.as_bytes());
            assert_eq!(document.formation_status(), FormationStatus::Recovered);
            assert!(
                document
                    .diagnostics()
                    .iter()
                    .any(|item| item.code == "json5.syntax.invalid-identifier@1")
            );
        }
    }

    #[test]
    fn json5_string_decoder_handles_extensions_without_rounding() {
        let decoded = decode_json_string(
            r"'single\x20\v\0\q\
line'",
            JsonProfile::Json5StandardV1,
        )
        .unwrap();
        assert_eq!(decoded.value, "single \u{000b}\0qline");
        assert!(!decoded.has_unescaped_line_separator);
    }
}
