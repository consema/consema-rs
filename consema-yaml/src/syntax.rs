use consema_document::{
    DocumentAuthority, FatalFormationFailure, LosslessStructuralIndex, SourceSnapshot, Span,
    StructuralPiece, StructuralPieceKind,
};

use crate::YamlSyntaxKind;
use crate::offsets::RawByteResolver;

#[derive(Clone, Copy, Debug)]
struct Lexeme {
    start: usize,
    end: usize,
    kind: YamlSyntaxKind,
}

pub(crate) fn tokenize(
    source: &SourceSnapshot,
    authority: &DocumentAuthority,
    max_tokens: usize,
) -> Result<Tokenized, FatalFormationFailure> {
    let text = source
        .decoded_text()
        .expect("YAML source always has decoded text");
    let chars = text.chars().collect::<Vec<_>>();
    let lexemes = Scanner::new(&chars, max_tokens).scan()?;
    let mut pieces = Vec::with_capacity(lexemes.len());
    let mut kinds = Vec::with_capacity(lexemes.len());
    let mut anchors = Vec::new();
    let mut aliases = Vec::new();
    // `SourceSnapshot::raw_byte_at` re-validates the whole decoded text on
    // every call (O(source) each), which makes a per-lexeme lookup loop
    // O(source x lexemes). Lexeme boundaries arrive in order, so one forward
    // walk resolves all of them in O(source + lexemes) total.
    let mut raw = RawByteResolver::new(source);
    for lexeme in lexemes {
        let start = raw.resolve(lexeme.start);
        let end = raw.resolve(lexeme.end);
        let span = authority
            .span(start, end)
            .expect("scanner emits ordered raw ranges");
        pieces.push(StructuralPiece::new(
            span,
            if lexeme.kind.is_trivia() {
                StructuralPieceKind::Trivia
            } else if lexeme.kind == YamlSyntaxKind::ErrorRegion {
                StructuralPieceKind::ErrorRegion
            } else {
                StructuralPieceKind::Token
            },
        ));
        kinds.push(lexeme.kind);
        if matches!(lexeme.kind, YamlSyntaxKind::Anchor | YamlSyntaxKind::Alias) {
            let name = chars[lexeme.start + 1..lexeme.end]
                .iter()
                .collect::<String>();
            if lexeme.kind == YamlSyntaxKind::Anchor {
                anchors.push(NamedOccurrence { name, span });
            } else {
                aliases.push(NamedOccurrence { name, span });
            }
        }
    }
    let index = LosslessStructuralIndex::new(authority.identity(), source.len(), pieces)
        .expect("YAML scanner partitions every raw source byte exactly once");
    Ok(Tokenized {
        index,
        kinds,
        anchors,
        aliases,
    })
}

#[derive(Clone, Debug)]
pub(crate) struct NamedOccurrence {
    pub(crate) name: String,
    pub(crate) span: Span,
}

pub(crate) struct Tokenized {
    pub(crate) index: LosslessStructuralIndex,
    pub(crate) kinds: Vec<YamlSyntaxKind>,
    pub(crate) anchors: Vec<NamedOccurrence>,
    pub(crate) aliases: Vec<NamedOccurrence>,
}

struct Scanner<'a> {
    chars: &'a [char],
    offset: usize,
    line_start: usize,
    max_tokens: usize,
    output: Vec<Lexeme>,
    pending_block_parent_indent: Option<usize>,
    plain_line_active: bool,
    plain_parent_indent: Option<usize>,
}

impl<'a> Scanner<'a> {
    const fn new(chars: &'a [char], max_tokens: usize) -> Self {
        Self {
            chars,
            offset: 0,
            line_start: 0,
            max_tokens,
            output: Vec::new(),
            pending_block_parent_indent: None,
            plain_line_active: false,
            plain_parent_indent: None,
        }
    }

    fn scan(mut self) -> Result<Vec<Lexeme>, FatalFormationFailure> {
        while self.offset < self.chars.len() {
            if self.offset == self.line_start
                && self.pending_block_parent_indent.is_some()
                && self.scan_block_content()?
            {
                continue;
            }
            let start = self.offset;
            let current = self.chars[start];
            if !matches!(current, ' ' | '\t' | '\r' | '\n')
                && !self.plain_line_active
                && self.plain_parent_indent.is_some()
            {
                if self.line_indent() > self.plain_parent_indent.expect("checked above")
                    && !self.starts_indented_structure()
                {
                    self.take_until_break();
                    self.push(start, self.offset, YamlSyntaxKind::PlainScalar)?;
                    self.plain_line_active = true;
                    continue;
                }
                self.plain_parent_indent = None;
            }
            if current == '\u{feff}' {
                self.offset += 1;
                self.push(start, self.offset, YamlSyntaxKind::Bom)?;
                self.end_plain_scalar();
                if start == self.line_start {
                    self.line_start = self.offset;
                }
            } else if matches!(current, ' ' | '\t') {
                self.take_while(|item| matches!(item, ' ' | '\t'));
                self.push(start, self.offset, YamlSyntaxKind::Whitespace)?;
            } else if matches!(current, '\r' | '\n') {
                self.scan_newline(start)?;
            } else if current == '#' {
                self.take_until_break();
                self.push(start, self.offset, YamlSyntaxKind::Comment)?;
                self.end_plain_scalar();
            } else if self.at_directive() {
                self.take_until_break();
                self.push(start, self.offset, YamlSyntaxKind::Directive)?;
                self.end_plain_scalar();
            } else if self.at_document_indicator('-', '-', '-') {
                self.offset += 3;
                self.push(start, self.offset, YamlSyntaxKind::DocumentStart)?;
                self.end_plain_scalar();
            } else if self.at_document_indicator('.', '.', '.') {
                self.offset += 3;
                self.push(start, self.offset, YamlSyntaxKind::DocumentEnd)?;
                self.end_plain_scalar();
            } else if matches!(current, '\'' | '"') {
                self.scan_quoted(current);
                self.push(
                    start,
                    self.offset,
                    if current == '\'' {
                        YamlSyntaxKind::SingleQuotedScalar
                    } else {
                        YamlSyntaxKind::DoubleQuotedScalar
                    },
                )?;
                self.end_plain_scalar();
            } else if matches!(current, '|' | '>') && self.is_block_header() {
                let parent_indent = self.line_indent();
                self.take_until_break();
                self.push(
                    start,
                    self.offset,
                    if current == '|' {
                        YamlSyntaxKind::LiteralBlockHeader
                    } else {
                        YamlSyntaxKind::FoldedBlockHeader
                    },
                )?;
                self.pending_block_parent_indent = Some(parent_indent);
                self.end_plain_scalar();
            } else if matches!(current, '&' | '*' | '!') && !self.plain_line_active {
                self.offset += 1;
                self.take_while(|item| !is_separation(item) && !is_flow_indicator(item));
                self.push(
                    start,
                    self.offset,
                    match current {
                        '&' => YamlSyntaxKind::Anchor,
                        '*' => YamlSyntaxKind::Alias,
                        '!' => YamlSyntaxKind::Tag,
                        _ => unreachable!(
                            "caller checked the byte is an anchor, alias, or tag marker"
                        ),
                    },
                )?;
                self.end_plain_scalar();
            } else if let Some(kind) = self.indicator_kind() {
                self.offset += 1;
                self.push(start, self.offset, kind)?;
                self.end_plain_scalar();
            } else {
                self.scan_plain();
                self.push(start, self.offset, YamlSyntaxKind::PlainScalar)?;
                if !self.plain_line_active {
                    self.plain_parent_indent = Some(self.line_indent());
                }
                self.plain_line_active = true;
            }
        }
        Ok(self.output)
    }

    fn push(
        &mut self,
        start: usize,
        end: usize,
        kind: YamlSyntaxKind,
    ) -> Result<(), FatalFormationFailure> {
        let observed = self.output.len().saturating_add(1);
        if observed > self.max_tokens {
            return Err(FatalFormationFailure::resource_limit(
                "syntax-pieces",
                observed,
                self.max_tokens,
            ));
        }
        debug_assert!(end > start);
        self.output.push(Lexeme { start, end, kind });
        Ok(())
    }

    fn scan_newline(&mut self, start: usize) -> Result<(), FatalFormationFailure> {
        if self.chars[self.offset] == '\r' && self.chars.get(self.offset + 1) == Some(&'\n') {
            self.offset += 2;
        } else {
            self.offset += 1;
        }
        self.push(start, self.offset, YamlSyntaxKind::Newline)?;
        self.line_start = self.offset;
        self.plain_line_active = false;
        Ok(())
    }

    fn end_plain_scalar(&mut self) {
        self.plain_line_active = false;
        self.plain_parent_indent = None;
    }

    fn starts_indented_structure(&self) -> bool {
        if matches!(self.chars[self.offset], '-' | '?')
            && self
                .chars
                .get(self.offset + 1)
                .is_none_or(|character| is_separation(*character))
        {
            return true;
        }
        let mut cursor = self.offset;
        while let Some(character) = self.chars.get(cursor) {
            if matches!(character, '\r' | '\n' | '#') {
                return false;
            }
            if *character == ':'
                && self
                    .chars
                    .get(cursor + 1)
                    .is_none_or(|next| is_separation(*next))
            {
                return true;
            }
            cursor += 1;
        }
        false
    }

    fn scan_quoted(&mut self, quote: char) {
        self.offset += 1;
        while self.offset < self.chars.len() {
            let current = self.chars[self.offset];
            self.offset += 1;
            if quote == '"' && current == '\\' && self.offset < self.chars.len() {
                if self.chars[self.offset] == '\r' {
                    self.offset += 1;
                    if self.chars.get(self.offset) == Some(&'\n') {
                        self.offset += 1;
                    }
                    self.line_start = self.offset;
                } else if self.chars[self.offset] == '\n' {
                    self.offset += 1;
                    self.line_start = self.offset;
                } else {
                    self.offset += 1;
                }
            } else if current == quote {
                if quote == '\'' && self.chars.get(self.offset) == Some(&'\'') {
                    self.offset += 1;
                } else {
                    break;
                }
            } else if current == '\n' {
                self.line_start = self.offset;
            } else if current == '\r' {
                if self.chars.get(self.offset) == Some(&'\n') {
                    self.offset += 1;
                }
                self.line_start = self.offset;
            }
        }
    }

    fn scan_plain(&mut self) {
        self.offset += 1;
        while let Some(&current) = self.chars.get(self.offset) {
            if is_separation(current) || is_flow_indicator(current) {
                break;
            }
            if current == ':' {
                let next = self.chars.get(self.offset + 1).copied();
                if next.is_none_or(|item| is_separation(item) || is_flow_indicator(item)) {
                    break;
                }
            }
            self.offset += 1;
        }
    }

    fn scan_block_content(&mut self) -> Result<bool, FatalFormationFailure> {
        let parent_indent = self.pending_block_parent_indent.expect("checked by caller");
        let start = self.offset;
        let mut cursor = start;
        let mut accepted_end = start;
        while cursor < self.chars.len() {
            let line_end = next_line_end(self.chars, cursor);
            let content_end = line_content_end(self.chars, cursor, line_end);
            let indent = self.chars[cursor..content_end]
                .iter()
                .take_while(|item| **item == ' ')
                .count();
            let blank = self.chars[cursor + indent..content_end]
                .iter()
                .all(|item| matches!(item, ' ' | '\t'));
            if !blank && indent <= parent_indent {
                break;
            }
            accepted_end = line_end;
            cursor = line_end;
        }
        self.pending_block_parent_indent = None;
        if accepted_end == start {
            return Ok(false);
        }
        self.offset = accepted_end;
        self.line_start = accepted_end;
        self.push(start, accepted_end, YamlSyntaxKind::BlockScalarContent)?;
        Ok(true)
    }

    fn indicator_kind(&self) -> Option<YamlSyntaxKind> {
        let current = self.chars[self.offset];
        match current {
            '[' => Some(YamlSyntaxKind::FlowSequenceStart),
            ']' => Some(YamlSyntaxKind::FlowSequenceEnd),
            '{' => Some(YamlSyntaxKind::FlowMappingStart),
            '}' => Some(YamlSyntaxKind::FlowMappingEnd),
            ',' => Some(YamlSyntaxKind::FlowEntry),
            '-' if self.followed_by_separation(1) => Some(YamlSyntaxKind::SequenceEntry),
            '?' if self.followed_by_separation(1) => Some(YamlSyntaxKind::ExplicitKey),
            ':' if self.followed_by_separation(1) => Some(YamlSyntaxKind::MappingValue),
            _ => None,
        }
    }

    fn at_directive(&self) -> bool {
        self.offset == self.line_start && self.chars[self.offset] == '%'
    }

    fn at_document_indicator(&self, a: char, b: char, c: char) -> bool {
        self.offset == self.line_start
            && self.chars.get(self.offset..self.offset + 3) == Some(&[a, b, c])
            && self.followed_by_separation(3)
    }

    fn followed_by_separation(&self, length: usize) -> bool {
        self.chars
            .get(self.offset + length)
            .copied()
            .is_none_or(is_separation)
    }

    fn is_block_header(&self) -> bool {
        self.chars[self.offset + 1..]
            .iter()
            .take_while(|item| !matches!(item, '\r' | '\n'))
            .all(|item| matches!(item, '+' | '-' | '0'..='9' | ' ' | '\t' | '#'))
    }

    fn line_indent(&self) -> usize {
        self.chars[self.line_start..self.offset]
            .iter()
            .take_while(|item| **item == ' ')
            .count()
    }

    fn take_until_break(&mut self) {
        self.take_while(|item| !matches!(item, '\r' | '\n'));
    }

    fn take_while(&mut self, predicate: impl Fn(char) -> bool) {
        while self.chars.get(self.offset).copied().is_some_and(&predicate) {
            self.offset += 1;
        }
    }
}

const fn is_separation(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\r' | '\n')
}

const fn is_flow_indicator(value: char) -> bool {
    matches!(value, '[' | ']' | '{' | '}' | ',')
}

fn next_line_end(chars: &[char], start: usize) -> usize {
    let mut cursor = start;
    while cursor < chars.len() && !matches!(chars[cursor], '\r' | '\n') {
        cursor += 1;
    }
    if chars.get(cursor) == Some(&'\r') {
        cursor += 1;
        if chars.get(cursor) == Some(&'\n') {
            cursor += 1;
        }
    } else if chars.get(cursor) == Some(&'\n') {
        cursor += 1;
    }
    cursor
}

fn line_content_end(chars: &[char], start: usize, line_end: usize) -> usize {
    let mut end = line_end;
    if end > start && chars[end - 1] == '\n' {
        end -= 1;
    }
    if end > start && chars[end - 1] == '\r' {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use consema_document::{EncodingRequest, SourceEncoding, SourceLimits};

    use super::*;

    fn kinds(text: &str) -> Vec<YamlSyntaxKind> {
        let source = SourceSnapshot::from_raw(
            Arc::<[u8]>::from(text.as_bytes()),
            EncodingRequest::new(SourceEncoding::Utf8),
            SourceLimits::default(),
        )
        .unwrap();
        tokenize(&source, &DocumentAuthority::fresh(), 100)
            .unwrap()
            .kinds
    }

    #[test]
    fn classifies_presentation_styles_and_trivia() {
        let result = kinds("---\nkey: &a [one, *a] # c\nblock: |-\n  x\n...\n");
        assert!(result.contains(&YamlSyntaxKind::DocumentStart));
        assert!(result.contains(&YamlSyntaxKind::Anchor));
        assert!(result.contains(&YamlSyntaxKind::Alias));
        assert!(result.contains(&YamlSyntaxKind::FlowSequenceStart));
        assert!(result.contains(&YamlSyntaxKind::Comment));
        assert!(result.contains(&YamlSyntaxKind::LiteralBlockHeader));
        assert!(result.contains(&YamlSyntaxKind::BlockScalarContent));
        assert!(result.contains(&YamlSyntaxKind::DocumentEnd));
    }

    #[test]
    fn plain_hash_and_colon_are_not_always_indicators() {
        assert_eq!(
            kinds("url: http://x/#part\n"),
            vec![
                YamlSyntaxKind::PlainScalar,
                YamlSyntaxKind::MappingValue,
                YamlSyntaxKind::Whitespace,
                YamlSyntaxKind::PlainScalar,
                YamlSyntaxKind::Newline,
            ]
        );
    }

    #[test]
    fn node_property_characters_inside_plain_scalars_remain_scalar_text() {
        let result = kinds("---\nk:#foo\n &a !t s\n");
        assert!(!result.contains(&YamlSyntaxKind::Anchor));
        assert!(!result.contains(&YamlSyntaxKind::Tag));

        let result = kinds("plain &a !t text\nkey: &real !tag value\n");
        assert_eq!(
            result
                .iter()
                .filter(|kind| **kind == YamlSyntaxKind::Anchor)
                .count(),
            1
        );
        assert_eq!(
            result
                .iter()
                .filter(|kind| **kind == YamlSyntaxKind::Tag)
                .count(),
            1
        );
    }

    #[test]
    fn nested_mapping_after_plain_value_retains_node_properties() {
        let result = kinds(
            "items:\n  - name: first\n    settings: &defaults {retries: 3}\n    copy: *defaults\n",
        );
        assert_eq!(
            result
                .iter()
                .filter(|kind| **kind == YamlSyntaxKind::Anchor)
                .count(),
            1
        );
        assert_eq!(
            result
                .iter()
                .filter(|kind| **kind == YamlSyntaxKind::Alias)
                .count(),
            1
        );
    }
}
