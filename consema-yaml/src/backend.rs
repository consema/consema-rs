use saphyr_parser::{Event, Parser, ScalarStyle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackendSpan {
    pub(crate) start_scalar: usize,
    pub(crate) end_scalar: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BackendTag {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BackendEventKind {
    StreamStart,
    StreamEnd,
    DocumentStart {
        explicit: bool,
    },
    DocumentEnd,
    Alias {
        anchor_id: usize,
    },
    Scalar {
        decoded: String,
        style: BackendScalarStyle,
        anchor_id: Option<usize>,
        tag: Option<BackendTag>,
    },
    SequenceStart {
        anchor_id: Option<usize>,
        tag: Option<BackendTag>,
    },
    SequenceEnd,
    MappingStart {
        anchor_id: Option<usize>,
        tag: Option<BackendTag>,
    },
    MappingEnd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BackendEvent {
    pub(crate) kind: BackendEventKind,
    pub(crate) span: BackendSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BackendError {
    Syntax {
        scalar_offset: usize,
    },
    ResourceLimit {
        name: &'static str,
        observed: usize,
        limit: usize,
    },
}

pub(crate) fn parse_events(
    text: &str,
    max_events: usize,
    max_depth: usize,
) -> Result<Vec<BackendEvent>, BackendError> {
    let mut output = Vec::new();
    let mut depth = 0usize;
    for result in Parser::new_from_str(text).keep_tags(false) {
        let (event, span) = result.map_err(|error| BackendError::Syntax {
            scalar_offset: error.marker().index(),
        })?;
        let kind = match event {
            Event::Nothing => continue,
            Event::StreamStart => BackendEventKind::StreamStart,
            Event::StreamEnd => BackendEventKind::StreamEnd,
            Event::DocumentStart(explicit) => BackendEventKind::DocumentStart { explicit },
            Event::DocumentEnd => BackendEventKind::DocumentEnd,
            Event::Alias(anchor_id) => BackendEventKind::Alias { anchor_id },
            Event::Scalar(decoded, style, anchor_id, tag) => BackendEventKind::Scalar {
                decoded: decoded.into_owned(),
                style: scalar_style(style),
                anchor_id: nonzero_anchor(anchor_id),
                tag: tag.map(|tag| BackendTag {
                    prefix: tag.handle.clone(),
                    suffix: tag.suffix.clone(),
                }),
            },
            Event::SequenceStart(anchor_id, tag) => {
                depth = checked_depth(depth, max_depth)?;
                BackendEventKind::SequenceStart {
                    anchor_id: nonzero_anchor(anchor_id),
                    tag: tag.map(|tag| BackendTag {
                        prefix: tag.handle.clone(),
                        suffix: tag.suffix.clone(),
                    }),
                }
            }
            Event::SequenceEnd => {
                depth = depth.saturating_sub(1);
                BackendEventKind::SequenceEnd
            }
            Event::MappingStart(anchor_id, tag) => {
                depth = checked_depth(depth, max_depth)?;
                BackendEventKind::MappingStart {
                    anchor_id: nonzero_anchor(anchor_id),
                    tag: tag.map(|tag| BackendTag {
                        prefix: tag.handle.clone(),
                        suffix: tag.suffix.clone(),
                    }),
                }
            }
            Event::MappingEnd => {
                depth = depth.saturating_sub(1);
                BackendEventKind::MappingEnd
            }
        };
        let observed = output.len().saturating_add(1);
        if observed > max_events {
            return Err(BackendError::ResourceLimit {
                name: "syntax-events",
                observed,
                limit: max_events,
            });
        }
        output.push(BackendEvent {
            kind,
            span: BackendSpan {
                start_scalar: span.start.index(),
                end_scalar: span.end.index(),
            },
        });
    }
    Ok(output)
}

fn checked_depth(depth: usize, limit: usize) -> Result<usize, BackendError> {
    let observed = depth.saturating_add(1);
    if observed > limit {
        Err(BackendError::ResourceLimit {
            name: "nesting-depth",
            observed,
            limit,
        })
    } else {
        Ok(observed)
    }
}

const fn nonzero_anchor(anchor_id: usize) -> Option<usize> {
    if anchor_id == 0 {
        None
    } else {
        Some(anchor_id)
    }
}

const fn scalar_style(style: ScalarStyle) -> BackendScalarStyle {
    match style {
        ScalarStyle::Plain => BackendScalarStyle::Plain,
        ScalarStyle::SingleQuoted => BackendScalarStyle::SingleQuoted,
        ScalarStyle::DoubleQuoted => BackendScalarStyle::DoubleQuoted,
        ScalarStyle::Literal => BackendScalarStyle::Literal,
        ScalarStyle::Folded => BackendScalarStyle::Folded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_preserves_styles_resolved_tags_anchors_aliases_and_documents() {
        let source = "%TAG !e! tag:example.com,2026:\n---\nroot: &node !e!thing [one, *node]\n---\nsecond: |\n  text\n";
        let events = parse_events(source, 100, 10).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.kind, BackendEventKind::DocumentStart { .. }))
                .count(),
            2
        );
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            BackendEventKind::SequenceStart {
                anchor_id: Some(1),
                tag: Some(tag),
            } if format!("{}{}", tag.prefix, tag.suffix) == "tag:example.com,2026:thing"
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, BackendEventKind::Alias { anchor_id: 1 }))
        );
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            BackendEventKind::Scalar {
                decoded,
                style: BackendScalarStyle::Literal,
                ..
            } if decoded == "text\n"
        )));
    }

    #[test]
    fn backend_spans_are_unicode_scalar_offsets_not_raw_bytes() {
        let source = "鍵: \"值\"";
        let events = parse_events(source, 100, 10).unwrap();
        let scalar = events
            .iter()
            .find(|event| {
                matches!(
                    &event.kind,
                    BackendEventKind::Scalar { decoded, .. } if decoded == "值"
                )
            })
            .unwrap();
        assert_eq!((scalar.span.start_scalar, scalar.span.end_scalar), (3, 6));
        assert_eq!(
            source
                .chars()
                .skip(scalar.span.start_scalar)
                .take(scalar.span.end_scalar - scalar.span.start_scalar)
                .collect::<String>(),
            "\"值\""
        );
    }

    #[test]
    fn backend_limits_fail_without_partial_events() {
        assert_eq!(
            parse_events("[[x]]", 100, 1).unwrap_err(),
            BackendError::ResourceLimit {
                name: "nesting-depth",
                observed: 2,
                limit: 1,
            }
        );
        assert_eq!(
            parse_events("x", 2, 10).unwrap_err(),
            BackendError::ResourceLimit {
                name: "syntax-events",
                observed: 3,
                limit: 2,
            }
        );
    }
}
