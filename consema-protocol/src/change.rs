//! Transferable atomic ChangeSet protocol.

use crate::schema::{
    exact_fields, integer_u64, nullable_string, object, optional_string, schema_fields, sequence,
    string, unsigned_u64,
};
use crate::{DiagnosticMessage, ProtocolError, ProtocolErrorKind};
use consema_core::{PortableValue, SequenceBuilder};
use consema_document::{ChangeSet, NodeMappingStatus, NodeRef};
use std::collections::BTreeSet;

/// One ordered source replacement in wire coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEditMessage {
    /// Inclusive old-source start.
    pub old_start: u64,
    /// Exclusive old-source end.
    pub old_end: u64,
    /// Inclusive new-source start.
    pub new_start: u64,
    /// Exclusive new-source end.
    pub new_end: u64,
    /// Exact replacement bytes.
    pub replacement: Vec<u8>,
}

impl SourceEditMessage {
    /// Validates range order and replacement/new-range agreement.
    pub fn new(
        old_start: u64,
        old_end: u64,
        new_start: u64,
        new_end: u64,
        replacement: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        let replacement_len = u64::try_from(replacement.len()).map_err(|_| {
            crate::schema::invalid("$.replacement", "replacement length exceeds u64")
        })?;
        if old_start > old_end || new_start > new_end || new_end - new_start != replacement_len {
            return Err(crate::schema::invalid(
                "$.source_edit",
                "invalid ranges or replacement length",
            ));
        }
        Ok(Self {
            old_start,
            old_end,
            new_start,
            new_end,
            replacement,
        })
    }
}

/// One portable node-mapping fact using caller-defined stable locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeMappingMessage {
    /// One or more old locators.
    pub old_locators: Vec<String>,
    /// Zero or more new locators.
    pub new_locators: Vec<String>,
    /// Mapping topology/status.
    pub status: NodeMappingStatus,
    /// Stable reason for non-trivial or unresolved mapping.
    pub reason: Option<String>,
}

impl NodeMappingMessage {
    /// Validates locator topology against mapping status.
    pub fn new(
        old_locators: Vec<String>,
        new_locators: Vec<String>,
        status: NodeMappingStatus,
        reason: Option<String>,
    ) -> Result<Self, ProtocolError> {
        if !unique_locators(&old_locators)
            || !unique_locators(&new_locators)
            || old_locators
                .iter()
                .chain(&new_locators)
                .any(|locator| locator.is_empty() || locator.len() > 4096)
        {
            return Err(crate::schema::invalid(
                "$.node_mapping",
                "locators must be non-empty, bounded, and unique per side",
            ));
        }
        let topology = match status {
            NodeMappingStatus::Preserved => old_locators.len() == 1 && new_locators.len() == 1,
            NodeMappingStatus::Replaced => old_locators.len() == 1 && new_locators.len() <= 1,
            NodeMappingStatus::Deleted => old_locators.len() == 1 && new_locators.is_empty(),
            NodeMappingStatus::Split => old_locators.len() == 1 && new_locators.len() >= 2,
            NodeMappingStatus::Merged => old_locators.len() >= 2 && new_locators.len() == 1,
            NodeMappingStatus::Unmapped => !old_locators.is_empty() && new_locators.is_empty(),
        };
        let needs_reason = match status {
            NodeMappingStatus::Preserved => false,
            NodeMappingStatus::Replaced => new_locators.is_empty(),
            NodeMappingStatus::Deleted
            | NodeMappingStatus::Split
            | NodeMappingStatus::Merged
            | NodeMappingStatus::Unmapped => true,
        };
        if !topology
            || needs_reason
                != reason
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 1024)
        {
            return Err(crate::schema::invalid(
                "$.node_mapping",
                "mapping topology or reason contradicts status",
            ));
        }
        Ok(Self {
            old_locators,
            new_locators,
            status,
            reason,
        })
    }
}

/// Complete `core.change-set@1` with external source and node identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeSetMessage {
    old_source_id: String,
    new_source_id: String,
    source_edits: Vec<SourceEditMessage>,
    node_mappings: Vec<NodeMappingMessage>,
    diagnostics: Vec<DiagnosticMessage>,
}

impl ChangeSetMessage {
    /// Validates source identities, edit order, and global old-locator uniqueness.
    pub fn new(
        old_source_id: impl Into<String>,
        new_source_id: impl Into<String>,
        source_edits: Vec<SourceEditMessage>,
        node_mappings: Vec<NodeMappingMessage>,
        diagnostics: Vec<DiagnosticMessage>,
    ) -> Result<Self, ProtocolError> {
        let old_source_id = old_source_id.into();
        let new_source_id = new_source_id.into();
        if old_source_id.is_empty()
            || new_source_id.is_empty()
            || old_source_id.len() > 1024
            || new_source_id.len() > 1024
        {
            return Err(crate::schema::invalid(
                "$",
                "source IDs must be non-empty and bounded",
            ));
        }
        if source_edits
            .windows(2)
            .any(|pair| pair[0].old_end > pair[1].old_start || pair[0].new_end > pair[1].new_start)
        {
            return Err(crate::schema::invalid(
                "$.source_edits",
                "edits must be ordered and non-overlapping in both snapshots",
            ));
        }
        let old_locators = node_mappings
            .iter()
            .flat_map(|mapping| mapping.old_locators.iter())
            .collect::<Vec<_>>();
        if old_locators.iter().collect::<BTreeSet<_>>().len() != old_locators.len() {
            return Err(crate::schema::invalid(
                "$.node_mappings",
                "an old locator may participate in only one mapping fact",
            ));
        }
        Ok(Self {
            old_source_id,
            new_source_id,
            source_edits,
            node_mappings,
            diagnostics,
        })
    }

    /// Externalizes an in-process ChangeSet through explicit source IDs and node binding.
    pub fn from_document(
        change_set: &ChangeSet,
        old_source_id: impl Into<String>,
        new_source_id: impl Into<String>,
        locator: impl Fn(NodeRef) -> Option<String>,
    ) -> Result<Self, ProtocolError> {
        let old_source_id = old_source_id.into();
        let new_source_id = new_source_id.into();
        let source_edits = change_set
            .source_edits()
            .iter()
            .map(|edit| {
                SourceEditMessage::new(
                    edit.old_span.start_byte() as u64,
                    edit.old_span.end_byte() as u64,
                    edit.new_span.start_byte() as u64,
                    edit.new_span.end_byte() as u64,
                    edit.replacement.to_vec(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let node_mappings = change_set
            .node_mappings()
            .iter()
            .map(|mapping| {
                let old = locator(mapping.old).ok_or_else(|| {
                    ProtocolError::new(
                        ProtocolErrorKind::ProcessLocalHandle,
                        "$.node_mappings.old",
                        "old NodeRef has no stable caller locator",
                    )
                })?;
                let new = mapping
                    .new
                    .map(|node| {
                        locator(node).ok_or_else(|| {
                            ProtocolError::new(
                                ProtocolErrorKind::ProcessLocalHandle,
                                "$.node_mappings.new",
                                "new NodeRef has no stable caller locator",
                            )
                        })
                    })
                    .transpose()?
                    .into_iter()
                    .collect();
                NodeMappingMessage::new(vec![old], new, mapping.status, mapping.reason.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let diagnostics = change_set
            .diagnostics()
            .iter()
            .map(|diagnostic| DiagnosticMessage::from_core(diagnostic, Some(&new_source_id)))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            old_source_id,
            new_source_id,
            source_edits,
            node_mappings,
            diagnostics,
        )
    }

    /// Base source ID.
    #[must_use]
    pub fn old_source_id(&self) -> &str {
        &self.old_source_id
    }

    /// Committed source ID.
    #[must_use]
    pub fn new_source_id(&self) -> &str {
        &self.new_source_id
    }

    /// Ordered source edits.
    #[must_use]
    pub fn source_edits(&self) -> &[SourceEditMessage] {
        &self.source_edits
    }

    /// Explicit node mappings.
    #[must_use]
    pub fn node_mappings(&self) -> &[NodeMappingMessage] {
        &self.node_mappings
    }

    /// Ordered operation diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticMessage] {
        &self.diagnostics
    }

    /// Encodes `core.change-set@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut edits = SequenceBuilder::new();
        for edit in &self.source_edits {
            edits.push(source_edit_value(edit));
        }
        let mut mappings = SequenceBuilder::new();
        for mapping in &self.node_mappings {
            mappings.push(node_mapping_value(mapping));
        }
        let mut diagnostics = SequenceBuilder::new();
        for diagnostic in &self.diagnostics {
            diagnostics.push(diagnostic.to_value());
        }
        object(vec![
            ("schema", PortableValue::string("core.change-set@1")),
            (
                "old_source_id",
                PortableValue::string(self.old_source_id.as_str()),
            ),
            (
                "new_source_id",
                PortableValue::string(self.new_source_id.as_str()),
            ),
            ("source_edits", edits.build()),
            ("node_mappings", mappings.build()),
            ("diagnostics", diagnostics.build()),
        ])
    }

    /// Strictly decodes `core.change-set@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.change-set@1",
            &[
                "schema",
                "old_source_id",
                "new_source_id",
                "source_edits",
                "node_mappings",
                "diagnostics",
            ],
            "$",
        )?;
        let source_edits = sequence(fields[3], "$.source_edits")?
            .iter()
            .enumerate()
            .map(|(index, edit)| parse_source_edit(edit, &format!("$.source_edits[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let node_mappings = sequence(fields[4], "$.node_mappings")?
            .iter()
            .enumerate()
            .map(|(index, mapping)| {
                parse_node_mapping(mapping, &format!("$.node_mappings[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let diagnostics = sequence(fields[5], "$.diagnostics")?
            .iter()
            .map(DiagnosticMessage::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            string(fields[1], "$.old_source_id")?,
            string(fields[2], "$.new_source_id")?,
            source_edits,
            node_mappings,
            diagnostics,
        )
    }
}

fn source_edit_value(edit: &SourceEditMessage) -> PortableValue {
    object(vec![
        ("old_start", integer_u64(edit.old_start)),
        ("old_end", integer_u64(edit.old_end)),
        ("new_start", integer_u64(edit.new_start)),
        ("new_end", integer_u64(edit.new_end)),
        (
            "replacement",
            PortableValue::bytes(edit.replacement.as_slice()),
        ),
    ])
}

fn parse_source_edit(
    value: &PortableValue,
    path: &str,
) -> Result<SourceEditMessage, ProtocolError> {
    let fields = exact_fields(
        value,
        &[
            "old_start",
            "old_end",
            "new_start",
            "new_end",
            "replacement",
        ],
        path,
    )?;
    let replacement = fields[4].as_bytes().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            format!("{path}.replacement"),
            "expected Bytes",
        )
    })?;
    SourceEditMessage::new(
        unsigned_u64(fields[0], &format!("{path}.old_start"))?,
        unsigned_u64(fields[1], &format!("{path}.old_end"))?,
        unsigned_u64(fields[2], &format!("{path}.new_start"))?,
        unsigned_u64(fields[3], &format!("{path}.new_end"))?,
        replacement.to_vec(),
    )
}

fn node_mapping_value(mapping: &NodeMappingMessage) -> PortableValue {
    let mut old_locators = SequenceBuilder::new();
    for locator in &mapping.old_locators {
        old_locators.push(PortableValue::string(locator.as_str()));
    }
    let mut new_locators = SequenceBuilder::new();
    for locator in &mapping.new_locators {
        new_locators.push(PortableValue::string(locator.as_str()));
    }
    object(vec![
        ("old_locators", old_locators.build()),
        ("new_locators", new_locators.build()),
        (
            "status",
            PortableValue::string(mapping_status_name(mapping.status)),
        ),
        ("reason", nullable_string(mapping.reason.as_deref())),
    ])
}

fn parse_node_mapping(
    value: &PortableValue,
    path: &str,
) -> Result<NodeMappingMessage, ProtocolError> {
    let fields = exact_fields(
        value,
        &["old_locators", "new_locators", "status", "reason"],
        path,
    )?;
    let old_locators = parse_locators(fields[0], &format!("{path}.old_locators"))?;
    let new_locators = parse_locators(fields[1], &format!("{path}.new_locators"))?;
    NodeMappingMessage::new(
        old_locators,
        new_locators,
        parse_mapping_status(string(fields[2], &format!("{path}.status"))?)?,
        optional_string(fields[3], &format!("{path}.reason"))?.map(str::to_owned),
    )
}

fn parse_locators(value: &PortableValue, path: &str) -> Result<Vec<String>, ProtocolError> {
    sequence(value, path)?
        .iter()
        .enumerate()
        .map(|(index, item)| string(item, &format!("{path}[{index}]")).map(str::to_owned))
        .collect()
}

const fn mapping_status_name(status: NodeMappingStatus) -> &'static str {
    match status {
        NodeMappingStatus::Preserved => "Preserved",
        NodeMappingStatus::Replaced => "Replaced",
        NodeMappingStatus::Deleted => "Deleted",
        NodeMappingStatus::Split => "Split",
        NodeMappingStatus::Merged => "Merged",
        NodeMappingStatus::Unmapped => "Unmapped",
    }
}

fn parse_mapping_status(value: &str) -> Result<NodeMappingStatus, ProtocolError> {
    match value {
        "Preserved" => Ok(NodeMappingStatus::Preserved),
        "Replaced" => Ok(NodeMappingStatus::Replaced),
        "Deleted" => Ok(NodeMappingStatus::Deleted),
        "Split" => Ok(NodeMappingStatus::Split),
        "Merged" => Ok(NodeMappingStatus::Merged),
        "Unmapped" => Ok(NodeMappingStatus::Unmapped),
        _ => Err(crate::schema::invalid(
            "$.status",
            "unknown node mapping status",
        )),
    }
}

fn unique_locators(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{BigInteger, PortableValue};
    use consema_document::ParseLimits;
    use consema_json::{EditTransactionBuilder, JsonProfile, RepresentationPolicy, parse};

    #[test]
    fn actual_json_change_set_externalizes_and_round_trips() {
        let document = parse(
            b"1".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut transaction = EditTransactionBuilder::new(&document);
        transaction.semantic_scalar(
            document.root().node_ref(),
            PortableValue::integer(BigInteger::from(2)),
            RepresentationPolicy::CanonicalForProfile,
        );
        let commit = document.commit(&transaction.build()).unwrap();
        let old_snapshot = document.snapshot_identity();
        let message = ChangeSetMessage::from_document(
            &commit.change_set,
            "source:old",
            "source:new",
            |node| {
                Some(if node.snapshot() == old_snapshot {
                    "json:root:old".to_owned()
                } else {
                    "json:root:new".to_owned()
                })
            },
        )
        .unwrap();
        assert_eq!(message.source_edits()[0].replacement, b"2");
        assert_eq!(
            ChangeSetMessage::from_value(&message.to_value()).unwrap(),
            message
        );
    }

    #[test]
    fn overlapping_edits_and_invalid_mapping_topology_fail() {
        let first = SourceEditMessage::new(0, 2, 0, 1, b"a".to_vec()).unwrap();
        let second = SourceEditMessage::new(1, 3, 1, 2, b"b".to_vec()).unwrap();
        assert!(
            ChangeSetMessage::new("old", "new", vec![first, second], Vec::new(), Vec::new())
                .is_err()
        );
        assert!(
            NodeMappingMessage::new(
                vec!["old".to_owned()],
                vec!["new".to_owned()],
                NodeMappingStatus::Deleted,
                Some("deleted".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn missing_locator_never_serializes_process_local_node() {
        let document = parse(
            b"1".as_slice(),
            JsonProfile::StrictV1,
            ParseLimits::default(),
        )
        .unwrap();
        let mut transaction = EditTransactionBuilder::new(&document);
        transaction.literal_scalar(document.root().node_ref(), b"2".as_slice());
        let commit = document.commit(&transaction.build()).unwrap();
        assert_eq!(
            ChangeSetMessage::from_document(&commit.change_set, "old", "new", |_| None,)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ProcessLocalHandle
        );
    }
}
