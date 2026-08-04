//! Transferable dry-run facts for one fully validated edit transaction.

use crate::{
    ContentDigest, FormatOperationId, ProfileId, SourcePatch, SourcePatchRedactionError,
    SourceReplacement,
};
use consema_core::Diagnostic;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// Caller-stable source identity used by a transferable edit plan.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EditPlanSourceId(Arc<str>);

impl EditPlanSourceId {
    /// Validates one non-empty bounded external source identity.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, EditPlanError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 {
            return Err(EditPlanError::InvalidSourceId);
        }
        Ok(Self(value))
    }

    /// Exact caller-stable source identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One safe, content-free summary of a declared edit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditOperationSummary {
    operation: FormatOperationId,
    arguments: BTreeMap<String, String>,
}

impl EditOperationSummary {
    /// Validates a bounded summary that must not contain raw edited values.
    pub fn new(
        operation: FormatOperationId,
        arguments: BTreeMap<String, String>,
    ) -> Result<Self, EditPlanError> {
        if arguments.len() > 64
            || arguments.iter().any(|(name, value)| {
                !valid_summary_name(name) || value.is_empty() || value.len() > 1024
            })
        {
            return Err(EditPlanError::InvalidOperationSummary);
        }
        Ok(Self {
            operation,
            arguments,
        })
    }

    /// Exact immutable operation ID/version.
    #[must_use]
    pub const fn operation(&self) -> &FormatOperationId {
        &self.operation
    }

    /// Stable sorted safe summary fields.
    #[must_use]
    pub const fn arguments(&self) -> &BTreeMap<String, String> {
        &self.arguments
    }
}

/// Fully validated dry-run plan; possessing it does not authorize a write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditPlan {
    source_id: EditPlanSourceId,
    profile: ProfileId,
    operations: Arc<[EditOperationSummary]>,
    patch: SourcePatch,
    report: Arc<[Diagnostic]>,
}

impl EditPlan {
    /// Closes a plan only when its ordered operation metadata matches its exact patch.
    pub fn new(
        source_id: EditPlanSourceId,
        profile: ProfileId,
        operations: Vec<EditOperationSummary>,
        patch: SourcePatch,
        report: Vec<Diagnostic>,
    ) -> Result<Self, EditPlanError> {
        for (index, operation) in operations.iter().enumerate() {
            let key = format!("operation.{index}");
            if patch.metadata().get(&key).map(String::as_str)
                != Some(operation.operation().to_string().as_str())
            {
                return Err(EditPlanError::OperationMetadataMismatch { index });
            }
        }
        if patch
            .metadata()
            .keys()
            .any(|key| key.strip_prefix("operation.").is_some())
            && patch
                .metadata()
                .keys()
                .filter(|key| key.strip_prefix("operation.").is_some())
                .count()
                != operations.len()
        {
            return Err(EditPlanError::OperationMetadataMismatch {
                index: operations.len(),
            });
        }
        Ok(Self {
            source_id,
            profile,
            operations: Arc::from(operations),
            patch,
            report: Arc::from(report),
        })
    }

    /// Caller-stable source identity.
    #[must_use]
    pub const fn source_id(&self) -> &EditPlanSourceId {
        &self.source_id
    }

    /// Required base content identity.
    #[must_use]
    pub const fn base_digest(&self) -> ContentDigest {
        self.patch.base_digest()
    }

    /// Exact profile under which the target was validated.
    #[must_use]
    pub const fn profile(&self) -> &ProfileId {
        &self.profile
    }

    /// Ordered declared operations with content-free summaries.
    #[must_use]
    pub fn operations(&self) -> &[EditOperationSummary] {
        &self.operations
    }

    /// Exact replacement facts, including review redaction flags.
    #[must_use]
    pub fn replacements(&self) -> &[SourceReplacement] {
        self.patch.replacements()
    }

    /// Precomputed exact target content identity.
    #[must_use]
    pub const fn target_digest(&self) -> ContentDigest {
        self.patch.target_digest()
    }

    /// Complete ordered edit report.
    #[must_use]
    pub fn report(&self) -> &[Diagnostic] {
        &self.report
    }

    /// Underlying patch whose application rechecks digest and every original-byte precondition.
    #[must_use]
    pub const fn source_patch(&self) -> &SourcePatch {
        &self.patch
    }

    /// Redacts every original/replacement payload from review/debug presentation.
    ///
    /// This does not remove bytes required to apply and verify the plan's SourcePatch.
    pub fn with_all_replacements_redacted(
        mut self,
        redact_original: bool,
        redact_replacement: bool,
    ) -> Result<Self, SourcePatchRedactionError> {
        self.patch = self
            .patch
            .with_all_replacements_redacted(redact_original, redact_replacement)?;
        Ok(self)
    }

    /// Redacts one exact replacement from review/debug presentation.
    pub fn with_replacement_redacted(
        mut self,
        index: usize,
        redact_original: bool,
        redact_replacement: bool,
    ) -> Result<Self, SourcePatchRedactionError> {
        self.patch =
            self.patch
                .with_replacement_redacted(index, redact_original, redact_replacement)?;
        Ok(self)
    }
}

/// Edit-plan construction failure before a transferable plan exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditPlanError {
    /// External source identity is empty or exceeds the frozen bound.
    InvalidSourceId,
    /// A summary key/value is invalid or exceeds its frozen bound.
    InvalidOperationSummary,
    /// Operation ordering disagrees with the exact SourcePatch metadata.
    OperationMetadataMismatch {
        /// First mismatching operation index.
        index: usize,
    },
}

impl Display for EditPlanError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for EditPlanError {}

fn valid_summary_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncodingRequest, SourceEncoding, SourceLimits, SourcePatchLimits, SourceSnapshot};

    #[test]
    fn plan_requires_stable_source_and_matching_operation_metadata() {
        assert_eq!(
            EditPlanSourceId::new(""),
            Err(EditPlanError::InvalidSourceId)
        );
        let source = SourceSnapshot::from_raw(
            b"a".as_slice(),
            EncodingRequest::new(SourceEncoding::Utf8),
            SourceLimits::default(),
        )
        .unwrap();
        let patch = SourcePatch::create(
            &source,
            Vec::new(),
            BTreeMap::from([(
                "operation.0".to_owned(),
                "json.edit.remove-member@1".to_owned(),
            )]),
            SourcePatchLimits::default(),
        )
        .unwrap();
        let summary = EditOperationSummary::new(
            FormatOperationId::new("json.edit.remove-member", 1),
            BTreeMap::from([("target_role".to_owned(), "json.object-member@1".to_owned())]),
        )
        .unwrap();
        let plan = EditPlan::new(
            EditPlanSourceId::new("config.json").unwrap(),
            ProfileId::new("json.strict", 1),
            vec![summary],
            patch,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(plan.source_id().as_str(), "config.json");
        assert_eq!(plan.base_digest(), plan.target_digest());
        assert!(plan.replacements().is_empty());
    }
}
