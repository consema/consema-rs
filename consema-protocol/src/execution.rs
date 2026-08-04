//! Resource, cancellation, and completion protocols.

use crate::schema::{
    integer_u64, nullable_string, object, optional_string, schema_fields, string, unsigned_u64,
};
use crate::{ErrorCodeRegistry, ProtocolError};
use consema_core::{ObjectBuilder, OperationStatus, PortableValue};
use std::collections::BTreeMap;

/// Closed language-neutral completion state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompletionStatus {
    /// Complete result is available.
    Success,
    /// Operation failed.
    Failed,
    /// Caller cancelled execution.
    Cancelled,
    /// A declared limit stopped execution.
    ResourceLimited,
    /// Implementation does not support the request.
    Unsupported,
    /// Request does not apply to the target.
    NotApplicable,
}

impl From<OperationStatus> for CompletionStatus {
    fn from(value: OperationStatus) -> Self {
        match value {
            OperationStatus::Success => Self::Success,
            OperationStatus::Failed => Self::Failed,
            OperationStatus::Cancelled => Self::Cancelled,
            OperationStatus::ResourceLimited => Self::ResourceLimited,
            OperationStatus::Unsupported => Self::Unsupported,
            OperationStatus::NotApplicable => Self::NotApplicable,
        }
    }
}

/// `core.completion@1` control-flow facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    status: CompletionStatus,
    processed: u64,
    produced: u64,
    limit_name: Option<String>,
    failure_code: Option<String>,
}

impl Completion {
    /// Validates state-specific completion invariants.
    pub fn new(
        status: CompletionStatus,
        processed: u64,
        produced: u64,
        limit_name: Option<String>,
        failure_code: Option<String>,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_registry(
            status,
            processed,
            produced,
            limit_name,
            failure_code,
            ErrorCodeRegistry::v1(),
        )
    }

    /// Validates completion facts against one explicit semantic-model registry.
    pub fn new_with_registry(
        status: CompletionStatus,
        processed: u64,
        produced: u64,
        limit_name: Option<String>,
        failure_code: Option<String>,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        if let Some(code) = failure_code.as_deref() {
            registry.validate_at(code, "$.failure_code")?;
        }
        let valid = match status {
            CompletionStatus::Success | CompletionStatus::Cancelled => {
                limit_name.is_none() && failure_code.is_none()
            }
            CompletionStatus::ResourceLimited => {
                limit_name.as_ref().is_some_and(|name| !name.is_empty()) && failure_code.is_none()
            }
            CompletionStatus::Failed
            | CompletionStatus::Unsupported
            | CompletionStatus::NotApplicable => {
                limit_name.is_none() && failure_code.as_ref().is_some_and(|code| !code.is_empty())
            }
        };
        if !valid {
            return Err(crate::schema::invalid(
                "$",
                "completion status contradicts limit/failure fields",
            ));
        }
        Ok(Self {
            status,
            processed,
            produced,
            limit_name,
            failure_code,
        })
    }

    /// Completion state.
    #[must_use]
    pub const fn status(&self) -> CompletionStatus {
        self.status
    }

    /// Work items consumed before terminal state.
    #[must_use]
    pub const fn processed(&self) -> u64 {
        self.processed
    }

    /// Complete or locally discovered output count.
    #[must_use]
    pub const fn produced(&self) -> u64 {
        self.produced
    }

    /// Limit that stopped execution.
    #[must_use]
    pub fn limit_name(&self) -> Option<&str> {
        self.limit_name.as_deref()
    }

    /// Stable terminal failure code.
    #[must_use]
    pub fn failure_code(&self) -> Option<&str> {
        self.failure_code.as_deref()
    }

    /// Encodes `core.completion@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        object(vec![
            ("schema", PortableValue::string("core.completion@1")),
            ("status", PortableValue::string(status_name(self.status))),
            ("processed", integer_u64(self.processed)),
            ("produced", integer_u64(self.produced)),
            ("limit_name", nullable_string(self.limit_name.as_deref())),
            (
                "failure_code",
                nullable_string(self.failure_code.as_deref()),
            ),
        ])
    }

    /// Strictly decodes `core.completion@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        Self::from_value_with_registry(value, ErrorCodeRegistry::v1())
    }

    /// Strictly decodes under one explicit semantic-model registry.
    pub fn from_value_with_registry(
        value: &PortableValue,
        registry: ErrorCodeRegistry,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.completion@1",
            &[
                "schema",
                "status",
                "processed",
                "produced",
                "limit_name",
                "failure_code",
            ],
            "$",
        )?;
        Self::new_with_registry(
            parse_status(string(fields[1], "$.status")?)?,
            unsigned_u64(fields[2], "$.processed")?,
            unsigned_u64(fields[3], "$.produced")?,
            optional_string(fields[4], "$.limit_name")?.map(str::to_owned),
            optional_string(fields[5], "$.failure_code")?.map(str::to_owned),
            registry,
        )
    }
}

/// Transferable bounded execution policy. Cancellation tokens remain process-local.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPolicy {
    limits: BTreeMap<String, u64>,
    cancellation_request_id: Option<String>,
}

impl ExecutionPolicy {
    /// Creates a policy with deterministically sorted unique limit names.
    pub fn new(
        limits: BTreeMap<String, u64>,
        cancellation_request_id: Option<String>,
    ) -> Result<Self, ProtocolError> {
        if limits.keys().any(|name| !valid_name(name)) {
            return Err(crate::schema::invalid(
                "$.limits",
                "limit names must be stable lowercase identifiers",
            ));
        }
        if cancellation_request_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 1024)
        {
            return Err(crate::schema::invalid(
                "$.cancellation_request_id",
                "invalid cancellation request ID",
            ));
        }
        Ok(Self {
            limits,
            cancellation_request_id,
        })
    }

    /// Named limits sorted by key.
    #[must_use]
    pub const fn limits(&self) -> &BTreeMap<String, u64> {
        &self.limits
    }

    /// Optional outer-transport cancellation request ID.
    #[must_use]
    pub fn cancellation_request_id(&self) -> Option<&str> {
        self.cancellation_request_id.as_deref()
    }

    /// Encodes `core.execution-policy@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut limits = ObjectBuilder::new();
        for (name, value) in &self.limits {
            limits
                .insert(name, integer_u64(*value))
                .expect("BTreeMap limit names are unique");
        }
        object(vec![
            ("schema", PortableValue::string("core.execution-policy@1")),
            ("limits", limits.build()),
            (
                "cancellation_request_id",
                nullable_string(self.cancellation_request_id.as_deref()),
            ),
        ])
    }

    /// Strictly decodes `core.execution-policy@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.execution-policy@1",
            &["schema", "limits", "cancellation_request_id"],
            "$",
        )?;
        let entries = fields[1].as_object().ok_or_else(|| {
            crate::schema::invalid("$.limits", "expected Object<String, Integer>")
        })?;
        let mut limits = BTreeMap::new();
        for entry in entries {
            limits.insert(
                entry.key().to_owned(),
                unsigned_u64(entry.value(), &format!("$.limits.{}", entry.key()))?,
            );
        }
        Self::new(
            limits,
            optional_string(fields[2], "$.cancellation_request_id")?.map(str::to_owned),
        )
    }
}

/// Idempotent outer-transport cancellation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationRequest {
    request_id: String,
    reason: Option<String>,
}

impl CancellationRequest {
    /// Creates a request; this is not a serialized CancellationToken.
    pub fn new(
        request_id: impl Into<String>,
        reason: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let request_id = request_id.into();
        if request_id.is_empty() || request_id.len() > 1024 {
            return Err(crate::schema::invalid("$.request_id", "invalid request ID"));
        }
        Ok(Self { request_id, reason })
    }

    /// Transport request ID.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Optional stable reason or operator note.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Encodes `core.cancellation-request@1`.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        object(vec![
            (
                "schema",
                PortableValue::string("core.cancellation-request@1"),
            ),
            (
                "request_id",
                PortableValue::string(self.request_id.as_str()),
            ),
            ("reason", nullable_string(self.reason.as_deref())),
        ])
    }

    /// Strictly decodes `core.cancellation-request@1`.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.cancellation-request@1",
            &["schema", "request_id", "reason"],
            "$",
        )?;
        Self::new(
            string(fields[1], "$.request_id")?,
            optional_string(fields[2], "$.reason")?.map(str::to_owned),
        )
    }
}

const fn status_name(status: CompletionStatus) -> &'static str {
    match status {
        CompletionStatus::Success => "Success",
        CompletionStatus::Failed => "Failed",
        CompletionStatus::Cancelled => "Cancelled",
        CompletionStatus::ResourceLimited => "ResourceLimited",
        CompletionStatus::Unsupported => "Unsupported",
        CompletionStatus::NotApplicable => "NotApplicable",
    }
}

fn parse_status(value: &str) -> Result<CompletionStatus, ProtocolError> {
    match value {
        "Success" => Ok(CompletionStatus::Success),
        "Failed" => Ok(CompletionStatus::Failed),
        "Cancelled" => Ok(CompletionStatus::Cancelled),
        "ResourceLimited" => Ok(CompletionStatus::ResourceLimited),
        "Unsupported" => Ok(CompletionStatus::Unsupported),
        "NotApplicable" => Ok(CompletionStatus::NotApplicable),
        _ => Err(crate::schema::invalid(
            "$.status",
            "unknown completion status",
        )),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_rejects_contradictory_states() {
        assert!(
            Completion::new(
                CompletionStatus::Success,
                1,
                1,
                Some("max_steps".to_owned()),
                None,
            )
            .is_err()
        );
        let completion = Completion::new(
            CompletionStatus::ResourceLimited,
            5,
            2,
            Some("max_steps".to_owned()),
            None,
        )
        .unwrap();
        assert_eq!(
            Completion::from_value(&completion.to_value()).unwrap(),
            completion
        );
        assert!(
            Completion::new(
                CompletionStatus::Failed,
                1,
                0,
                None,
                Some("example.failure@1".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn selected_registry_controls_new_nested_failure_codes() {
        let code = "yaml.parse.syntax@1".to_owned();
        assert!(
            Completion::new(CompletionStatus::Failed, 1, 0, None, Some(code.clone()),).is_err()
        );
        let completion = Completion::new_with_registry(
            CompletionStatus::Failed,
            1,
            0,
            None,
            Some(code),
            ErrorCodeRegistry::v5(),
        )
        .unwrap();
        assert!(Completion::from_value(&completion.to_value()).is_err());
        assert_eq!(
            Completion::from_value_with_registry(&completion.to_value(), ErrorCodeRegistry::v5(),)
                .unwrap(),
            completion
        );

        let contract = crate::ContractId::new("core.completion", 1).unwrap();
        assert!(
            crate::ProtocolMessage::new(
                contract.clone(),
                completion.to_value(),
                crate::ContractRegistry::v4(),
            )
            .is_err()
        );
        crate::ProtocolMessage::new(
            contract,
            completion.to_value(),
            crate::ContractRegistry::v5(),
        )
        .unwrap();
    }

    #[test]
    fn execution_and_cancellation_round_trip_without_serializing_tokens() {
        let policy = ExecutionPolicy::new(
            BTreeMap::from([("max_steps".to_owned(), 100)]),
            Some("request-1".to_owned()),
        )
        .unwrap();
        assert_eq!(
            ExecutionPolicy::from_value(&policy.to_value()).unwrap(),
            policy
        );
        let request = CancellationRequest::new("request-1", Some("caller".to_owned())).unwrap();
        assert_eq!(
            CancellationRequest::from_value(&request.to_value()).unwrap(),
            request
        );
    }
}
