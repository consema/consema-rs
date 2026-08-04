//! Audited two-stage conversion report wire contract.

use crate::schema::{object, schema_fields, string};
use crate::{
    LossClassification, MaterializationReportMessage, ProjectionReportMessage, ProtocolError,
};
use consema_core::PortableValue;
use consema_document::{MaterializationFidelity, ProfileId};

/// Whole-conversion semantic fidelity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConversionFidelityMessage {
    /// Both stages retain exact portable semantics.
    Exact,
    /// At least one stage performs an authorized reversible transformation.
    Transformed,
    /// Projection contains explicitly authorized irreversible loss.
    Lossy,
}

/// Transferable `core.conversion-report@1` with both stages intact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionReportMessage {
    source_profile: ProfileId,
    target_profile: ProfileId,
    projection_fidelity: ConversionFidelityMessage,
    projection_report: ProjectionReportMessage,
    materialization_fidelity: MaterializationFidelity,
    materialization_report: MaterializationReportMessage,
    overall_fidelity: ConversionFidelityMessage,
}

impl ConversionReportMessage {
    /// Validates stage fidelity against complete reports and recomputes the overall result.
    pub fn new(
        source_profile: ProfileId,
        target_profile: ProfileId,
        projection_fidelity: ConversionFidelityMessage,
        projection_report: ProjectionReportMessage,
        materialization_fidelity: MaterializationFidelity,
        materialization_report: MaterializationReportMessage,
        overall_fidelity: ConversionFidelityMessage,
    ) -> Result<Self, ProtocolError> {
        let has_reversible = projection_report
            .events()
            .iter()
            .any(|event| event.loss_classification == LossClassification::Reversible);
        let has_loss = projection_report
            .events()
            .iter()
            .any(|event| event.loss_classification == LossClassification::Lossy);
        let projection_valid = match projection_fidelity {
            ConversionFidelityMessage::Exact => !has_reversible && !has_loss,
            ConversionFidelityMessage::Transformed => has_reversible && !has_loss,
            ConversionFidelityMessage::Lossy => has_loss,
        };
        if !projection_valid {
            return Err(crate::schema::invalid(
                "$.projection_report",
                "projection fidelity contradicts its complete event report",
            ));
        }

        let has_materialization_transform = materialization_report
            .events()
            .iter()
            .any(|event| event.code == "core.materialization.mapping-transformed@1");
        if (materialization_fidelity == MaterializationFidelity::Transformed)
            != has_materialization_transform
        {
            return Err(crate::schema::invalid(
                "$.materialization_report",
                "materialization fidelity contradicts its complete event report",
            ));
        }

        let materialization_overall = match materialization_fidelity {
            MaterializationFidelity::Exact => ConversionFidelityMessage::Exact,
            MaterializationFidelity::Transformed => ConversionFidelityMessage::Transformed,
        };
        if overall_fidelity != projection_fidelity.max(materialization_overall) {
            return Err(crate::schema::invalid(
                "$.overall_fidelity",
                "overall fidelity is not the worst complete stage fidelity",
            ));
        }

        Ok(Self {
            source_profile,
            target_profile,
            projection_fidelity,
            projection_report,
            materialization_fidelity,
            materialization_report,
            overall_fidelity,
        })
    }

    /// Exact source Profile.
    #[must_use]
    pub const fn source_profile(&self) -> &ProfileId {
        &self.source_profile
    }

    /// Exact target Profile.
    #[must_use]
    pub const fn target_profile(&self) -> &ProfileId {
        &self.target_profile
    }

    /// Projection-stage fidelity.
    #[must_use]
    pub const fn projection_fidelity(&self) -> ConversionFidelityMessage {
        self.projection_fidelity
    }

    /// Complete ordered projection report.
    #[must_use]
    pub const fn projection_report(&self) -> &ProjectionReportMessage {
        &self.projection_report
    }

    /// Materialization-stage fidelity.
    #[must_use]
    pub const fn materialization_fidelity(&self) -> MaterializationFidelity {
        self.materialization_fidelity
    }

    /// Complete ordered materialization report.
    #[must_use]
    pub const fn materialization_report(&self) -> &MaterializationReportMessage {
        &self.materialization_report
    }

    /// Worst fidelity across both stages.
    #[must_use]
    pub const fn overall_fidelity(&self) -> ConversionFidelityMessage {
        self.overall_fidelity
    }

    /// Encodes the fixed two-stage report schema.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        object(vec![
            ("schema", PortableValue::string("core.conversion-report@1")),
            ("source_profile", profile_value(&self.source_profile)),
            ("target_profile", profile_value(&self.target_profile)),
            (
                "projection_fidelity",
                PortableValue::string(fidelity_name(self.projection_fidelity)),
            ),
            ("projection_report", self.projection_report.to_value()),
            (
                "materialization_fidelity",
                PortableValue::string(materialization_fidelity_name(self.materialization_fidelity)),
            ),
            (
                "materialization_report",
                self.materialization_report.to_value(),
            ),
            (
                "overall_fidelity",
                PortableValue::string(fidelity_name(self.overall_fidelity)),
            ),
        ])
    }

    /// Strictly decodes and revalidates both report stages.
    pub fn from_value(value: &PortableValue) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.conversion-report@1",
            &[
                "schema",
                "source_profile",
                "target_profile",
                "projection_fidelity",
                "projection_report",
                "materialization_fidelity",
                "materialization_report",
                "overall_fidelity",
            ],
            "$",
        )?;
        Self::new(
            parse_profile(fields[1], "$.source_profile")?,
            parse_profile(fields[2], "$.target_profile")?,
            parse_fidelity(
                string(fields[3], "$.projection_fidelity")?,
                "$.projection_fidelity",
            )?,
            ProjectionReportMessage::from_value(fields[4])?,
            parse_materialization_fidelity(string(fields[5], "$.materialization_fidelity")?)?,
            MaterializationReportMessage::from_value(fields[6])?,
            parse_fidelity(
                string(fields[7], "$.overall_fidelity")?,
                "$.overall_fidelity",
            )?,
        )
    }
}

fn profile_value(profile: &ProfileId) -> PortableValue {
    object(vec![
        ("id", PortableValue::string(profile.id())),
        (
            "version",
            PortableValue::integer(consema_core::BigInteger::from(i64::from(profile.version()))),
        ),
    ])
}

fn parse_profile(value: &PortableValue, path: &str) -> Result<ProfileId, ProtocolError> {
    let fields = crate::schema::exact_fields(value, &["id", "version"], path)?;
    let id = string(fields[0], &format!("{path}.id"))?;
    let version = crate::schema::unsigned_u32(fields[1], &format!("{path}.version"))?;
    let reference = crate::ProfileReference::new(id, version)?;
    Ok(ProfileId::new(reference.id(), reference.version()))
}

const fn fidelity_name(fidelity: ConversionFidelityMessage) -> &'static str {
    match fidelity {
        ConversionFidelityMessage::Exact => "Exact",
        ConversionFidelityMessage::Transformed => "Transformed",
        ConversionFidelityMessage::Lossy => "Lossy",
    }
}

fn parse_fidelity(value: &str, path: &str) -> Result<ConversionFidelityMessage, ProtocolError> {
    match value {
        "Exact" => Ok(ConversionFidelityMessage::Exact),
        "Transformed" => Ok(ConversionFidelityMessage::Transformed),
        "Lossy" => Ok(ConversionFidelityMessage::Lossy),
        _ => Err(crate::schema::invalid(path, "unknown conversion fidelity")),
    }
}

const fn materialization_fidelity_name(fidelity: MaterializationFidelity) -> &'static str {
    match fidelity {
        MaterializationFidelity::Exact => "Exact",
        MaterializationFidelity::Transformed => "Transformed",
    }
}

fn parse_materialization_fidelity(value: &str) -> Result<MaterializationFidelity, ProtocolError> {
    match value {
        "Exact" => Ok(MaterializationFidelity::Exact),
        "Transformed" => Ok(MaterializationFidelity::Transformed),
        _ => Err(crate::schema::invalid(
            "$.materialization_fidelity",
            "unknown materialization fidelity",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_two_stage_report_round_trips() {
        let report = ConversionReportMessage::new(
            ProfileId::new("toml.1.0", 1),
            ProfileId::new("json.strict", 1),
            ConversionFidelityMessage::Exact,
            ProjectionReportMessage::default(),
            MaterializationFidelity::Exact,
            MaterializationReportMessage::default(),
            ConversionFidelityMessage::Exact,
        )
        .unwrap();
        assert_eq!(
            ConversionReportMessage::from_value(&report.to_value()).unwrap(),
            report
        );
    }

    #[test]
    fn overall_fidelity_cannot_hide_a_worse_stage() {
        assert!(
            ConversionReportMessage::new(
                ProfileId::new("toml.1.0", 1),
                ProfileId::new("json.strict", 1),
                ConversionFidelityMessage::Exact,
                ProjectionReportMessage::default(),
                MaterializationFidelity::Exact,
                MaterializationReportMessage::default(),
                ConversionFidelityMessage::Transformed,
            )
            .is_err()
        );
    }
}
