//! Exact Java UTF-16 code-unit strings.

use crate::schema::{object, schema_fields, sequence, string};
use crate::{ProtocolError, ProtocolErrorKind, ProtocolLimits};
use consema_core::{PortableValue, SequenceBuilder};
use std::sync::Arc;

/// Whether an exact Java UTF-16 string is also well-formed Unicode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JavaUnicodeStatus {
    /// Every surrogate is part of one adjacent high/low pair.
    WellFormedUnicode,
    /// At least one surrogate code unit is unpaired.
    UnpairedSurrogate,
}

/// Exact Java string content transported as canonical big-endian UTF-16 units.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaUtf16String {
    code_units: Arc<[u16]>,
    bytes: Arc<[u8]>,
    unicode_status: JavaUnicodeStatus,
}

impl JavaUtf16String {
    /// Builds an exact string while enforcing the same limits as wire decoding.
    pub fn new(
        code_units: impl Into<Vec<u16>>,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        let code_units = code_units.into();
        check_unit_count(code_units.len(), limits)?;
        let byte_len = code_units
            .len()
            .checked_mul(2)
            .ok_or_else(|| resource("$.bytes", "UTF-16 byte length overflows usize"))?;
        if byte_len > limits.max_blob_bytes {
            return Err(resource(
                "$.bytes",
                "UTF-16 bytes exceed the configured blob limit",
            ));
        }
        let mut bytes = Vec::with_capacity(byte_len);
        for unit in &code_units {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Ok(Self {
            unicode_status: classify(&code_units),
            code_units: code_units.into(),
            bytes: bytes.into(),
        })
    }

    /// Exact ordered UTF-16 code units.
    #[must_use]
    pub fn code_units(&self) -> &[u16] {
        &self.code_units
    }

    /// The same units as BOM-free, big-endian bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Recomputed Unicode well-formedness classification.
    #[must_use]
    pub const fn unicode_status(&self) -> JavaUnicodeStatus {
        self.unicode_status
    }

    /// Encodes `core.java-utf16-string@1` in canonical field order.
    #[must_use]
    pub fn to_value(&self) -> PortableValue {
        let mut units = SequenceBuilder::new();
        for unit in &*self.code_units {
            units.push(PortableValue::string(format!("{unit:04X}")));
        }
        object(vec![
            ("schema", PortableValue::string("core.java-utf16-string@1")),
            ("encoding", PortableValue::string("UTF16BE/1")),
            ("code_units", units.build()),
            ("bytes", PortableValue::bytes(self.bytes.as_ref())),
            (
                "unicode_status",
                PortableValue::string(status_name(self.unicode_status)),
            ),
        ])
    }

    /// Strictly decodes and canonically re-verifies one exact Java string.
    pub fn from_value(
        value: &PortableValue,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        let fields = schema_fields(
            value,
            "core.java-utf16-string@1",
            &[
                "schema",
                "encoding",
                "code_units",
                "bytes",
                "unicode_status",
            ],
            "$",
        )?;
        if string(fields[1], "$.encoding")? != "UTF16BE/1" {
            return Err(invalid("$.encoding", "expected exact encoding UTF16BE/1"));
        }
        let encoded_units = sequence(fields[2], "$.code_units")?;
        check_unit_count(encoded_units.len(), limits)?;
        let bytes = fields[3]
            .as_bytes()
            .ok_or_else(|| wrong_type("$.bytes", "expected Bytes"))?;
        if bytes.len() > limits.max_blob_bytes {
            return Err(resource(
                "$.bytes",
                "UTF-16 bytes exceed the configured blob limit",
            ));
        }
        if bytes.len() % 2 != 0 {
            return Err(invalid("$.bytes", "UTF-16 byte length must be even"));
        }
        let expected_bytes = encoded_units
            .len()
            .checked_mul(2)
            .ok_or_else(|| resource("$.bytes", "UTF-16 byte length overflows usize"))?;
        if bytes.len() != expected_bytes {
            return Err(invalid(
                "$.bytes",
                "byte count does not equal two bytes per code unit",
            ));
        }

        let mut code_units = Vec::with_capacity(encoded_units.len());
        for (index, encoded) in encoded_units.iter().enumerate() {
            let path = format!("$.code_units[{index}]");
            let text = string(encoded, &path)?;
            let unit = parse_unit(text).ok_or_else(|| {
                invalid(
                    &path,
                    "code unit must be exactly four uppercase hexadecimal digits",
                )
            })?;
            let offset = index * 2;
            if unit.to_be_bytes() != bytes[offset..offset + 2] {
                return Err(invalid(&path, "code unit and byte representation differ"));
            }
            code_units.push(unit);
        }

        let status = parse_status(string(fields[4], "$.unicode_status")?)?;
        let decoded = Self::new(code_units, limits)?;
        if decoded.unicode_status != status {
            return Err(invalid(
                "$.unicode_status",
                "status does not match exact surrogate pairing",
            ));
        }
        if decoded.to_value() != *value {
            return Err(invalid(
                "$",
                "Java UTF-16 string is not canonically encoded",
            ));
        }
        Ok(decoded)
    }
}

fn check_unit_count(count: usize, limits: ProtocolLimits) -> Result<(), ProtocolError> {
    if count > limits.max_container_entries {
        return Err(resource(
            "$.code_units",
            "code-unit count exceeds the configured container limit",
        ));
    }
    Ok(())
}

fn parse_unit(value: &str) -> Option<u16> {
    if value.len() != 4
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return None;
    }
    u16::from_str_radix(value, 16).ok()
}

fn classify(units: &[u16]) -> JavaUnicodeStatus {
    let mut index = 0;
    while index < units.len() {
        match units[index] {
            0xD800..=0xDBFF
                if units
                    .get(index + 1)
                    .is_some_and(|next| (0xDC00..=0xDFFF).contains(next)) =>
            {
                index += 2;
            }
            0xD800..=0xDFFF => return JavaUnicodeStatus::UnpairedSurrogate,
            _ => index += 1,
        }
    }
    JavaUnicodeStatus::WellFormedUnicode
}

const fn status_name(status: JavaUnicodeStatus) -> &'static str {
    match status {
        JavaUnicodeStatus::WellFormedUnicode => "WellFormedUnicode",
        JavaUnicodeStatus::UnpairedSurrogate => "UnpairedSurrogate",
    }
}

fn parse_status(value: &str) -> Result<JavaUnicodeStatus, ProtocolError> {
    match value {
        "WellFormedUnicode" => Ok(JavaUnicodeStatus::WellFormedUnicode),
        "UnpairedSurrogate" => Ok(JavaUnicodeStatus::UnpairedSurrogate),
        _ => Err(invalid("$.unicode_status", "unknown Unicode status")),
    }
}

fn invalid(path: impl Into<String>, detail: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, detail)
}

fn resource(path: impl Into<String>, detail: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::ResourceLimit, path, detail)
}

fn wrong_type(path: impl Into<String>, detail: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::WrongType, path, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_java_utf16_shape_round_trips_exactly() {
        let cases = [
            (vec![], JavaUnicodeStatus::WellFormedUnicode),
            (
                vec![0x0000, 0x0041, 0xFFFF],
                JavaUnicodeStatus::WellFormedUnicode,
            ),
            (vec![0xD83D, 0xDE00], JavaUnicodeStatus::WellFormedUnicode),
            (vec![0xDC00], JavaUnicodeStatus::UnpairedSurrogate),
            (vec![0xD800], JavaUnicodeStatus::UnpairedSurrogate),
            (
                vec![0xD800, 0xD801, 0xDC00],
                JavaUnicodeStatus::UnpairedSurrogate,
            ),
            (
                vec![0xD800, 0xDC00, 0xDC01],
                JavaUnicodeStatus::UnpairedSurrogate,
            ),
        ];
        for (units, status) in cases {
            let exact = JavaUtf16String::new(units, ProtocolLimits::default()).unwrap();
            assert_eq!(exact.unicode_status(), status);
            assert_eq!(
                JavaUtf16String::from_value(&exact.to_value(), ProtocolLimits::default()).unwrap(),
                exact
            );
        }
    }

    #[test]
    fn noncanonical_units_mismatched_bytes_and_status_fail() {
        let lowercase = wire("00af", &[0x00, 0xAF], "WellFormedUnicode");
        assert_eq!(
            JavaUtf16String::from_value(&lowercase, ProtocolLimits::default())
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::InvalidValue
        );

        let mismatch = wire("0041", &[0x00, 0x42], "WellFormedUnicode");
        assert_eq!(
            JavaUtf16String::from_value(&mismatch, ProtocolLimits::default())
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::InvalidValue
        );

        let wrong_status = wire("D800", &[0xD8, 0x00], "WellFormedUnicode");
        assert_eq!(
            JavaUtf16String::from_value(&wrong_status, ProtocolLimits::default())
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::InvalidValue
        );
    }

    #[test]
    fn odd_bytes_and_preallocation_limits_fail() {
        let odd = wire("0041", &[0x00], "WellFormedUnicode");
        assert_eq!(
            JavaUtf16String::from_value(&odd, ProtocolLimits::default())
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::InvalidValue
        );

        let limited = ProtocolLimits {
            max_container_entries: 0,
            ..ProtocolLimits::default()
        };
        let value = wire("0041", &[0x00, 0x41], "WellFormedUnicode");
        assert_eq!(
            JavaUtf16String::from_value(&value, limited)
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::ResourceLimit
        );
    }

    fn wire(unit: &str, bytes: &[u8], status: &str) -> PortableValue {
        let mut units = SequenceBuilder::new();
        units.push(PortableValue::string(unit));
        object(vec![
            ("schema", PortableValue::string("core.java-utf16-string@1")),
            ("encoding", PortableValue::string("UTF16BE/1")),
            ("code_units", units.build()),
            ("bytes", PortableValue::bytes(bytes)),
            ("unicode_status", PortableValue::string(status)),
        ])
    }
}
