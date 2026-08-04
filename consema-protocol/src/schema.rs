//! Fixed-field PortableValue schema helpers.

use crate::{ProtocolError, ProtocolErrorKind};
use consema_core::{BigInteger, ObjectBuilder, PortableValue};

pub(crate) fn object(fields: Vec<(&str, PortableValue)>) -> PortableValue {
    let mut builder = ObjectBuilder::new();
    for (name, value) in fields {
        builder
            .insert(name, value)
            .expect("protocol schema fields are statically unique");
    }
    builder.build()
}

pub(crate) fn exact_fields<'a>(
    value: &'a PortableValue,
    expected: &[&str],
    path: &str,
) -> Result<Vec<&'a PortableValue>, ProtocolError> {
    let entries = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected Object"))?;
    let names = entries
        .iter()
        .map(consema_core::ObjectEntry::key)
        .collect::<Vec<_>>();
    if let Some(name) = names.iter().find(|name| !expected.contains(name)) {
        return Err(ProtocolError::new(
            ProtocolErrorKind::UnknownField,
            format!("{path}.{name}"),
            "field is not declared by the fixed schema",
        ));
    }
    if let Some(name) = expected.iter().find(|name| !names.contains(name)) {
        return Err(ProtocolError::new(
            ProtocolErrorKind::MissingField,
            format!("{path}.{name}"),
            "required field is absent",
        ));
    }
    if names != expected {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            path,
            "fields are not in canonical order",
        ));
    }
    Ok(entries
        .iter()
        .map(consema_core::ObjectEntry::value)
        .collect())
}

pub(crate) fn schema_fields<'a>(
    value: &'a PortableValue,
    schema: &str,
    expected: &[&str],
    path: &str,
) -> Result<Vec<&'a PortableValue>, ProtocolError> {
    let fields = exact_fields(value, expected, path)?;
    if string(fields[0], &format!("{path}.schema"))? != schema {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            format!("{path}.schema"),
            format!("expected {schema}"),
        ));
    }
    Ok(fields)
}

pub(crate) fn string<'a>(value: &'a PortableValue, path: &str) -> Result<&'a str, ProtocolError> {
    value
        .as_string()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected String"))
}

pub(crate) fn sequence<'a>(
    value: &'a PortableValue,
    path: &str,
) -> Result<&'a [PortableValue], ProtocolError> {
    value
        .as_sequence()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected Sequence"))
}

pub(crate) fn unsigned_u32(value: &PortableValue, path: &str) -> Result<u32, ProtocolError> {
    value
        .as_integer()
        .and_then(BigInteger::to_i64)
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorKind::InvalidValue,
                path,
                "expected an unsigned 32-bit Integer",
            )
        })
}

pub(crate) fn unsigned_u64(value: &PortableValue, path: &str) -> Result<u64, ProtocolError> {
    let integer = value.as_integer().ok_or_else(|| {
        ProtocolError::new(ProtocolErrorKind::WrongType, path, "expected Integer")
    })?;
    if integer.signum() < 0 || integer.magnitude().len() > 8 {
        return Err(ProtocolError::new(
            ProtocolErrorKind::InvalidValue,
            path,
            "expected an unsigned 64-bit Integer",
        ));
    }
    Ok(integer
        .magnitude()
        .iter()
        .fold(0_u64, |result, byte| (result << 8) | u64::from(*byte)))
}

pub(crate) fn integer_u64(value: u64) -> PortableValue {
    let bytes = value.to_be_bytes();
    PortableValue::integer(
        BigInteger::from_sign_and_magnitude(i8::from(value != 0), &bytes)
            .expect("u64 has a valid canonical magnitude"),
    )
}

pub(crate) fn nullable_string(value: Option<&str>) -> PortableValue {
    value.map_or_else(PortableValue::null, PortableValue::string)
}

pub(crate) fn optional_string<'a>(
    value: &'a PortableValue,
    path: &str,
) -> Result<Option<&'a str>, ProtocolError> {
    if value == &PortableValue::null() {
        Ok(None)
    } else {
        string(value, path).map(Some)
    }
}

pub(crate) fn invalid(path: &str, detail: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, detail)
}
