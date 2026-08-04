//! Canonical JSON and PVCE transports for PortableValue.

use crate::{PORTABLE_VALUE_JSON_SCHEMA, ProtocolError, ProtocolErrorKind, ProtocolLimits};
use consema_core::{
    BigInteger, BinaryFloat32, BinaryFloat64, Date, Decimal, EntryMappingBuilder, LocalDateTime,
    ObjectBuilder, OffsetDateTime, PortableValue, PortableValueKind, SequenceBuilder, Time,
};
use consema_document::{FormationStatus, ParseLimits};
use consema_json::{JsonObjectMember, JsonProfile, JsonValue, SemanticAvailability};

/// Encodes a PortableValue as canonical `core.portable-value-json@1` bytes.
pub fn encode_json(
    value: &PortableValue,
    limits: ProtocolLimits,
) -> Result<Vec<u8>, ProtocolError> {
    let mut context = JsonEncoder::new(limits);
    context.push("{\"schema\":")?;
    context.string(PORTABLE_VALUE_JSON_SCHEMA, "$.schema")?;
    context.push(",\"value\":")?;
    context.value(value, 0, "$.value")?;
    context.push("}")?;
    Ok(context.output.into_bytes())
}

/// Strictly decodes canonical `core.portable-value-json@1` bytes.
pub fn decode_json(bytes: &[u8], limits: ProtocolLimits) -> Result<PortableValue, ProtocolError> {
    if bytes.len() > limits.max_bytes {
        return Err(resource("$", "transport bytes"));
    }
    let parse_limits = ParseLimits {
        max_source_bytes: limits.max_bytes,
        max_nesting_depth: limits.max_depth.saturating_mul(4).saturating_add(8),
        max_token_count: limits.max_nodes.saturating_mul(32).saturating_add(64),
        max_node_count: limits.max_nodes.saturating_mul(16).saturating_add(32),
        max_diagnostics: 1_000,
    };
    let document =
        consema_json::parse(bytes, JsonProfile::StrictV1, parse_limits).map_err(|_| {
            ProtocolError::new(
                ProtocolErrorKind::InvalidJson,
                "$",
                "JSON document could not be formed",
            )
        })?;
    if document.formation_status() != FormationStatus::Complete
        || !document.diagnostics().is_empty()
    {
        return Err(ProtocolError::new(
            ProtocolErrorKind::InvalidJson,
            "$",
            "JSON syntax, duplicate members, or profile diagnostics are present",
        ));
    }

    let root = exact_object(document.root(), &["schema", "value"], "$")?;
    let schema = json_string(root[0].value(), "$.schema", limits)?;
    if schema != PORTABLE_VALUE_JSON_SCHEMA {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            "$.schema",
            "unexpected transport schema",
        ));
    }
    let mut state = DecodeState { limits, nodes: 0 };
    let value = decode_value(root[1].value(), 0, "$.value", &mut state)?;
    let canonical = encode_json(&value, limits)?;
    if canonical != bytes {
        return Err(ProtocolError::new(
            ProtocolErrorKind::NonCanonicalJson,
            "$",
            "input is valid but not the canonical JSON byte form",
        ));
    }
    Ok(value)
}

/// Encodes a PortableValue as canonical PVCE/1 after applying protocol limits.
pub fn encode_pvce(
    value: &PortableValue,
    limits: ProtocolLimits,
) -> Result<Vec<u8>, ProtocolError> {
    let mut state = ValueLimitState { limits, nodes: 0 };
    state.value(value, 0, "$")?;
    let bytes = consema_pvce::encode(value);
    if bytes.len() > limits.max_bytes {
        return Err(resource("$", "transport bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes canonical PVCE/1 under protocol limits.
pub fn decode_pvce(bytes: &[u8], limits: ProtocolLimits) -> Result<PortableValue, ProtocolError> {
    consema_pvce::decode(
        bytes,
        consema_pvce::DecodeLimits {
            max_bytes: limits.max_bytes,
            max_depth: limits.max_depth,
            max_nodes: limits.max_nodes,
            max_container_entries: limits.max_container_entries,
            max_integer_bytes: limits.max_integer_bytes,
            max_blob_bytes: limits.max_blob_bytes,
        },
    )
    .map_err(|error| {
        let kind = if matches!(error, consema_pvce::DecodeError::ResourceLimit(_)) {
            ProtocolErrorKind::ResourceLimit
        } else {
            ProtocolErrorKind::InvalidPvce
        };
        ProtocolError::new(kind, "$", error.to_string())
    })
}

struct JsonEncoder {
    limits: ProtocolLimits,
    nodes: usize,
    output: String,
}

impl JsonEncoder {
    fn new(limits: ProtocolLimits) -> Self {
        Self {
            limits,
            nodes: 0,
            output: String::new(),
        }
    }

    fn push(&mut self, text: &str) -> Result<(), ProtocolError> {
        if self.output.len().saturating_add(text.len()) > self.limits.max_bytes {
            return Err(resource("$", "transport bytes"));
        }
        self.output.push_str(text);
        Ok(())
    }

    fn string(&mut self, value: &str, path: &str) -> Result<(), ProtocolError> {
        if value.len() > self.limits.max_blob_bytes {
            return Err(resource(path, "string bytes"));
        }
        self.push("\"")?;
        for character in value.chars() {
            match character {
                '"' => self.push("\\\"")?,
                '\\' => self.push("\\\\")?,
                '\u{08}' => self.push("\\b")?,
                '\u{09}' => self.push("\\t")?,
                '\u{0a}' => self.push("\\n")?,
                '\u{0c}' => self.push("\\f")?,
                '\u{0d}' => self.push("\\r")?,
                '\u{00}'..='\u{1f}' => {
                    let escaped = format!("\\u{:04x}", u32::from(character));
                    self.push(&escaped)?;
                }
                _ => {
                    let mut encoded = [0_u8; 4];
                    self.push(character.encode_utf8(&mut encoded))?;
                }
            }
        }
        self.push("\"")
    }

    fn node(&mut self, depth: usize, path: &str) -> Result<(), ProtocolError> {
        if depth > self.limits.max_depth {
            return Err(resource(path, "nesting depth"));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(resource(path, "value nodes"));
        }
        Ok(())
    }

    fn value(
        &mut self,
        value: &PortableValue,
        depth: usize,
        path: &str,
    ) -> Result<(), ProtocolError> {
        self.node(depth, path)?;
        self.push("{\"type\":")?;
        self.string(kind_name(value.kind()), path)?;
        match value.kind() {
            PortableValueKind::Null => {}
            PortableValueKind::Boolean => {
                self.push(",\"value\":")?;
                self.push(if value.as_boolean().expect("boolean kind") {
                    "true"
                } else {
                    "false"
                })?;
            }
            PortableValueKind::Integer => {
                self.push(",\"value\":")?;
                self.integer(value.as_integer().expect("integer kind"), path)?;
            }
            PortableValueKind::Decimal => {
                let decimal = value.as_decimal().expect("decimal kind");
                self.push(",\"coefficient\":")?;
                self.integer(decimal.coefficient(), path)?;
                self.push(",\"exponent\":")?;
                self.integer(decimal.exponent(), path)?;
            }
            PortableValueKind::BinaryFloat32 => {
                self.push(",\"bits\":")?;
                self.string(
                    &format!(
                        "{:08x}",
                        value.as_binary_float32().expect("binary32 kind").bits()
                    ),
                    path,
                )?;
            }
            PortableValueKind::BinaryFloat64 => {
                self.push(",\"bits\":")?;
                self.string(
                    &format!(
                        "{:016x}",
                        value.as_binary_float64().expect("binary64 kind").bits()
                    ),
                    path,
                )?;
            }
            PortableValueKind::String => {
                self.push(",\"value\":")?;
                self.string(value.as_string().expect("string kind"), path)?;
            }
            PortableValueKind::Bytes => {
                let bytes = value.as_bytes().expect("bytes kind");
                if bytes.len() > self.limits.max_blob_bytes {
                    return Err(resource(path, "bytes"));
                }
                self.push(",\"hex\":\"")?;
                for byte in bytes {
                    self.push(&format!("{byte:02x}"))?;
                }
                self.push("\"")?;
            }
            PortableValueKind::Date => {
                let date = value.as_date().expect("date kind");
                self.push(",\"year\":")?;
                self.integer(date.year(), path)?;
                self.push(",\"month\":")?;
                self.string(&date.month().to_string(), path)?;
                self.push(",\"day\":")?;
                self.string(&date.day().to_string(), path)?;
            }
            PortableValueKind::Time => {
                let time = value.as_time().expect("time kind");
                self.push(",\"hour\":")?;
                self.string(&time.hour().to_string(), path)?;
                self.push(",\"minute\":")?;
                self.string(&time.minute().to_string(), path)?;
                self.push(",\"second\":")?;
                self.string(&time.second().to_string(), path)?;
                self.push(",\"fraction\":")?;
                self.value(
                    &PortableValue::decimal(time.fractional_second().clone()),
                    depth.saturating_add(1),
                    path,
                )?;
            }
            PortableValueKind::LocalDateTime => {
                let date_time = value.as_local_date_time().expect("local date-time kind");
                self.push(",\"date\":")?;
                self.value(
                    &PortableValue::date(date_time.date().clone()),
                    depth.saturating_add(1),
                    path,
                )?;
                self.push(",\"time\":")?;
                self.value(
                    &PortableValue::time(date_time.time().clone()),
                    depth.saturating_add(1),
                    path,
                )?;
            }
            PortableValueKind::OffsetDateTime => {
                let date_time = value.as_offset_date_time().expect("offset date-time kind");
                self.push(",\"local\":")?;
                self.value(
                    &PortableValue::local_date_time(date_time.local().clone()),
                    depth.saturating_add(1),
                    path,
                )?;
                self.push(",\"offset_seconds\":")?;
                self.string(&date_time.offset_seconds().to_string(), path)?;
            }
            PortableValueKind::Sequence => {
                let items = value.as_sequence().expect("sequence kind");
                self.container(items.len(), path)?;
                self.push(",\"items\":[")?;
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        self.push(",")?;
                    }
                    self.value(item, depth.saturating_add(1), &format!("{path}[{index}]"))?;
                }
                self.push("]")?;
            }
            PortableValueKind::Object => {
                let entries = value.as_object().expect("object kind");
                self.container(entries.len(), path)?;
                self.push(",\"entries\":[")?;
                for (index, entry) in entries.iter().enumerate() {
                    if index != 0 {
                        self.push(",")?;
                    }
                    self.push("{\"key\":")?;
                    self.string(entry.key(), &format!("{path}.entries[{index}].key"))?;
                    self.push(",\"value\":")?;
                    self.value(
                        entry.value(),
                        depth.saturating_add(1),
                        &format!("{path}.entries[{index}].value"),
                    )?;
                    self.push("}")?;
                }
                self.push("]")?;
            }
            PortableValueKind::EntryMapping => {
                let entries = value.as_entry_mapping().expect("entry-mapping kind");
                self.container(entries.len(), path)?;
                self.push(",\"entries\":[")?;
                for (index, entry) in entries.iter().enumerate() {
                    if index != 0 {
                        self.push(",")?;
                    }
                    self.push("{\"key\":")?;
                    self.value(
                        entry.key(),
                        depth.saturating_add(1),
                        &format!("{path}.entries[{index}].key"),
                    )?;
                    self.push(",\"value\":")?;
                    self.value(
                        entry.value(),
                        depth.saturating_add(1),
                        &format!("{path}.entries[{index}].value"),
                    )?;
                    self.push("}")?;
                }
                self.push("]")?;
            }
        }
        self.push("}")
    }

    fn integer(&mut self, value: &BigInteger, path: &str) -> Result<(), ProtocolError> {
        if value.magnitude().len() > self.limits.max_integer_bytes {
            return Err(resource(path, "integer magnitude"));
        }
        self.string(&value.to_string(), path)
    }

    fn container(&self, count: usize, path: &str) -> Result<(), ProtocolError> {
        if count > self.limits.max_container_entries {
            Err(resource(path, "container entries"))
        } else {
            Ok(())
        }
    }
}

struct DecodeState {
    limits: ProtocolLimits,
    nodes: usize,
}

impl DecodeState {
    fn node(&mut self, depth: usize, path: &str) -> Result<(), ProtocolError> {
        if depth > self.limits.max_depth {
            return Err(resource(path, "nesting depth"));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(resource(path, "value nodes"));
        }
        Ok(())
    }

    fn container(&self, count: usize, path: &str) -> Result<(), ProtocolError> {
        if count > self.limits.max_container_entries {
            Err(resource(path, "container entries"))
        } else {
            Ok(())
        }
    }
}

fn decode_value(
    value: JsonValue<'_>,
    depth: usize,
    path: &str,
    state: &mut DecodeState,
) -> Result<PortableValue, ProtocolError> {
    state.node(depth, path)?;
    let members = json_object(value, path)?;
    let Some(first) = members.first() else {
        return Err(ProtocolError::new(
            ProtocolErrorKind::MissingField,
            format!("{path}.type"),
            "missing value type",
        ));
    };
    if json_member_name(*first, path)? != "type" {
        return Err(ProtocolError::new(
            ProtocolErrorKind::SchemaMismatch,
            path,
            "type must be the first field",
        ));
    }
    let kind = json_string(first.value(), &format!("{path}.type"), state.limits)?;
    match kind {
        "Null" => {
            exact_object(value, &["type"], path)?;
            Ok(PortableValue::null())
        }
        "Boolean" => {
            let fields = exact_object(value, &["type", "value"], path)?;
            Ok(PortableValue::boolean(json_boolean(
                fields[1].value(),
                &format!("{path}.value"),
            )?))
        }
        "Integer" => {
            let fields = exact_object(value, &["type", "value"], path)?;
            Ok(PortableValue::integer(parse_integer(
                json_string(fields[1].value(), &format!("{path}.value"), state.limits)?,
                &format!("{path}.value"),
                state.limits,
            )?))
        }
        "Decimal" => {
            let fields = exact_object(value, &["type", "coefficient", "exponent"], path)?;
            let coefficient = parse_integer(
                json_string(
                    fields[1].value(),
                    &format!("{path}.coefficient"),
                    state.limits,
                )?,
                &format!("{path}.coefficient"),
                state.limits,
            )?;
            let exponent = parse_integer(
                json_string(fields[2].value(), &format!("{path}.exponent"), state.limits)?,
                &format!("{path}.exponent"),
                state.limits,
            )?;
            Ok(PortableValue::decimal(Decimal::new(coefficient, exponent)))
        }
        "BinaryFloat32" => {
            let fields = exact_object(value, &["type", "bits"], path)?;
            let bits = parse_hex_u32(
                json_string(fields[1].value(), &format!("{path}.bits"), state.limits)?,
                &format!("{path}.bits"),
            )?;
            Ok(PortableValue::binary_float32(BinaryFloat32::from_bits(
                bits,
            )))
        }
        "BinaryFloat64" => {
            let fields = exact_object(value, &["type", "bits"], path)?;
            let bits = parse_hex_u64(
                json_string(fields[1].value(), &format!("{path}.bits"), state.limits)?,
                &format!("{path}.bits"),
            )?;
            Ok(PortableValue::binary_float64(BinaryFloat64::from_bits(
                bits,
            )))
        }
        "String" => {
            let fields = exact_object(value, &["type", "value"], path)?;
            Ok(PortableValue::string(json_string(
                fields[1].value(),
                &format!("{path}.value"),
                state.limits,
            )?))
        }
        "Bytes" => {
            let fields = exact_object(value, &["type", "hex"], path)?;
            Ok(PortableValue::bytes(parse_hex_bytes(
                json_string(fields[1].value(), &format!("{path}.hex"), state.limits)?,
                &format!("{path}.hex"),
                state.limits,
            )?))
        }
        "Date" => decode_date(value, path, state.limits).map(PortableValue::date),
        "Time" => decode_time(value, depth, path, state).map(PortableValue::time),
        "LocalDateTime" => {
            let fields = exact_object(value, &["type", "date", "time"], path)?;
            let date_value = decode_value(
                fields[1].value(),
                depth.saturating_add(1),
                &format!("{path}.date"),
                state,
            )?;
            let time_value = decode_value(
                fields[2].value(),
                depth.saturating_add(1),
                &format!("{path}.time"),
                state,
            )?;
            let date = date_value.as_date().cloned().ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorKind::WrongType,
                    format!("{path}.date"),
                    "expected Date",
                )
            })?;
            let time = time_value.as_time().cloned().ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorKind::WrongType,
                    format!("{path}.time"),
                    "expected Time",
                )
            })?;
            Ok(PortableValue::local_date_time(LocalDateTime::new(
                date, time,
            )))
        }
        "OffsetDateTime" => {
            let fields = exact_object(value, &["type", "local", "offset_seconds"], path)?;
            let local_value = decode_value(
                fields[1].value(),
                depth.saturating_add(1),
                &format!("{path}.local"),
                state,
            )?;
            let local = local_value.as_local_date_time().cloned().ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorKind::WrongType,
                    format!("{path}.local"),
                    "expected LocalDateTime",
                )
            })?;
            let offset = parse_i32(
                json_string(
                    fields[2].value(),
                    &format!("{path}.offset_seconds"),
                    state.limits,
                )?,
                &format!("{path}.offset_seconds"),
                state.limits,
            )?;
            OffsetDateTime::new(local, offset)
                .map(PortableValue::offset_date_time)
                .map_err(|_| invalid(path, "invalid offset date-time"))
        }
        "Sequence" => {
            let fields = exact_object(value, &["type", "items"], path)?;
            let items = json_array(fields[1].value(), &format!("{path}.items"))?;
            state.container(items.len(), path)?;
            let mut builder = SequenceBuilder::new();
            for (index, item) in items.into_iter().enumerate() {
                builder.push(decode_value(
                    item,
                    depth.saturating_add(1),
                    &format!("{path}.items[{index}]"),
                    state,
                )?);
            }
            Ok(builder.build())
        }
        "Object" => {
            let fields = exact_object(value, &["type", "entries"], path)?;
            let entries = json_array(fields[1].value(), &format!("{path}.entries"))?;
            state.container(entries.len(), path)?;
            let mut builder = ObjectBuilder::new();
            for (index, entry) in entries.into_iter().enumerate() {
                let entry_path = format!("{path}.entries[{index}]");
                let fields = exact_object(entry, &["key", "value"], &entry_path)?;
                let key = json_string(
                    fields[0].value(),
                    &format!("{entry_path}.key"),
                    state.limits,
                )?;
                let item = decode_value(
                    fields[1].value(),
                    depth.saturating_add(1),
                    &format!("{entry_path}.value"),
                    state,
                )?;
                builder
                    .insert(key, item)
                    .map_err(|_| invalid(&entry_path, "duplicate object key"))?;
            }
            Ok(builder.build())
        }
        "EntryMapping" => {
            let fields = exact_object(value, &["type", "entries"], path)?;
            let entries = json_array(fields[1].value(), &format!("{path}.entries"))?;
            state.container(entries.len(), path)?;
            let mut builder = EntryMappingBuilder::new();
            for (index, entry) in entries.into_iter().enumerate() {
                let entry_path = format!("{path}.entries[{index}]");
                let fields = exact_object(entry, &["key", "value"], &entry_path)?;
                let key = decode_value(
                    fields[0].value(),
                    depth.saturating_add(1),
                    &format!("{entry_path}.key"),
                    state,
                )?;
                let item = decode_value(
                    fields[1].value(),
                    depth.saturating_add(1),
                    &format!("{entry_path}.value"),
                    state,
                )?;
                builder.push(key, item);
            }
            Ok(builder.build())
        }
        _ => Err(invalid(&format!("{path}.type"), "unknown value type")),
    }
}

fn decode_date(
    value: JsonValue<'_>,
    path: &str,
    limits: ProtocolLimits,
) -> Result<Date, ProtocolError> {
    let fields = exact_object(value, &["type", "year", "month", "day"], path)?;
    let year = parse_integer(
        json_string(fields[1].value(), &format!("{path}.year"), limits)?,
        &format!("{path}.year"),
        limits,
    )?;
    let month = parse_u8(
        json_string(fields[2].value(), &format!("{path}.month"), limits)?,
        &format!("{path}.month"),
        limits,
    )?;
    let day = parse_u8(
        json_string(fields[3].value(), &format!("{path}.day"), limits)?,
        &format!("{path}.day"),
        limits,
    )?;
    Date::new(year, month, day).map_err(|_| invalid(path, "invalid date"))
}

fn decode_time(
    value: JsonValue<'_>,
    depth: usize,
    path: &str,
    state: &mut DecodeState,
) -> Result<Time, ProtocolError> {
    let fields = exact_object(
        value,
        &["type", "hour", "minute", "second", "fraction"],
        path,
    )?;
    let hour = parse_u8(
        json_string(fields[1].value(), &format!("{path}.hour"), state.limits)?,
        &format!("{path}.hour"),
        state.limits,
    )?;
    let minute = parse_u8(
        json_string(fields[2].value(), &format!("{path}.minute"), state.limits)?,
        &format!("{path}.minute"),
        state.limits,
    )?;
    let second = parse_u8(
        json_string(fields[3].value(), &format!("{path}.second"), state.limits)?,
        &format!("{path}.second"),
        state.limits,
    )?;
    let fraction_value = decode_value(
        fields[4].value(),
        depth.saturating_add(1),
        &format!("{path}.fraction"),
        state,
    )?;
    let fraction = fraction_value.as_decimal().cloned().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::WrongType,
            format!("{path}.fraction"),
            "expected Decimal",
        )
    })?;
    Time::new(hour, minute, second, fraction).map_err(|_| invalid(path, "invalid time"))
}

fn exact_object<'a>(
    value: JsonValue<'a>,
    expected: &[&str],
    path: &str,
) -> Result<Vec<JsonObjectMember<'a>>, ProtocolError> {
    let members = json_object(value, path)?;
    let mut names = Vec::with_capacity(members.len());
    for member in &members {
        names.push(json_member_name(*member, path)?);
    }
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
            "fields are duplicated or not in canonical order",
        ));
    }
    Ok(members)
}

fn json_object<'a>(
    value: JsonValue<'a>,
    path: &str,
) -> Result<Vec<JsonObjectMember<'a>>, ProtocolError> {
    match value.object_members() {
        SemanticAvailability::Available(Some(members)) => Ok(members),
        SemanticAvailability::Available(None) => Err(ProtocolError::new(
            ProtocolErrorKind::WrongType,
            path,
            "expected JSON object",
        )),
        SemanticAvailability::Unavailable(_) => Err(invalid(path, "unavailable JSON semantics")),
    }
}

fn json_array<'a>(value: JsonValue<'a>, path: &str) -> Result<Vec<JsonValue<'a>>, ProtocolError> {
    match value.array_elements() {
        SemanticAvailability::Available(Some(elements)) => Ok(elements
            .into_iter()
            .map(consema_json::JsonArrayElement::value)
            .collect()),
        SemanticAvailability::Available(None) => Err(ProtocolError::new(
            ProtocolErrorKind::WrongType,
            path,
            "expected JSON array",
        )),
        SemanticAvailability::Unavailable(_) => Err(invalid(path, "unavailable JSON semantics")),
    }
}

fn json_member_name<'a>(
    member: JsonObjectMember<'a>,
    path: &str,
) -> Result<&'a str, ProtocolError> {
    match member.name() {
        SemanticAvailability::Available(name) => Ok(name),
        SemanticAvailability::Unavailable(_) => Err(invalid(path, "unavailable member name")),
    }
}

fn json_string<'a>(
    value: JsonValue<'a>,
    path: &str,
    limits: ProtocolLimits,
) -> Result<&'a str, ProtocolError> {
    match value.as_string() {
        SemanticAvailability::Available(Some(text)) => {
            if text.len() > limits.max_blob_bytes {
                Err(resource(path, "string bytes"))
            } else {
                Ok(text)
            }
        }
        SemanticAvailability::Available(None) => Err(ProtocolError::new(
            ProtocolErrorKind::WrongType,
            path,
            "expected JSON string",
        )),
        SemanticAvailability::Unavailable(_) => Err(invalid(path, "unavailable JSON string")),
    }
}

fn json_boolean(value: JsonValue<'_>, path: &str) -> Result<bool, ProtocolError> {
    match value.as_boolean() {
        SemanticAvailability::Available(Some(boolean)) => Ok(boolean),
        SemanticAvailability::Available(None) => Err(ProtocolError::new(
            ProtocolErrorKind::WrongType,
            path,
            "expected JSON boolean",
        )),
        SemanticAvailability::Unavailable(_) => Err(invalid(path, "unavailable JSON boolean")),
    }
}

fn parse_integer(
    text: &str,
    path: &str,
    limits: ProtocolLimits,
) -> Result<BigInteger, ProtocolError> {
    let max_digits = limits.max_integer_bytes.saturating_mul(3).saturating_add(2);
    if text.len() > max_digits {
        return Err(resource(path, "integer decimal digits"));
    }
    let integer = BigInteger::parse_decimal(text).map_err(|_| invalid(path, "invalid integer"))?;
    if integer.magnitude().len() > limits.max_integer_bytes {
        return Err(resource(path, "integer magnitude"));
    }
    Ok(integer)
}

fn parse_u8(text: &str, path: &str, limits: ProtocolLimits) -> Result<u8, ProtocolError> {
    parse_integer(text, path, limits)?
        .to_i64()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| invalid(path, "integer is outside u8"))
}

fn parse_i32(text: &str, path: &str, limits: ProtocolLimits) -> Result<i32, ProtocolError> {
    parse_integer(text, path, limits)?
        .to_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| invalid(path, "integer is outside i32"))
}

fn parse_hex_u32(text: &str, path: &str) -> Result<u32, ProtocolError> {
    if text.len() != 8 {
        return Err(invalid(path, "binary32 bits require 8 hexadecimal digits"));
    }
    u32::from_str_radix(text, 16).map_err(|_| invalid(path, "invalid binary32 bits"))
}

fn parse_hex_u64(text: &str, path: &str) -> Result<u64, ProtocolError> {
    if text.len() != 16 {
        return Err(invalid(path, "binary64 bits require 16 hexadecimal digits"));
    }
    u64::from_str_radix(text, 16).map_err(|_| invalid(path, "invalid binary64 bits"))
}

fn parse_hex_bytes(
    text: &str,
    path: &str,
    limits: ProtocolLimits,
) -> Result<Vec<u8>, ProtocolError> {
    if text.len() % 2 != 0 {
        return Err(invalid(path, "byte hex length must be even"));
    }
    let byte_count = text.len() / 2;
    if byte_count > limits.max_blob_bytes {
        return Err(resource(path, "bytes"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex pairs are UTF-8 byte slices");
            u8::from_str_radix(pair, 16).map_err(|_| invalid(path, "invalid byte hex"))
        })
        .collect()
}

struct ValueLimitState {
    limits: ProtocolLimits,
    nodes: usize,
}

impl ValueLimitState {
    fn value(
        &mut self,
        value: &PortableValue,
        depth: usize,
        path: &str,
    ) -> Result<(), ProtocolError> {
        if depth > self.limits.max_depth {
            return Err(resource(path, "nesting depth"));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(resource(path, "value nodes"));
        }
        match value.kind() {
            PortableValueKind::Integer => {
                self.integer(value.as_integer().expect("integer kind"), path)?;
            }
            PortableValueKind::Decimal => {
                let decimal = value.as_decimal().expect("decimal kind");
                self.integer(decimal.coefficient(), path)?;
                self.integer(decimal.exponent(), path)?;
            }
            PortableValueKind::String => {
                self.blob(value.as_string().expect("string kind").len(), path)?;
            }
            PortableValueKind::Bytes => {
                self.blob(value.as_bytes().expect("bytes kind").len(), path)?;
            }
            PortableValueKind::Date => {
                self.integer(value.as_date().expect("date kind").year(), path)?;
            }
            PortableValueKind::Time => {
                let fraction = value.as_time().expect("time kind").fractional_second();
                self.integer(fraction.coefficient(), path)?;
                self.integer(fraction.exponent(), path)?;
            }
            PortableValueKind::LocalDateTime => {
                let local = value.as_local_date_time().expect("local date-time kind");
                self.integer(local.date().year(), path)?;
                self.integer(local.time().fractional_second().coefficient(), path)?;
                self.integer(local.time().fractional_second().exponent(), path)?;
            }
            PortableValueKind::OffsetDateTime => {
                let local = value
                    .as_offset_date_time()
                    .expect("offset date-time kind")
                    .local();
                self.integer(local.date().year(), path)?;
                self.integer(local.time().fractional_second().coefficient(), path)?;
                self.integer(local.time().fractional_second().exponent(), path)?;
            }
            PortableValueKind::Sequence => {
                let items = value.as_sequence().expect("sequence kind");
                self.container(items.len(), path)?;
                for (index, item) in items.iter().enumerate() {
                    self.value(item, depth.saturating_add(1), &format!("{path}[{index}]"))?;
                }
            }
            PortableValueKind::Object => {
                let entries = value.as_object().expect("object kind");
                self.container(entries.len(), path)?;
                for (index, entry) in entries.iter().enumerate() {
                    self.blob(entry.key().len(), path)?;
                    self.value(
                        entry.value(),
                        depth.saturating_add(1),
                        &format!("{path}.entries[{index}].value"),
                    )?;
                }
            }
            PortableValueKind::EntryMapping => {
                let entries = value.as_entry_mapping().expect("entry-mapping kind");
                self.container(entries.len(), path)?;
                for (index, entry) in entries.iter().enumerate() {
                    self.value(
                        entry.key(),
                        depth.saturating_add(1),
                        &format!("{path}.entries[{index}].key"),
                    )?;
                    self.value(
                        entry.value(),
                        depth.saturating_add(1),
                        &format!("{path}.entries[{index}].value"),
                    )?;
                }
            }
            PortableValueKind::Null
            | PortableValueKind::Boolean
            | PortableValueKind::BinaryFloat32
            | PortableValueKind::BinaryFloat64 => {}
        }
        Ok(())
    }

    fn integer(&self, value: &BigInteger, path: &str) -> Result<(), ProtocolError> {
        if value.magnitude().len() > self.limits.max_integer_bytes {
            Err(resource(path, "integer magnitude"))
        } else {
            Ok(())
        }
    }

    fn blob(&self, count: usize, path: &str) -> Result<(), ProtocolError> {
        if count > self.limits.max_blob_bytes {
            Err(resource(path, "blob bytes"))
        } else {
            Ok(())
        }
    }

    fn container(&self, count: usize, path: &str) -> Result<(), ProtocolError> {
        if count > self.limits.max_container_entries {
            Err(resource(path, "container entries"))
        } else {
            Ok(())
        }
    }
}

const fn kind_name(kind: PortableValueKind) -> &'static str {
    match kind {
        PortableValueKind::Null => "Null",
        PortableValueKind::Boolean => "Boolean",
        PortableValueKind::Integer => "Integer",
        PortableValueKind::Decimal => "Decimal",
        PortableValueKind::BinaryFloat32 => "BinaryFloat32",
        PortableValueKind::BinaryFloat64 => "BinaryFloat64",
        PortableValueKind::String => "String",
        PortableValueKind::Bytes => "Bytes",
        PortableValueKind::Date => "Date",
        PortableValueKind::Time => "Time",
        PortableValueKind::LocalDateTime => "LocalDateTime",
        PortableValueKind::OffsetDateTime => "OffsetDateTime",
        PortableValueKind::Sequence => "Sequence",
        PortableValueKind::Object => "Object",
        PortableValueKind::EntryMapping => "EntryMapping",
    }
}

fn invalid(path: &str, detail: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::InvalidValue, path, detail)
}

fn resource(path: &str, detail: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorKind::ResourceLimit, path, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{EntryMappingBuilder, ObjectBuilder};

    fn all_kinds() -> PortableValue {
        let date = Date::new(BigInteger::from(-44), 3, 15).unwrap();
        let fraction = Decimal::new(BigInteger::from(125), BigInteger::from(-3));
        let time = Time::new(12, 34, 56, fraction.clone()).unwrap();
        let local = LocalDateTime::new(date.clone(), time.clone());
        let offset = OffsetDateTime::new(local.clone(), -90).unwrap();
        let mut object = ObjectBuilder::new();
        object.insert("x", PortableValue::boolean(true)).unwrap();
        let mut mapping = EntryMappingBuilder::new();
        mapping.push(PortableValue::string("k"), PortableValue::null());
        PortableValue::sequence(vec![
            PortableValue::null(),
            PortableValue::boolean(false),
            PortableValue::integer(BigInteger::parse_decimal("12345678901234567890").unwrap()),
            PortableValue::decimal(Decimal::new(BigInteger::from(123), BigInteger::from(-2))),
            PortableValue::binary_float32(BinaryFloat32::from_bits(0x7fc0_0001)),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x8000_0000_0000_0000)),
            PortableValue::string("quote \" slash \\ newline\n 世界"),
            PortableValue::bytes([0, 1, 0xfe, 0xff].as_slice()),
            PortableValue::date(date),
            PortableValue::time(time),
            PortableValue::local_date_time(local),
            PortableValue::offset_date_time(offset),
            PortableValue::sequence(vec![PortableValue::string("nested")]),
            object.build(),
            mapping.build(),
        ])
    }

    #[test]
    fn every_core_kind_round_trips_through_both_transports() {
        let value = all_kinds();
        let limits = ProtocolLimits::default();
        let json = encode_json(&value, limits).unwrap();
        assert_eq!(decode_json(&json, limits).unwrap(), value);
        let pvce = encode_pvce(&value, limits).unwrap();
        assert_eq!(decode_pvce(&pvce, limits).unwrap(), value);
    }

    #[test]
    fn valid_but_noncanonical_json_is_rejected() {
        let canonical = encode_json(&PortableValue::null(), ProtocolLimits::default()).unwrap();
        let mut spaced = Vec::with_capacity(canonical.len() + 1);
        spaced.extend_from_slice(b" ");
        spaced.extend_from_slice(&canonical);
        let error = decode_json(&spaced, ProtocolLimits::default()).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::NonCanonicalJson);
    }

    #[test]
    fn fixed_fields_and_limits_are_strict() {
        let unknown =
            br#"{"schema":"core.portable-value-json@1","value":{"type":"Null","extra":true}}"#;
        assert_eq!(
            decode_json(unknown, ProtocolLimits::default())
                .unwrap_err()
                .kind(),
            ProtocolErrorKind::UnknownField
        );

        let limits = ProtocolLimits {
            max_depth: 0,
            ..ProtocolLimits::default()
        };
        assert_eq!(
            encode_json(
                &PortableValue::sequence(vec![PortableValue::null()]),
                limits,
            )
            .unwrap_err()
            .kind(),
            ProtocolErrorKind::ResourceLimit
        );
    }
}
