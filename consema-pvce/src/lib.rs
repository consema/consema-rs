//! Portable Value Canonical Encoding / 1.
//!
//! The architecture baseline fixes record tags and semantic requirements but
//! intentionally does not assign the stream magic, sign octets, or unsigned
//! varint bit layout. This reference implementation freezes those remaining
//! wire constants for `PVCE/1` as follows:
//!
//! - stream magic is the ASCII octets `PVCE`;
//! - version is minimal unsigned LEB128 `1`;
//! - integer sign octets are `0` (zero), `1` (positive), `2` (negative);
//! - all unsigned lengths/counts/tags are minimal unsigned LEB128.
//!
//! Any incompatible change requires a new encoding version.

use consema_core::{
    BigInteger, BinaryFloat32, BinaryFloat64, Date, Decimal, EntryMappingBuilder, ExtendedValue,
    LocalDateTime, ObjectBuilder, OffsetDateTime, PortableValue, PortableValueKind, Time,
    ValueBuildError,
};
use std::fmt::{self, Display, Formatter};

/// PVCE/1 stream magic.
pub const MAGIC: [u8; 4] = *b"PVCE";
/// PVCE version.
pub const VERSION: u64 = 1;

const TAG_NULL: u64 = 0x00;
const TAG_FALSE: u64 = 0x01;
const TAG_TRUE: u64 = 0x02;
const TAG_INTEGER: u64 = 0x10;
const TAG_DECIMAL: u64 = 0x11;
const TAG_FLOAT32: u64 = 0x12;
const TAG_FLOAT64: u64 = 0x13;
const TAG_STRING: u64 = 0x20;
const TAG_BYTES: u64 = 0x21;
const TAG_DATE: u64 = 0x30;
const TAG_TIME: u64 = 0x31;
const TAG_LOCAL_DATE_TIME: u64 = 0x32;
const TAG_OFFSET_DATE_TIME: u64 = 0x33;
const TAG_SEQUENCE: u64 = 0x40;
const TAG_OBJECT: u64 = 0x41;
const TAG_ENTRY_MAPPING: u64 = 0x42;
const TAG_EXTENDED: u64 = 0x7f;

/// A PVCE root record. Extensions remain separate from the closed core tree.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EncodedValue {
    /// Closed PortableValue v1 value.
    Core(PortableValue),
    /// Formally versioned extension payload.
    Extended(ExtendedValue),
}

/// Strict decoder resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    /// Maximum complete stream bytes.
    pub max_bytes: usize,
    /// Maximum nested container depth.
    pub max_depth: usize,
    /// Maximum total core records.
    pub max_nodes: usize,
    /// Maximum entries in one container.
    pub max_container_entries: usize,
    /// Maximum arbitrary integer magnitude bytes.
    pub max_integer_bytes: usize,
    /// Maximum String, Bytes, or extension payload bytes.
    pub max_blob_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_depth: 256,
            max_nodes: 1_000_000,
            max_container_entries: 1_000_000,
            max_integer_bytes: 1024 * 1024,
            max_blob_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Encodes one core value as a complete canonical PVCE/1 stream.
#[must_use]
pub fn encode(value: &PortableValue) -> Vec<u8> {
    encode_value(&EncodedValue::Core(value.clone()))
}

/// Encodes one core or extension root as a complete canonical PVCE/1 stream.
#[must_use]
pub fn encode_value(value: &EncodedValue) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&MAGIC);
    write_varint(VERSION, &mut output);
    match value {
        EncodedValue::Core(value) => encode_record(value, &mut output),
        EncodedValue::Extended(value) => encode_extended_record(value, &mut output),
    }
    output
}

/// Strictly decodes a core PortableValue stream.
pub fn decode(bytes: &[u8], limits: DecodeLimits) -> Result<PortableValue, DecodeError> {
    match decode_value(bytes, limits)? {
        EncodedValue::Core(value) => Ok(value),
        EncodedValue::Extended(_) => Err(DecodeError::ExpectedCoreValue),
    }
}
/// Bounded canonical encoding limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeLimits {
    /// Maximum complete stream bytes.
    pub max_bytes: usize,
    /// Maximum nested container depth.
    pub max_depth: usize,
    /// Maximum total core records.
    pub max_nodes: usize,
    /// Maximum entries in one container.
    pub max_container_entries: usize,
    /// Maximum arbitrary integer magnitude bytes.
    pub max_integer_bytes: usize,
    /// Maximum String, Bytes, or extension payload bytes.
    pub max_blob_bytes: usize,
}

impl Default for EncodeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_depth: 256,
            max_nodes: 1_000_000,
            max_container_entries: 1_000_000,
            max_integer_bytes: 1024 * 1024,
            max_blob_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Stable bounded encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// A declared resource limit was reached; no partial output is returned.
    ResourceLimit(&'static str),
    /// Computed stream size overflowed the host address space.
    LengthOverflow,
}

/// Encodes one core value with explicit resource limits; never truncates.
pub fn encode_bounded(value: &PortableValue, limits: EncodeLimits) -> Result<Vec<u8>, EncodeError> {
    let size = measure_root(&EncodedValue::Core(value.clone()), limits)?;
    if size > limits.max_bytes {
        return Err(EncodeError::ResourceLimit("stream-bytes"));
    }
    Ok(encode_value(&EncodedValue::Core(value.clone())))
}

/// Encodes one core or extension root with explicit resource limits.
pub fn encode_value_bounded(
    value: &EncodedValue,
    limits: EncodeLimits,
) -> Result<Vec<u8>, EncodeError> {
    let size = measure_root(value, limits)?;
    if size > limits.max_bytes {
        return Err(EncodeError::ResourceLimit("stream-bytes"));
    }
    Ok(encode_value(value))
}

struct Sizer {
    limits: EncodeLimits,
    nodes: usize,
}

impl Sizer {
    fn record(&mut self, depth: usize) -> Result<(), EncodeError> {
        if depth > self.limits.max_depth {
            return Err(EncodeError::ResourceLimit("nesting-depth"));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(EncodeError::ResourceLimit("value-nodes"));
        }
        Ok(())
    }

    fn blob_size(&self, length: usize, name: &'static str) -> Result<usize, EncodeError> {
        if length > self.limits.max_blob_bytes {
            return Err(EncodeError::ResourceLimit(name));
        }
        add(varint_size(length as u64), length)
    }

    fn integer_field_size(&self, value: &BigInteger) -> Result<usize, EncodeError> {
        let magnitude = value.magnitude().len();
        if magnitude > self.limits.max_integer_bytes {
            return Err(EncodeError::ResourceLimit("integer-bytes"));
        }
        let payload = add(add(1, varint_size(magnitude as u64))?, magnitude)?;
        add(varint_size(payload as u64), payload)
    }

    fn decimal_field_size(&self, value: &Decimal) -> Result<usize, EncodeError> {
        let payload = add(
            self.integer_field_size(value.coefficient())?,
            self.integer_field_size(value.exponent())?,
        )?;
        add(varint_size(payload as u64), payload)
    }

    fn date_field_size(&self, value: &Date) -> Result<usize, EncodeError> {
        let payload = add(self.integer_field_size(value.year())?, 2)?;
        add(varint_size(payload as u64), payload)
    }

    fn time_field_size(&self, value: &Time) -> Result<usize, EncodeError> {
        let payload = add(3, self.decimal_field_size(value.fractional_second())?)?;
        add(varint_size(payload as u64), payload)
    }

    fn container_size(
        &mut self,
        count: usize,
        values: impl IntoIterator<Item = PortableValue>,
        depth: usize,
    ) -> Result<usize, EncodeError> {
        if count > self.limits.max_container_entries {
            return Err(EncodeError::ResourceLimit("container-entries"));
        }
        let mut payload = varint_size(count as u64);
        for value in values {
            payload = add(payload, self.record_size(&value, depth)?)?;
        }
        Ok(payload)
    }

    fn record_size(&mut self, value: &PortableValue, depth: usize) -> Result<usize, EncodeError> {
        self.record(depth)?;
        let (tag, payload) = match value.kind() {
            PortableValueKind::Null => (TAG_NULL, 0),
            PortableValueKind::Boolean => (
                if value.as_boolean().expect("boolean kind") {
                    TAG_TRUE
                } else {
                    TAG_FALSE
                },
                0,
            ),
            PortableValueKind::Integer => {
                let magnitude = value.as_integer().expect("integer kind").magnitude().len();
                if magnitude > self.limits.max_integer_bytes {
                    return Err(EncodeError::ResourceLimit("integer-bytes"));
                }
                (
                    TAG_INTEGER,
                    add(add(1, varint_size(magnitude as u64))?, magnitude)?,
                )
            }
            PortableValueKind::Decimal => (
                TAG_DECIMAL,
                add(
                    self.integer_field_size(
                        value.as_decimal().expect("decimal kind").coefficient(),
                    )?,
                    self.integer_field_size(value.as_decimal().expect("decimal kind").exponent())?,
                )?,
            ),
            PortableValueKind::BinaryFloat32 => (TAG_FLOAT32, 4),
            PortableValueKind::BinaryFloat64 => (TAG_FLOAT64, 8),
            PortableValueKind::String => (
                TAG_STRING,
                self.blob_size(value.as_string().expect("string kind").len(), "blob-bytes")?,
            ),
            PortableValueKind::Bytes => (
                TAG_BYTES,
                self.blob_size(value.as_bytes().expect("bytes kind").len(), "blob-bytes")?,
            ),
            PortableValueKind::Date => (
                TAG_DATE,
                add(
                    self.integer_field_size(value.as_date().expect("date kind").year())?,
                    2,
                )?,
            ),
            PortableValueKind::Time => (
                TAG_TIME,
                add(
                    3,
                    self.decimal_field_size(
                        value.as_time().expect("time kind").fractional_second(),
                    )?,
                )?,
            ),
            PortableValueKind::LocalDateTime => {
                let value = value.as_local_date_time().expect("local date-time kind");
                (
                    TAG_LOCAL_DATE_TIME,
                    add(
                        self.date_field_size(value.date())?,
                        self.time_field_size(value.time())?,
                    )?,
                )
            }
            PortableValueKind::OffsetDateTime => {
                let value = value.as_offset_date_time().expect("offset date-time kind");
                (
                    TAG_OFFSET_DATE_TIME,
                    add(
                        add(
                            self.date_field_size(value.local().date())?,
                            self.time_field_size(value.local().time())?,
                        )?,
                        self.integer_field_size(&BigInteger::from(i64::from(
                            value.offset_seconds(),
                        )))?,
                    )?,
                )
            }
            PortableValueKind::Sequence => {
                let values = value.as_sequence().expect("sequence kind");
                (
                    TAG_SEQUENCE,
                    self.container_size(values.len(), values.iter().cloned(), depth + 1)?,
                )
            }
            PortableValueKind::Object => {
                let entries = value.as_object().expect("object kind");
                let mut payload = varint_size(entries.len() as u64);
                if entries.len() > self.limits.max_container_entries {
                    return Err(EncodeError::ResourceLimit("container-entries"));
                }
                for entry in entries {
                    let key = PortableValue::string(entry.key());
                    payload = add(
                        payload,
                        add(
                            self.record_size(&key, depth + 1)?,
                            self.record_size(entry.value(), depth + 1)?,
                        )?,
                    )?;
                }
                (TAG_OBJECT, payload)
            }
            PortableValueKind::EntryMapping => {
                let entries = value.as_entry_mapping().expect("entry-mapping kind");
                let mut payload = varint_size(entries.len() as u64);
                if entries.len() > self.limits.max_container_entries {
                    return Err(EncodeError::ResourceLimit("container-entries"));
                }
                for entry in entries {
                    payload = add(
                        payload,
                        add(
                            self.record_size(entry.key(), depth + 1)?,
                            self.record_size(entry.value(), depth + 1)?,
                        )?,
                    )?;
                }
                (TAG_ENTRY_MAPPING, payload)
            }
        };
        add(add(varint_size(tag), varint_size(payload as u64))?, payload)
    }
}

fn add(left: usize, right: usize) -> Result<usize, EncodeError> {
    left.checked_add(right).ok_or(EncodeError::LengthOverflow)
}

const fn varint_size(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

fn measure_root(value: &EncodedValue, limits: EncodeLimits) -> Result<usize, EncodeError> {
    let mut sizer = Sizer { limits, nodes: 0 };
    let record = match value {
        EncodedValue::Core(value) => sizer.record_size(value, 0)?,
        EncodedValue::Extended(value) => {
            let payload = add(
                add(
                    sizer.blob_size(value.type_id().len(), "blob-bytes")?,
                    varint_size(u64::from(value.semantic_version())),
                )?,
                add(
                    sizer.blob_size(value.payload_codec_id().len(), "blob-bytes")?,
                    sizer.blob_size(value.canonical_payload().len(), "blob-bytes")?,
                )?,
            )?;
            add(
                add(varint_size(TAG_EXTENDED), varint_size(payload as u64))?,
                payload,
            )?
        }
    };
    add(add(4, 1)?, record)
}

/// Strictly decodes a core or already canonical extension root.
pub fn decode_value(bytes: &[u8], limits: DecodeLimits) -> Result<EncodedValue, DecodeError> {
    if bytes.len() > limits.max_bytes {
        return Err(DecodeError::ResourceLimit("stream-bytes"));
    }
    let mut reader = Reader::new(bytes, limits);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let version = reader.varint()?;
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let (tag, payload) = reader.record()?;
    let value = if tag == TAG_EXTENDED {
        EncodedValue::Extended(decode_extended(payload, &mut reader)?)
    } else {
        EncodedValue::Core(decode_core_record(tag, payload, &mut reader, 0)?)
    };
    if !reader.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

fn encode_record(value: &PortableValue, output: &mut Vec<u8>) {
    let mut payload = Vec::new();
    let tag = match value.kind() {
        PortableValueKind::Null => TAG_NULL,
        PortableValueKind::Boolean => {
            return write_record(
                if value.as_boolean().expect("boolean kind") {
                    TAG_TRUE
                } else {
                    TAG_FALSE
                },
                &[],
                output,
            );
        }
        PortableValueKind::Integer => {
            encode_integer_payload(value.as_integer().expect("integer kind"), &mut payload);
            TAG_INTEGER
        }
        PortableValueKind::Decimal => {
            encode_decimal_payload(value.as_decimal().expect("decimal kind"), &mut payload);
            TAG_DECIMAL
        }
        PortableValueKind::BinaryFloat32 => {
            payload.extend_from_slice(
                &value
                    .as_binary_float32()
                    .expect("binary32 kind")
                    .bits()
                    .to_be_bytes(),
            );
            TAG_FLOAT32
        }
        PortableValueKind::BinaryFloat64 => {
            payload.extend_from_slice(
                &value
                    .as_binary_float64()
                    .expect("binary64 kind")
                    .bits()
                    .to_be_bytes(),
            );
            TAG_FLOAT64
        }
        PortableValueKind::String => {
            encode_blob(
                value.as_string().expect("string kind").as_bytes(),
                &mut payload,
            );
            TAG_STRING
        }
        PortableValueKind::Bytes => {
            encode_blob(value.as_bytes().expect("bytes kind"), &mut payload);
            TAG_BYTES
        }
        PortableValueKind::Date => {
            encode_date_payload(value.as_date().expect("date kind"), &mut payload);
            TAG_DATE
        }
        PortableValueKind::Time => {
            encode_time_payload(value.as_time().expect("time kind"), &mut payload);
            TAG_TIME
        }
        PortableValueKind::LocalDateTime => {
            encode_local_date_time_payload(
                value.as_local_date_time().expect("local date-time kind"),
                &mut payload,
            );
            TAG_LOCAL_DATE_TIME
        }
        PortableValueKind::OffsetDateTime => {
            let value = value.as_offset_date_time().expect("offset date-time kind");
            encode_local_date_time_payload(value.local(), &mut payload);
            encode_integer_field(
                &BigInteger::from(i64::from(value.offset_seconds())),
                &mut payload,
            );
            TAG_OFFSET_DATE_TIME
        }
        PortableValueKind::Sequence => {
            let values = value.as_sequence().expect("sequence kind");
            write_varint(values.len() as u64, &mut payload);
            for value in values {
                encode_record(value, &mut payload);
            }
            TAG_SEQUENCE
        }
        PortableValueKind::Object => {
            let entries = value.as_object().expect("object kind");
            write_varint(entries.len() as u64, &mut payload);
            for entry in entries {
                encode_record(&PortableValue::string(entry.key()), &mut payload);
                encode_record(entry.value(), &mut payload);
            }
            TAG_OBJECT
        }
        PortableValueKind::EntryMapping => {
            let entries = value.as_entry_mapping().expect("entry-mapping kind");
            write_varint(entries.len() as u64, &mut payload);
            for entry in entries {
                encode_record(entry.key(), &mut payload);
                encode_record(entry.value(), &mut payload);
            }
            TAG_ENTRY_MAPPING
        }
    };
    write_record(tag, &payload, output);
}

fn encode_extended_record(value: &ExtendedValue, output: &mut Vec<u8>) {
    let mut payload = Vec::new();
    encode_blob(value.type_id().as_bytes(), &mut payload);
    write_varint(u64::from(value.semantic_version()), &mut payload);
    encode_blob(value.payload_codec_id().as_bytes(), &mut payload);
    encode_blob(value.canonical_payload(), &mut payload);
    write_record(TAG_EXTENDED, &payload, output);
}

fn encode_integer_payload(value: &BigInteger, output: &mut Vec<u8>) {
    output.push(match value.signum() {
        -1 => 2,
        0 => 0,
        1 => 1,
        _ => unreachable!("BigInteger canonical sign"),
    });
    write_varint(value.magnitude().len() as u64, output);
    output.extend_from_slice(value.magnitude());
}

fn encode_integer_field(value: &BigInteger, output: &mut Vec<u8>) {
    let mut payload = Vec::new();
    encode_integer_payload(value, &mut payload);
    write_varint(payload.len() as u64, output);
    output.extend_from_slice(&payload);
}

fn encode_decimal_payload(value: &Decimal, output: &mut Vec<u8>) {
    encode_integer_field(value.coefficient(), output);
    encode_integer_field(value.exponent(), output);
}

fn encode_decimal_field(value: &Decimal, output: &mut Vec<u8>) {
    let mut payload = Vec::new();
    encode_decimal_payload(value, &mut payload);
    write_varint(payload.len() as u64, output);
    output.extend_from_slice(&payload);
}

fn encode_blob(bytes: &[u8], output: &mut Vec<u8>) {
    write_varint(bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}

fn encode_date_payload(value: &Date, output: &mut Vec<u8>) {
    encode_integer_field(value.year(), output);
    output.push(value.month());
    output.push(value.day());
}

fn encode_date_field(value: &Date, output: &mut Vec<u8>) {
    let mut payload = Vec::new();
    encode_date_payload(value, &mut payload);
    write_varint(payload.len() as u64, output);
    output.extend_from_slice(&payload);
}

fn encode_time_payload(value: &Time, output: &mut Vec<u8>) {
    output.extend_from_slice(&[value.hour(), value.minute(), value.second()]);
    encode_decimal_field(value.fractional_second(), output);
}

fn encode_time_field(value: &Time, output: &mut Vec<u8>) {
    let mut payload = Vec::new();
    encode_time_payload(value, &mut payload);
    write_varint(payload.len() as u64, output);
    output.extend_from_slice(&payload);
}

fn encode_local_date_time_payload(value: &LocalDateTime, output: &mut Vec<u8>) {
    encode_date_field(value.date(), output);
    encode_time_field(value.time(), output);
}

fn write_record(tag: u64, payload: &[u8], output: &mut Vec<u8>) {
    write_varint(tag, output);
    write_varint(payload.len() as u64, output);
    output.extend_from_slice(payload);
}

fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut octet = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            octet |= 0x80;
        }
        output.push(octet);
        if value == 0 {
            return;
        }
    }
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: DecodeLimits,
    nodes: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], limits: DecodeLimits) -> Self {
        Self {
            bytes,
            offset: 0,
            limits,
            nodes: 0,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DecodeError::UnexpectedEnd)?;
        self.offset = end;
        Ok(value)
    }

    fn octet(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let start = self.offset;
        let mut value = 0_u64;
        for shift in (0..=63).step_by(7) {
            let octet = self.octet()?;
            let low = u64::from(octet & 0x7f);
            if shift == 63 && low > 1 {
                return Err(DecodeError::VarintOverflow);
            }
            value |= low << shift;
            if octet & 0x80 == 0 {
                if self.offset - start > 1 && low == 0 {
                    return Err(DecodeError::NonCanonicalVarint);
                }
                return Ok(value);
            }
        }
        Err(DecodeError::VarintOverflow)
    }

    fn length(&mut self, limit: usize, name: &'static str) -> Result<usize, DecodeError> {
        let value = usize::try_from(self.varint()?).map_err(|_| DecodeError::LengthOverflow)?;
        if value > limit {
            return Err(DecodeError::ResourceLimit(name));
        }
        Ok(value)
    }

    fn record(&mut self) -> Result<(u64, &'a [u8]), DecodeError> {
        let tag = self.varint()?;
        let length = self.length(self.limits.max_bytes, "record-bytes")?;
        Ok((tag, self.take(length)?))
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn child<'b>(&self, payload: &'b [u8]) -> Reader<'b> {
        Reader {
            bytes: payload,
            offset: 0,
            limits: self.limits,
            nodes: self.nodes,
        }
    }

    fn absorb(&mut self, child: &Reader<'_>) {
        self.nodes = child.nodes;
    }

    fn count_node(&mut self) -> Result<(), DecodeError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(DecodeError::ResourceLimit("value-nodes"));
        }
        Ok(())
    }
}

fn decode_core_record(
    tag: u64,
    payload: &[u8],
    parent: &mut Reader<'_>,
    depth: usize,
) -> Result<PortableValue, DecodeError> {
    if depth > parent.limits.max_depth {
        return Err(DecodeError::ResourceLimit("nesting-depth"));
    }
    parent.count_node()?;
    let mut reader = parent.child(payload);
    let value = match tag {
        TAG_NULL if payload.is_empty() => PortableValue::null(),
        TAG_FALSE if payload.is_empty() => PortableValue::boolean(false),
        TAG_TRUE if payload.is_empty() => PortableValue::boolean(true),
        TAG_INTEGER => PortableValue::integer(decode_integer_payload(&mut reader)?),
        TAG_DECIMAL => PortableValue::decimal(decode_decimal_payload(&mut reader)?),
        TAG_FLOAT32 if payload.len() == 4 => {
            PortableValue::binary_float32(BinaryFloat32::from_bits(u32::from_be_bytes(
                reader.take(4)?.try_into().expect("length checked"),
            )))
        }
        TAG_FLOAT64 if payload.len() == 8 => {
            PortableValue::binary_float64(BinaryFloat64::from_bits(u64::from_be_bytes(
                reader.take(8)?.try_into().expect("length checked"),
            )))
        }
        TAG_NULL | TAG_FALSE | TAG_TRUE | TAG_FLOAT32 | TAG_FLOAT64 => {
            return Err(DecodeError::InvalidPayload(tag));
        }
        TAG_STRING => {
            let bytes = decode_blob(&mut reader)?;
            let string = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
            PortableValue::string(string)
        }
        TAG_BYTES => PortableValue::bytes(decode_blob(&mut reader)?),
        TAG_DATE => PortableValue::date(decode_date_payload(&mut reader)?),
        TAG_TIME => PortableValue::time(decode_time_payload(&mut reader)?),
        TAG_LOCAL_DATE_TIME => {
            PortableValue::local_date_time(decode_local_date_time_payload(&mut reader)?)
        }
        TAG_OFFSET_DATE_TIME => {
            let local = decode_local_date_time_payload(&mut reader)?;
            let offset = decode_integer_field(&mut reader)?
                .to_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or(DecodeError::InvalidTemporal)?;
            PortableValue::offset_date_time(
                OffsetDateTime::new(local, offset).map_err(map_build_error)?,
            )
        }
        TAG_SEQUENCE => {
            let count = reader.length(reader.limits.max_container_entries, "container-entries")?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let (child_tag, child_payload) = reader.record()?;
                if child_tag == TAG_EXTENDED {
                    return Err(DecodeError::NestedExtendedValue);
                }
                values.push(decode_core_record(
                    child_tag,
                    child_payload,
                    &mut reader,
                    depth + 1,
                )?);
            }
            PortableValue::sequence(values)
        }
        TAG_OBJECT => {
            let count = reader.length(reader.limits.max_container_entries, "container-entries")?;
            let mut builder = ObjectBuilder::new();
            for _ in 0..count {
                let (key_tag, key_payload) = reader.record()?;
                if key_tag != TAG_STRING {
                    return Err(DecodeError::ObjectKeyNotString);
                }
                let key_value = decode_core_record(key_tag, key_payload, &mut reader, depth + 1)?;
                let (value_tag, value_payload) = reader.record()?;
                if value_tag == TAG_EXTENDED {
                    return Err(DecodeError::NestedExtendedValue);
                }
                let value = decode_core_record(value_tag, value_payload, &mut reader, depth + 1)?;
                builder
                    .insert(key_value.as_string().expect("decoded string"), value)
                    .map_err(map_build_error)?;
            }
            builder.build()
        }
        TAG_ENTRY_MAPPING => {
            let count = reader.length(reader.limits.max_container_entries, "container-entries")?;
            let mut builder = EntryMappingBuilder::new();
            for _ in 0..count {
                let (key_tag, key_payload) = reader.record()?;
                let key = decode_core_record(key_tag, key_payload, &mut reader, depth + 1)?;
                let (value_tag, value_payload) = reader.record()?;
                let value = decode_core_record(value_tag, value_payload, &mut reader, depth + 1)?;
                builder.push(key, value);
            }
            builder.build()
        }
        TAG_EXTENDED => return Err(DecodeError::NestedExtendedValue),
        _ => return Err(DecodeError::UnknownCoreTag(tag)),
    };
    if !reader.is_empty() {
        return Err(DecodeError::TrailingPayload(tag));
    }
    parent.absorb(&reader);
    Ok(value)
}

fn decode_integer_payload(reader: &mut Reader<'_>) -> Result<BigInteger, DecodeError> {
    let sign = reader.octet()?;
    let length = reader.length(reader.limits.max_integer_bytes, "integer-bytes")?;
    let magnitude = reader.take(length)?;
    match (sign, magnitude) {
        (0, []) => Ok(BigInteger::zero()),
        (0, _) | (1 | 2, [] | [0, ..]) => Err(DecodeError::NonCanonicalInteger),
        (1, _) => BigInteger::from_sign_and_magnitude(1, magnitude).map_err(map_build_error),
        (2, _) => BigInteger::from_sign_and_magnitude(-1, magnitude).map_err(map_build_error),
        _ => Err(DecodeError::InvalidIntegerSign(sign)),
    }
}

fn decode_integer_field(reader: &mut Reader<'_>) -> Result<BigInteger, DecodeError> {
    let length = reader.length(
        reader.limits.max_integer_bytes.saturating_add(16),
        "integer-field",
    )?;
    let payload = reader.take(length)?;
    let mut field = reader.child(payload);
    let value = decode_integer_payload(&mut field)?;
    if !field.is_empty() {
        return Err(DecodeError::TrailingField);
    }
    Ok(value)
}

fn decode_decimal_payload(reader: &mut Reader<'_>) -> Result<Decimal, DecodeError> {
    let coefficient = decode_integer_field(reader)?;
    let exponent = decode_integer_field(reader)?;
    let decimal = Decimal::new(coefficient.clone(), exponent.clone());
    if decimal.coefficient() != &coefficient || decimal.exponent() != &exponent {
        return Err(DecodeError::NonCanonicalDecimal);
    }
    Ok(decimal)
}

fn decode_decimal_field(reader: &mut Reader<'_>) -> Result<Decimal, DecodeError> {
    let length = reader.length(
        reader
            .limits
            .max_integer_bytes
            .saturating_mul(2)
            .saturating_add(32),
        "decimal-field",
    )?;
    let payload = reader.take(length)?;
    let mut field = reader.child(payload);
    let value = decode_decimal_payload(&mut field)?;
    if !field.is_empty() {
        return Err(DecodeError::TrailingField);
    }
    Ok(value)
}

fn decode_blob<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    let length = reader.length(reader.limits.max_blob_bytes, "blob-bytes")?;
    reader.take(length)
}

fn decode_date_payload(reader: &mut Reader<'_>) -> Result<Date, DecodeError> {
    let year = decode_integer_field(reader)?;
    let month = reader.octet()?;
    let day = reader.octet()?;
    Date::new(year, month, day).map_err(map_build_error)
}

fn decode_date_field(reader: &mut Reader<'_>) -> Result<Date, DecodeError> {
    let length = reader.length(
        reader.limits.max_integer_bytes.saturating_add(32),
        "date-field",
    )?;
    let payload = reader.take(length)?;
    let mut field = reader.child(payload);
    let value = decode_date_payload(&mut field)?;
    if !field.is_empty() {
        return Err(DecodeError::TrailingField);
    }
    Ok(value)
}

fn decode_time_payload(reader: &mut Reader<'_>) -> Result<Time, DecodeError> {
    let hour = reader.octet()?;
    let minute = reader.octet()?;
    let second = reader.octet()?;
    let fraction = decode_decimal_field(reader)?;
    Time::new(hour, minute, second, fraction).map_err(map_build_error)
}

fn decode_time_field(reader: &mut Reader<'_>) -> Result<Time, DecodeError> {
    let length = reader.length(
        reader
            .limits
            .max_integer_bytes
            .saturating_mul(2)
            .saturating_add(64),
        "time-field",
    )?;
    let payload = reader.take(length)?;
    let mut field = reader.child(payload);
    let value = decode_time_payload(&mut field)?;
    if !field.is_empty() {
        return Err(DecodeError::TrailingField);
    }
    Ok(value)
}

fn decode_local_date_time_payload(reader: &mut Reader<'_>) -> Result<LocalDateTime, DecodeError> {
    Ok(LocalDateTime::new(
        decode_date_field(reader)?,
        decode_time_field(reader)?,
    ))
}

fn decode_extended(payload: &[u8], parent: &mut Reader<'_>) -> Result<ExtendedValue, DecodeError> {
    let mut reader = parent.child(payload);
    let type_id = std::str::from_utf8(decode_blob(&mut reader)?)
        .map_err(|_| DecodeError::InvalidUtf8)?
        .to_owned();
    let semantic_version =
        u32::try_from(reader.varint()?).map_err(|_| DecodeError::LengthOverflow)?;
    let codec = std::str::from_utf8(decode_blob(&mut reader)?)
        .map_err(|_| DecodeError::InvalidUtf8)?
        .to_owned();
    let canonical_payload = decode_blob(&mut reader)?.to_vec();
    if !reader.is_empty() {
        return Err(DecodeError::TrailingPayload(TAG_EXTENDED));
    }
    Ok(ExtendedValue::new(
        type_id,
        semantic_version,
        codec,
        canonical_payload,
    ))
}

fn map_build_error(error: ValueBuildError) -> DecodeError {
    match error {
        ValueBuildError::DuplicateObjectKey(_) => DecodeError::DuplicateObjectKey,
        ValueBuildError::InvalidDate
        | ValueBuildError::InvalidTime
        | ValueBuildError::InvalidOffset => DecodeError::InvalidTemporal,
        _ => DecodeError::InvalidValue,
    }
}

/// Strict canonical decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Stream magic did not match PVCE.
    InvalidMagic,
    /// Encoding version is unsupported.
    UnsupportedVersion(u64),
    /// Input ended inside a required field.
    UnexpectedEnd,
    /// More bytes followed the root record.
    TrailingBytes,
    /// More bytes followed a fully decoded payload.
    TrailingPayload(u64),
    /// More bytes followed a nested field.
    TrailingField,
    /// Unsigned varint was not shortest-form.
    NonCanonicalVarint,
    /// Unsigned varint exceeded `u64`.
    VarintOverflow,
    /// A length did not fit the host address space.
    LengthOverflow,
    /// Resource limit was reached.
    ResourceLimit(&'static str),
    /// Unknown core tag cannot become PortableValue.
    UnknownCoreTag(u64),
    /// A fixed payload did not match its tag.
    InvalidPayload(u64),
    /// Integer sign octet is not in the v1 registry.
    InvalidIntegerSign(u8),
    /// Integer representation was not unique canonical form.
    NonCanonicalInteger,
    /// Decimal coefficient/exponent were not normalized.
    NonCanonicalDecimal,
    /// String or identifier bytes were not valid UTF-8.
    InvalidUtf8,
    /// Object key record was not String.
    ObjectKeyNotString,
    /// Object contained a duplicate key.
    DuplicateObjectKey,
    /// Temporal fields were invalid.
    InvalidTemporal,
    /// Value construction failed.
    InvalidValue,
    /// ExtendedValue cannot be nested in the closed PortableValue tree.
    NestedExtendedValue,
    /// A core-only call encountered an extension root.
    ExpectedCoreValue,
}

impl Display for DecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use consema_core::{EntryMappingBuilder, SequenceBuilder};

    fn round_trip(value: PortableValue) {
        let bytes = encode(&value);
        assert_eq!(decode(&bytes, DecodeLimits::default()).unwrap(), value);
    }

    #[test]
    fn every_core_kind_round_trips() {
        let date = Date::new(BigInteger::from(-12_345_i64), 2, 28).unwrap();
        let time = Time::new(
            23,
            59,
            58,
            Decimal::new(BigInteger::from(125_i64), BigInteger::from(-3_i64)),
        )
        .unwrap();
        let local = LocalDateTime::new(date.clone(), time.clone());
        let offset = OffsetDateTime::new(local.clone(), -23 * 60 * 60).unwrap();
        let mut mapping = EntryMappingBuilder::new();
        mapping.push(PortableValue::boolean(true), PortableValue::null());
        let mut object = ObjectBuilder::new();
        object
            .insert("a", PortableValue::integer(BigInteger::from(1_i64)))
            .unwrap();
        object
            .insert("b", PortableValue::string("\u{4e2d}"))
            .unwrap();
        round_trip(object.build());
        let mut sequence = SequenceBuilder::new();
        for value in [
            PortableValue::null(),
            PortableValue::boolean(false),
            PortableValue::integer(
                BigInteger::parse_decimal("123456789012345678901234567890").unwrap(),
            ),
            PortableValue::decimal(Decimal::new(
                BigInteger::from(1_i64),
                BigInteger::from(-999_i64),
            )),
            PortableValue::binary_float32(BinaryFloat32::from_bits(0x7fc0_0001)),
            PortableValue::binary_float64(BinaryFloat64::from_bits(0x8000_0000_0000_0000)),
            PortableValue::string("é"),
            PortableValue::bytes(vec![0, 255]),
            PortableValue::date(date),
            PortableValue::time(time),
            PortableValue::local_date_time(local),
            PortableValue::offset_date_time(offset),
            mapping.build(),
        ] {
            sequence.push(value);
        }
        round_trip(sequence.build());
    }

    #[test]
    fn object_order_affects_encoding_and_is_strict() {
        let mut first = ObjectBuilder::new();
        first
            .insert("a", PortableValue::integer(BigInteger::from(1_i64)))
            .unwrap();
        first.insert("b", PortableValue::null()).unwrap();
        let mut second = ObjectBuilder::new();
        second.insert("b", PortableValue::null()).unwrap();
        second
            .insert("a", PortableValue::integer(BigInteger::from(1_i64)))
            .unwrap();
        assert_ne!(encode(&first.build()), encode(&second.build()));
    }

    #[test]
    fn object_byte_vector_is_frozen() {
        let mut object = ObjectBuilder::new();
        object
            .insert("a", PortableValue::integer(BigInteger::from(1_i64)))
            .unwrap();
        assert_eq!(
            hex(&encode(&object.build())),
            "5056434501410a01200201611003010101"
        );
    }

    #[test]
    fn bounded_encode_rejects_each_resource_limit() {
        let mut sequence = SequenceBuilder::new();
        sequence.push(PortableValue::string("12345"));
        sequence.push(PortableValue::string("67890"));
        sequence.push(PortableValue::string("abcde"));
        let value = sequence.build();
        assert_eq!(
            encode_bounded(
                &value,
                EncodeLimits {
                    max_bytes: 4,
                    ..EncodeLimits::default()
                }
            ),
            Err(EncodeError::ResourceLimit("stream-bytes"))
        );
        assert_eq!(
            encode_bounded(
                &value,
                EncodeLimits {
                    max_nodes: 2,
                    ..EncodeLimits::default()
                }
            ),
            Err(EncodeError::ResourceLimit("value-nodes"))
        );
        assert_eq!(
            encode_bounded(
                &value,
                EncodeLimits {
                    max_container_entries: 2,
                    ..EncodeLimits::default()
                }
            ),
            Err(EncodeError::ResourceLimit("container-entries"))
        );
        assert_eq!(
            encode_bounded(
                &PortableValue::string("12345"),
                EncodeLimits {
                    max_blob_bytes: 4,
                    ..EncodeLimits::default()
                }
            ),
            Err(EncodeError::ResourceLimit("blob-bytes"))
        );
        assert_eq!(
            encode_bounded(
                &PortableValue::integer(BigInteger::from(0x0102_i64)),
                EncodeLimits {
                    max_integer_bytes: 1,
                    ..EncodeLimits::default()
                }
            ),
            Err(EncodeError::ResourceLimit("integer-bytes"))
        );
        let mut nested = PortableValue::null();
        for _ in 0..3 {
            let mut level = SequenceBuilder::new();
            level.push(nested);
            nested = level.build();
        }
        assert_eq!(
            encode_bounded(
                &nested,
                EncodeLimits {
                    max_depth: 2,
                    ..EncodeLimits::default()
                }
            ),
            Err(EncodeError::ResourceLimit("nesting-depth"))
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut output, octet| {
            write!(output, "{octet:02x}").expect("String write");
            output
        })
    }

    #[test]
    fn extended_root_round_trips_opaquely() {
        let value = EncodedValue::Extended(ExtendedValue::new(
            "example.uuid",
            1,
            "example.raw@1",
            vec![1, 2, 3],
        ));
        let bytes = encode_value(&value);
        assert_eq!(
            decode_value(&bytes, DecodeLimits::default()).unwrap(),
            value
        );
    }

    #[test]
    fn rejects_non_minimal_version_varint() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[0x81, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode(&bytes, DecodeLimits::default()),
            Err(DecodeError::NonCanonicalVarint)
        );
    }

    #[test]
    fn rejects_noncanonical_zero_integer() {
        let bytes = [b'P', b'V', b'C', b'E', 1, 0x10, 3, 1, 1, 0];
        assert_eq!(
            decode(&bytes, DecodeLimits::default()),
            Err(DecodeError::NonCanonicalInteger)
        );
    }

    #[test]
    fn byte_vector_is_frozen() {
        assert_eq!(encode(&PortableValue::null()), b"PVCE\x01\x00\x00");
        assert_eq!(
            encode(&PortableValue::integer(BigInteger::from(-256_i64))),
            b"PVCE\x01\x10\x04\x02\x02\x01\x00"
        );
    }
}
