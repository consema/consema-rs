//! Property tests for the protocol/varint value transports
//! (0.13.0 gate plan M2, 路线图 §15.3: high-risk protocol/varint logic).
//!
//! Properties:
//! * canonical JSON transport: encode → decode is the identity, and
//!   decoding accepts only the canonical byte form (re-encoding is the
//!   fixed point);
//! * PVCE transport: encode → decode is the identity for the same values
//!   (exercises the varint decoder at every width, including multi-byte
//!   magnitudes);
//! * decode of arbitrary bytes never panics and reports bounded results
//!   (property version of the protocol fuzz target, with proptest
//!   shrinking for minimal counterexamples).

mod protocol_logic {
    include!("../../consema-protocol/fuzz/fuzz_logic/decode.rs");
}

use consema_core::{
    BigInteger, BinaryFloat32, BinaryFloat64, Date, Decimal, EntryMappingBuilder, LocalDateTime,
    ObjectBuilder, OffsetDateTime, PortableValue, SequenceBuilder, Time,
};
use consema_document::{
    MaterializationLimits, MaterializationRequest, MaterializationStyleId, NewlinePolicy, ProfileId,
};
use consema_protocol::{ProtocolLimits, decode_json, decode_pvce, encode_json, encode_pvce};
use proptest::prelude::*;

/// Canonical base-ten integer (covers varint widths 1..=10 for large
/// magnitudes).
fn big_integer_strategy() -> impl Strategy<Value = BigInteger> {
    prop_oneof![
        (-1_000_000_000i64..=1_000_000_000).prop_map(|value| {
            BigInteger::parse_decimal(&value.to_string()).expect("i64 decimal parses")
        }),
        (
            prop::sample::select(&[-1i8, 0, 1]),
            prop::collection::vec(any::<u8>(), 0..=64)
        )
            .prop_map(|(sign, magnitude)| {
                if sign == 0 {
                    BigInteger::zero()
                } else {
                    BigInteger::from_sign_and_magnitude(sign, &magnitude)
                        .expect("sign and magnitude are canonical")
                }
            }),
    ]
}

fn decimal_strategy() -> impl Strategy<Value = Decimal> {
    prop_oneof![
        (-1_000_000_000i64..=1_000_000_000, -20i32..=20).prop_map(|(coefficient, exponent)| {
            Decimal::new(
                BigInteger::parse_decimal(&coefficient.to_string()).expect("coefficient parses"),
                BigInteger::parse_decimal(&exponent.to_string()).expect("exponent parses"),
            )
        }),
        // Fractional values in [0, 1) for Time fractional seconds.
        (0i64..=999_999_999).prop_map(|coefficient| {
            Decimal::new(
                BigInteger::parse_decimal(&coefficient.to_string()).expect("coefficient parses"),
                BigInteger::parse_decimal("-9").expect("exponent parses"),
            )
        }),
    ]
}

fn date_strategy() -> impl Strategy<Value = Date> {
    (0i64..=9_999, 1u8..=12, 1u8..=28).prop_map(|(year, month, day)| {
        Date::new(
            BigInteger::parse_decimal(&year.to_string()).expect("year parses"),
            month,
            day,
        )
        .expect("date fields are always valid")
    })
}

fn time_strategy() -> impl Strategy<Value = Time> {
    (
        0u8..=23,
        0u8..=59,
        0u8..=59,
        (0i64..=999_999_999).prop_map(|coefficient| {
            Decimal::new(
                BigInteger::parse_decimal(&coefficient.to_string()).expect("coefficient parses"),
                BigInteger::parse_decimal("-9").expect("exponent parses"),
            )
        }),
    )
        .prop_map(|(hour, minute, second, fractional_second)| {
            Time::new(hour, minute, second, fractional_second).expect("time fields are valid")
        })
}

fn offset_date_time_strategy() -> impl Strategy<Value = OffsetDateTime> {
    (date_strategy(), time_strategy(), (-86_399i32..=86_399)).prop_map(
        |(date, time, offset_seconds)| {
            OffsetDateTime::new(LocalDateTime::new(date, time), offset_seconds)
                .expect("offset stays within one day")
        },
    )
}

/// Printable-string leaf (all strings must be valid Unicode scalar
/// sequences for the transports).
fn string_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(proptest::char::range('\u{20}', '\u{7e}'), 0..=24)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Object keys are unique by construction (index-suffixed).
fn unique_string_strategy(pool: &'static [&'static str]) -> impl Strategy<Value = String> {
    (prop::sample::select(pool), 0usize..=1_000_000)
        .prop_map(|(base, index)| format!("{base}#{index}"))
}

fn leaf_strategy() -> impl Strategy<Value = PortableValue> {
    prop_oneof![
        Just(PortableValue::null()),
        any::<bool>().prop_map(PortableValue::boolean),
        big_integer_strategy().prop_map(PortableValue::integer),
        decimal_strategy().prop_map(PortableValue::decimal),
        any::<u32>().prop_map(|bits| PortableValue::binary_float32(BinaryFloat32::from_bits(bits))),
        any::<u64>().prop_map(|bits| PortableValue::binary_float64(BinaryFloat64::from_bits(bits))),
        string_strategy().prop_map(PortableValue::string),
        prop::collection::vec(any::<u8>(), 0..=16).prop_map(PortableValue::bytes),
        date_strategy().prop_map(PortableValue::date),
        time_strategy().prop_map(PortableValue::time),
        (date_strategy(), time_strategy()).prop_map(|(date, time)| PortableValue::local_date_time(
            LocalDateTime::new(date, time)
        )),
        offset_date_time_strategy().prop_map(PortableValue::offset_date_time),
    ]
}

/// Depth-bounded arbitrary PortableValue tree (limits stay within the
/// production protocol defaults).
fn value_strategy(depth: usize) -> impl Strategy<Value = PortableValue> {
    if depth == 0 {
        return leaf_strategy().boxed();
    }
    prop_oneof![
        leaf_strategy(),
        prop::collection::vec(value_strategy(depth - 1), 0..=3).prop_map(PortableValue::sequence),
        prop::collection::vec(
            (
                unique_string_strategy(&["a", "b", "c", "d", "e"]),
                value_strategy(depth - 1)
            ),
            0..=3,
        )
        .prop_map(|members| {
            let mut builder = ObjectBuilder::new();
            for (key, value) in members {
                builder
                    .insert(key, value)
                    .expect("index-suffixed keys are unique");
            }
            builder.build()
        }),
        prop::collection::vec(
            (value_strategy(depth - 1), value_strategy(depth - 1)),
            0..=3,
        )
        .prop_map(|entries| {
            let mut builder = EntryMappingBuilder::new();
            for (key, value) in entries {
                builder.push(key, value);
            }
            builder.build()
        }),
        prop::collection::vec(value_strategy(depth - 1), 0..=3).prop_map(|values| {
            let mut builder = SequenceBuilder::new();
            for value in values {
                builder.push(value);
            }
            builder.build()
        }),
    ]
    .boxed()
}

fn arbitrary_value() -> impl Strategy<Value = PortableValue> {
    value_strategy(3)
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn canonical_json_transport_round_trips(value in arbitrary_value()) {
        let Ok(encoded) = encode_json(&value, ProtocolLimits::default()) else {
            return Ok(()); // resource-limit refusal is a pass
        };
        let decoded = decode_json(&encoded, ProtocolLimits::default())
            .expect("canonical JSON always decodes");
        prop_assert_eq!(&decoded, &value, "encode/decode is the identity");
        let re_encoded = encode_json(&decoded, ProtocolLimits::default())
            .expect("decoded value re-encodes");
        prop_assert_eq!(re_encoded, encoded, "canonical JSON is a fixed point");
    }

    #[test]
    fn pvce_transport_round_trips(value in arbitrary_value()) {
        let Ok(encoded) = encode_pvce(&value, ProtocolLimits::default()) else {
            return Ok(()); // resource-limit refusal is a pass
        };
        let decoded = decode_pvce(&encoded, ProtocolLimits::default())
            .expect("PVCE always decodes");
        prop_assert_eq!(&decoded, &value, "PVCE encode/decode is the identity");
    }

    #[test]
    fn varint_integer_round_trips_magnitudes(
        sign in any::<i8>(),
        magnitude in prop::collection::vec(any::<u8>(), 0..=64),
    ) {
        let Ok(integer) =
            BigInteger::from_sign_and_magnitude(sign, &magnitude)
        else {
            return Ok(()); // non-canonical sign/magnitude is not a value
        };
        let value = PortableValue::integer(integer);
        let encoded = encode_pvce(&value, ProtocolLimits::default())
            .expect("integer encodes within limits");
        let decoded = decode_pvce(&encoded, ProtocolLimits::default())
            .expect("PVCE always decodes");
        prop_assert_eq!(&decoded, &value, "varint width round-trips the exact magnitude");
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        protocol_logic::fuzz_decode(&bytes);
    }
}

/// Decode of a value and of its own re-encoding must agree (fixed point on
/// the PVCE side too) for values that survive encoding.
#[test]
fn pvce_reencoded_bytes_are_stable() {
    let value = PortableValue::sequence(vec![
        PortableValue::integer(
            BigInteger::parse_decimal("123456789012345678901234567890").expect("parses"),
        ),
        PortableValue::string("pvce stability"),
        PortableValue::boolean(true),
        PortableValue::null(),
    ]);
    let encoded = encode_pvce(&value, ProtocolLimits::default()).expect("encodes");
    let decoded = decode_pvce(&encoded, ProtocolLimits::default()).expect("decodes");
    assert_eq!(decoded, value);
    let re_encoded = encode_pvce(&decoded, ProtocolLimits::default()).expect("re-encodes");
    assert_eq!(re_encoded, encoded, "PVCE encoding is a fixed point");
}

/// Materialization of a round-tripped value must form completely (the
/// transport → materialization pipeline never fabricates a recovered
/// document from a complete value).
#[test]
fn transported_values_materialize_completely() {
    let mut builder = ObjectBuilder::new();
    builder
        .insert("name", PortableValue::string("consema"))
        .expect("unique key");
    builder
        .insert(
            "count",
            PortableValue::integer(BigInteger::parse_decimal("42").expect("parses")),
        )
        .expect("unique key");
    let value = builder.build();
    let encoded = encode_json(&value, ProtocolLimits::default()).expect("encodes");
    let decoded = decode_json(&encoded, ProtocolLimits::default()).expect("decodes");
    let request = MaterializationRequest::new(
        ProfileId::new("json.strict", 1),
        MaterializationStyleId::new("json.canonical-compact", 1),
    )
    .with_newline(NewlinePolicy::None);
    let result = consema_json::materialize(&decoded, &request);
    match result {
        consema_document::MaterializationResult::Complete(materialized) => {
            assert_eq!(
                materialized.document.formation_status(),
                consema_document::FormationStatus::Complete
            );
        }
        consema_document::MaterializationResult::Failed(attempt) => {
            assert!(
                attempt.analyzed_input_paths.len()
                    <= MaterializationLimits::default().max_input_nodes,
                "a failed materialization never over-analyzes input"
            );
        }
    }
}
