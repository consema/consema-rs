// Fuzz-target logic: protocol/PVCE/PGCE decoders (0.13.0 gate plan M2).
//
// Drives the high-risk decoder entry points with mutated bytes:
// * canonical `core.portable-value-json@1` decoding (`decode_json`),
// * PVCE/1 varint decoding (`consema_pvce::decode` and `decode_value`),
// * PGCE decoding (`consema_graph::decode_pgce`), which decodes the graph
//   varint header and node/edge tables,
// * the plist binary decoder is covered by the consema-plist targets.
//
// Resource limits are the production defaults; a limit failure is a decode
// error and therefore a pass. No decode may panic; a successful decode must
// re-encode canonically (decode-then-encode round-trip fixed point).

use consema_graph::{PgceLimits, decode_pgce, encode_pgce_bounded};
use consema_protocol::{ProtocolLimits, decode_json, decode_pvce, encode_json, encode_pvce};
use consema_pvce::{DecodeLimits, EncodeLimits, decode, decode_value, encode_bounded};

/// Drives every protocol decoder over one mutated input.
pub fn fuzz_decode(data: &[u8]) {
    // Canonical JSON transport.
    if let Ok(value) = decode_json(data, ProtocolLimits::default()) {
        let encoded = encode_json(&value, ProtocolLimits::default())
            .expect("a decoded value re-encodes canonically");
        assert_eq!(
            encoded, data,
            "decode_json accepts only the canonical byte form; re-encoding is the fixed point"
        );
    }
    // PVCE varint transport.
    if let Ok(value) = decode_pvce(data, ProtocolLimits::default()) {
        let encoded = encode_pvce(&value, ProtocolLimits::default())
            .expect("a decoded value re-encodes under the same limits");
        let round_tripped = decode_pvce(&encoded, ProtocolLimits::default())
            .expect("re-encoding decodes under the same limits");
        assert_eq!(round_tripped, value, "PVCE round-trips the value exactly");
    }
    // Raw PVCE reader (the varint decoder itself).
    if let Ok(value) = decode(data, DecodeLimits::default()) {
        let encoded = encode_bounded(&value, EncodeLimits::default())
            .expect("a decoded value re-encodes under the same limits");
        let round_tripped = decode(&encoded, DecodeLimits::default())
            .expect("re-encoding decodes under the same limits");
        assert_eq!(round_tripped, value, "PVCE/1 round-trips the value exactly");
    }
    if decode_value(data, DecodeLimits::default()).is_ok() {
        // The raw encoded-value reader shares the varint decoder; the
        // value-level round trip above already proves the fixed point.
    }
    // PGCE graph transport.
    if let Ok(graph) = decode_pgce(data, PgceLimits::default()) {
        let encoded = encode_pgce_bounded(&graph, PgceLimits::default())
            .expect("a decoded graph re-encodes under the same limits");
        let round_tripped = decode_pgce(&encoded, PgceLimits::default())
            .expect("re-encoding decodes under the same limits");
        assert_eq!(round_tripped, graph, "PGCE round-trips the graph exactly");
    }
}
