//! Pinned Python 3.14 / Unicode 16.0 default `optionxform` semantics.

#![allow(clippy::unreadable_literal)]

// Generated from Rust 1.85's Unicode 16.0 unconditional full lowercase
// mappings and then compacted into ordered ranges and exceptions. Keeping the
// data in this crate prevents compiler Unicode-table upgrades from changing an
// already selected INI profile.
const LOWER_RANGES: &[(u32, u32, u32, i32)] = &[
    (0x000041, 0x00005A, 1, 32),
    (0x0000C0, 0x0000D6, 1, 32),
    (0x0000D8, 0x0000DE, 1, 32),
    (0x000100, 0x00012E, 2, 1),
    (0x000132, 0x000136, 2, 1),
    (0x000139, 0x000147, 2, 1),
    (0x00014A, 0x000176, 2, 1),
    (0x000179, 0x00017D, 2, 1),
    (0x000182, 0x000184, 2, 1),
    (0x000189, 0x00018A, 1, 205),
    (0x0001A0, 0x0001A4, 2, 1),
    (0x0001B1, 0x0001B2, 1, 217),
    (0x0001B3, 0x0001B5, 2, 1),
    (0x0001CB, 0x0001DB, 2, 1),
    (0x0001DE, 0x0001EE, 2, 1),
    (0x0001F2, 0x0001F4, 2, 1),
    (0x0001F8, 0x00021E, 2, 1),
    (0x000222, 0x000232, 2, 1),
    (0x000246, 0x00024E, 2, 1),
    (0x000370, 0x000372, 2, 1),
    (0x000388, 0x00038A, 1, 37),
    (0x00038E, 0x00038F, 1, 63),
    (0x000391, 0x0003A1, 1, 32),
    (0x0003A3, 0x0003AB, 1, 32),
    (0x0003D8, 0x0003EE, 2, 1),
    (0x0003FD, 0x0003FF, 1, -130),
    (0x000400, 0x00040F, 1, 80),
    (0x000410, 0x00042F, 1, 32),
    (0x000460, 0x000480, 2, 1),
    (0x00048A, 0x0004BE, 2, 1),
    (0x0004C1, 0x0004CD, 2, 1),
    (0x0004D0, 0x00052E, 2, 1),
    (0x000531, 0x000556, 1, 48),
    (0x0010A0, 0x0010C5, 1, 7264),
    (0x0013A0, 0x0013EF, 1, 38864),
    (0x0013F0, 0x0013F5, 1, 8),
    (0x001C90, 0x001CBA, 1, -3008),
    (0x001CBD, 0x001CBF, 1, -3008),
    (0x001E00, 0x001E94, 2, 1),
    (0x001EA0, 0x001EFE, 2, 1),
    (0x001F08, 0x001F0F, 1, -8),
    (0x001F18, 0x001F1D, 1, -8),
    (0x001F28, 0x001F2F, 1, -8),
    (0x001F38, 0x001F3F, 1, -8),
    (0x001F48, 0x001F4D, 1, -8),
    (0x001F59, 0x001F5F, 2, -8),
    (0x001F68, 0x001F6F, 1, -8),
    (0x001F88, 0x001F8F, 1, -8),
    (0x001F98, 0x001F9F, 1, -8),
    (0x001FA8, 0x001FAF, 1, -8),
    (0x001FB8, 0x001FB9, 1, -8),
    (0x001FBA, 0x001FBB, 1, -74),
    (0x001FC8, 0x001FCB, 1, -86),
    (0x001FD8, 0x001FD9, 1, -8),
    (0x001FDA, 0x001FDB, 1, -100),
    (0x001FE8, 0x001FE9, 1, -8),
    (0x001FEA, 0x001FEB, 1, -112),
    (0x001FF8, 0x001FF9, 1, -128),
    (0x001FFA, 0x001FFB, 1, -126),
    (0x002160, 0x00216F, 1, 16),
    (0x0024B6, 0x0024CF, 1, 26),
    (0x002C00, 0x002C2F, 1, 48),
    (0x002C67, 0x002C6B, 2, 1),
    (0x002C7E, 0x002C7F, 1, -10815),
    (0x002C80, 0x002CE2, 2, 1),
    (0x002CEB, 0x002CED, 2, 1),
    (0x00A640, 0x00A66C, 2, 1),
    (0x00A680, 0x00A69A, 2, 1),
    (0x00A722, 0x00A72E, 2, 1),
    (0x00A732, 0x00A76E, 2, 1),
    (0x00A779, 0x00A77B, 2, 1),
    (0x00A77E, 0x00A786, 2, 1),
    (0x00A790, 0x00A792, 2, 1),
    (0x00A796, 0x00A7A8, 2, 1),
    (0x00A7B4, 0x00A7C2, 2, 1),
    (0x00A7C7, 0x00A7C9, 2, 1),
    (0x00A7D6, 0x00A7DA, 2, 1),
    (0x00FF21, 0x00FF3A, 1, 32),
    (0x010400, 0x010427, 1, 40),
    (0x0104B0, 0x0104D3, 1, 40),
    (0x010570, 0x01057A, 1, 39),
    (0x01057C, 0x01058A, 1, 39),
    (0x01058C, 0x010592, 1, 39),
    (0x010594, 0x010595, 1, 39),
    (0x010C80, 0x010CB2, 1, 64),
    (0x010D50, 0x010D65, 1, 32),
    (0x0118A0, 0x0118BF, 1, 32),
    (0x016E40, 0x016E5F, 1, 32),
    (0x01E900, 0x01E921, 1, 34),
];

const LOWER_SINGLES: &[(u32, u32)] = &[
    (0x000178, 0x0000FF),
    (0x000181, 0x000253),
    (0x000186, 0x000254),
    (0x000187, 0x000188),
    (0x00018B, 0x00018C),
    (0x00018E, 0x0001DD),
    (0x00018F, 0x000259),
    (0x000190, 0x00025B),
    (0x000191, 0x000192),
    (0x000193, 0x000260),
    (0x000194, 0x000263),
    (0x000196, 0x000269),
    (0x000197, 0x000268),
    (0x000198, 0x000199),
    (0x00019C, 0x00026F),
    (0x00019D, 0x000272),
    (0x00019F, 0x000275),
    (0x0001A6, 0x000280),
    (0x0001A7, 0x0001A8),
    (0x0001A9, 0x000283),
    (0x0001AC, 0x0001AD),
    (0x0001AE, 0x000288),
    (0x0001AF, 0x0001B0),
    (0x0001B7, 0x000292),
    (0x0001B8, 0x0001B9),
    (0x0001BC, 0x0001BD),
    (0x0001C4, 0x0001C6),
    (0x0001C5, 0x0001C6),
    (0x0001C7, 0x0001C9),
    (0x0001C8, 0x0001C9),
    (0x0001CA, 0x0001CC),
    (0x0001F1, 0x0001F3),
    (0x0001F6, 0x000195),
    (0x0001F7, 0x0001BF),
    (0x000220, 0x00019E),
    (0x00023A, 0x002C65),
    (0x00023B, 0x00023C),
    (0x00023D, 0x00019A),
    (0x00023E, 0x002C66),
    (0x000241, 0x000242),
    (0x000243, 0x000180),
    (0x000244, 0x000289),
    (0x000245, 0x00028C),
    (0x000376, 0x000377),
    (0x00037F, 0x0003F3),
    (0x000386, 0x0003AC),
    (0x00038C, 0x0003CC),
    (0x0003CF, 0x0003D7),
    (0x0003F4, 0x0003B8),
    (0x0003F7, 0x0003F8),
    (0x0003F9, 0x0003F2),
    (0x0003FA, 0x0003FB),
    (0x0004C0, 0x0004CF),
    (0x0010C7, 0x002D27),
    (0x0010CD, 0x002D2D),
    (0x001C89, 0x001C8A),
    (0x001E9E, 0x0000DF),
    (0x001FBC, 0x001FB3),
    (0x001FCC, 0x001FC3),
    (0x001FEC, 0x001FE5),
    (0x001FFC, 0x001FF3),
    (0x002126, 0x0003C9),
    (0x00212A, 0x00006B),
    (0x00212B, 0x0000E5),
    (0x002132, 0x00214E),
    (0x002183, 0x002184),
    (0x002C60, 0x002C61),
    (0x002C62, 0x00026B),
    (0x002C63, 0x001D7D),
    (0x002C64, 0x00027D),
    (0x002C6D, 0x000251),
    (0x002C6E, 0x000271),
    (0x002C6F, 0x000250),
    (0x002C70, 0x000252),
    (0x002C72, 0x002C73),
    (0x002C75, 0x002C76),
    (0x002CF2, 0x002CF3),
    (0x00A77D, 0x001D79),
    (0x00A78B, 0x00A78C),
    (0x00A78D, 0x000265),
    (0x00A7AA, 0x000266),
    (0x00A7AB, 0x00025C),
    (0x00A7AC, 0x000261),
    (0x00A7AD, 0x00026C),
    (0x00A7AE, 0x00026A),
    (0x00A7B0, 0x00029E),
    (0x00A7B1, 0x000287),
    (0x00A7B2, 0x00029D),
    (0x00A7B3, 0x00AB53),
    (0x00A7C4, 0x00A794),
    (0x00A7C5, 0x000282),
    (0x00A7C6, 0x001D8E),
    (0x00A7CB, 0x000264),
    (0x00A7CC, 0x00A7CD),
    (0x00A7D0, 0x00A7D1),
    (0x00A7DC, 0x00019B),
    (0x00A7F5, 0x00A7F6),
];

pub(crate) fn optionxform(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        let code = u32::from(character);
        if code == 0x000130 {
            output.push('i');
            output.push('\u{0307}');
        } else if let Some(mapped) = simple_lowercase(code) {
            output.push(char::from_u32(mapped).expect("Unicode 16 lowercase is a scalar"));
        } else {
            output.push(character);
        }
    }
    output
}

fn simple_lowercase(code: u32) -> Option<u32> {
    let range_index = LOWER_RANGES.partition_point(|range| range.0 <= code);
    if let Some((start, _end, _step, delta)) = range_index
        .checked_sub(1)
        .and_then(|index| LOWER_RANGES.get(index))
        .copied()
        .filter(|(start, end, step, _)| code <= *end && code.saturating_sub(*start) % *step == 0)
    {
        debug_assert!(code >= start);
        return code.checked_add_signed(delta);
    }
    LOWER_SINGLES
        .binary_search_by_key(&code, |entry| entry.0)
        .ok()
        .map(|index| LOWER_SINGLES[index].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_16_full_lowercase_examples_are_exact() {
        assert_eq!(optionxform("Key"), "key");
        assert_eq!(optionxform("\u{0130}"), "i\u{0307}");
        assert_eq!(optionxform("\u{212A}\u{1E9E}"), "k\u{00DF}");
        assert_eq!(optionxform("\u{10400}"), "\u{10428}");
    }

    #[test]
    fn unicode_17_new_letters_remain_unassigned_under_the_frozen_profile() {
        for code in [0xA7CE, 0xA7D2, 0xA7D4]
            .into_iter()
            .chain(0x16EA0..=0x16EB8)
        {
            let character = char::from_u32(code).unwrap();
            assert_eq!(optionxform(&character.to_string()), character.to_string());
        }
    }

    #[test]
    fn table_is_exhaustive_against_the_msrv_unicode_16_runtime() {
        if char::UNICODE_VERSION != (16, 0, 0) {
            return;
        }
        for code in 0..=0x10_FFFF {
            let Some(character) = char::from_u32(code) else {
                continue;
            };
            assert_eq!(
                optionxform(&character.to_string()),
                character.to_lowercase().collect::<String>(),
                "lowercase mismatch at U+{code:04X}"
            );
        }
    }
}
