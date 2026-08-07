//! Safe internal DTD/entity boundary (RFC 0012 §3).
//!
//! The Profile permits no DOCTYPE or an internal-only DOCTYPE with a bounded
//! subset. External subsets, external/unparsed/parameter entities, notation,
//! and `ELEMENT`/`ATTLIST`/conditional declarations never trigger fallback
//! behavior. Expansion is guarded before and during allocation across the
//! whole document, not independently per reference.

/// One predefined XML entity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PredefinedEntity {
    /// Entity name without the `&` and `;`.
    pub name: &'static str,
    /// Replacement character data.
    pub value: &'static str,
}

/// The five predefined entities, always available with their XML meanings.
pub const PREDEFINED_ENTITIES: [PredefinedEntity; 5] = [
    PredefinedEntity {
        name: "lt",
        value: "<",
    },
    PredefinedEntity {
        name: "gt",
        value: ">",
    },
    PredefinedEntity {
        name: "amp",
        value: "&",
    },
    PredefinedEntity {
        name: "apos",
        value: "'",
    },
    PredefinedEntity {
        name: "quot",
        value: "\"",
    },
];

/// Returns the replacement value of a predefined entity by exact name.
#[must_use]
pub fn predefined_value(name: &str) -> Option<&'static str> {
    PREDEFINED_ENTITIES
        .iter()
        .find(|entity| entity.name == name)
        .map(|entity| entity.value)
}

/// Returns whether `c` is a legal XML 1.0 character.
#[must_use]
pub fn is_xml_char(c: char) -> bool {
    matches!(c as u32,
        0x09 | 0x0A | 0x0D
        | 0x20..=0xD7FF
        | 0xE000..=0xFFFD
        | 0x0001_0000..=0x0010_FFFF)
}

/// Replacement-text validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplacementError {
    /// The replacement text contains `<`, which would create entity-generated
    /// markup.
    ContainsMarkup,
    /// The replacement text contains an illegal XML 1.0 character.
    IllegalCharacter {
        /// The offending Unicode scalar value.
        scalar: u32,
    },
}

/// Validates one internal general entity value.
///
/// An admitted value may contain character data, character references,
/// predefined entity references, or references to another admitted internal
/// general entity, but never `<`.
pub fn validate_replacement_text(text: &str) -> Result<(), ReplacementError> {
    if text.contains('<') {
        return Err(ReplacementError::ContainsMarkup);
    }
    for c in text.chars() {
        if !is_xml_char(c) {
            return Err(ReplacementError::IllegalCharacter { scalar: c as u32 });
        }
    }
    Ok(())
}

/// Entity expansion breach category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpansionBreach {
    /// Too many entity declarations.
    DeclarationLimit,
    /// Too many entity references.
    ReferenceLimit,
    /// Reference expansion depth exceeded.
    DepthLimit,
    /// Expanded bytes exceed the document-wide budget.
    ExpandedBytes,
    /// Expanded scalars exceed the document-wide budget.
    ExpandedScalars,
    /// Expanded/declared byte amplification exceeds the ratio.
    Amplification,
}

/// Entity expansion limits derived from [`crate::XmlParseLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityExpansionLimits {
    /// Maximum entity declarations.
    pub max_declarations: usize,
    /// Maximum entity references.
    pub max_references: usize,
    /// Maximum reference expansion depth.
    pub max_expansion_depth: usize,
    /// Maximum expanded bytes across the whole document.
    pub max_expanded_bytes: usize,
    /// Maximum expanded scalars across the whole document.
    pub max_expanded_scalars: usize,
    /// Maximum expanded/declared byte amplification ratio.
    pub max_amplification_ratio: u64,
}

/// Document-wide entity expansion accounting.
///
/// Counters apply across the whole document, not independently per
/// reference, so an attack cannot split its budget across references.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EntityExpansionState {
    /// Collected internal general entity declarations.
    pub declarations: usize,
    /// Total references resolved.
    pub references: usize,
    /// Sum of declared replacement bytes.
    pub declared_bytes: usize,
    /// Sum of replacement scalars over all declarations.
    pub declared_scalars: usize,
    /// Total expanded bytes emitted.
    pub expanded_bytes: usize,
    /// Total expanded scalars emitted.
    pub expanded_scalars: usize,
    /// Current reference nesting depth.
    pub expansion_depth: usize,
}

impl EntityExpansionState {
    /// Creates an empty accounting state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one collected declaration with its replacement text size.
    pub fn record_declaration(
        &mut self,
        replacement_bytes: usize,
        replacement_scalars: usize,
        limits: EntityExpansionLimits,
    ) -> Result<(), ExpansionBreach> {
        if self.declarations >= limits.max_declarations {
            return Err(ExpansionBreach::DeclarationLimit);
        }
        self.declarations += 1;
        self.declared_bytes = self.declared_bytes.saturating_add(replacement_bytes);
        self.declared_scalars = self.declared_scalars.saturating_add(replacement_scalars);
        Ok(())
    }

    /// Enters one reference expansion and accounts its resolved size.
    pub fn enter_reference(
        &mut self,
        expanded_bytes: usize,
        expanded_scalars: usize,
        limits: EntityExpansionLimits,
    ) -> Result<(), ExpansionBreach> {
        if self.references >= limits.max_references {
            return Err(ExpansionBreach::ReferenceLimit);
        }
        if self.expansion_depth >= limits.max_expansion_depth {
            return Err(ExpansionBreach::DepthLimit);
        }
        self.references += 1;
        self.expansion_depth += 1;
        self.expanded_bytes = self.expanded_bytes.saturating_add(expanded_bytes);
        self.expanded_scalars = self.expanded_scalars.saturating_add(expanded_scalars);
        if self.expanded_bytes > limits.max_expanded_bytes {
            return Err(ExpansionBreach::ExpandedBytes);
        }
        if self.expanded_scalars > limits.max_expanded_scalars {
            return Err(ExpansionBreach::ExpandedScalars);
        }
        if self.expanded_bytes > self.amplification_bound(limits) {
            return Err(ExpansionBreach::Amplification);
        }
        Ok(())
    }

    /// Leaves one completed reference expansion.
    pub fn leave_reference(&mut self) {
        self.expansion_depth = self.expansion_depth.saturating_sub(1);
    }

    fn amplification_bound(&self, limits: EntityExpansionLimits) -> usize {
        self.declared_bytes
            .saturating_mul(usize::try_from(limits.max_amplification_ratio).unwrap_or(usize::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> EntityExpansionLimits {
        EntityExpansionLimits {
            max_declarations: 2,
            max_references: 4,
            max_expansion_depth: 2,
            max_expanded_bytes: 100,
            max_expanded_scalars: 100,
            max_amplification_ratio: 10,
        }
    }

    #[test]
    fn predefined_entities_have_their_xml_meanings() {
        assert_eq!(predefined_value("lt"), Some("<"));
        assert_eq!(predefined_value("gt"), Some(">"));
        assert_eq!(predefined_value("amp"), Some("&"));
        assert_eq!(predefined_value("apos"), Some("'"));
        assert_eq!(predefined_value("quot"), Some("\""));
        assert_eq!(predefined_value("nbsp"), None);
    }

    #[test]
    fn replacement_text_never_creates_markup() {
        assert_eq!(
            validate_replacement_text("a < b"),
            Err(ReplacementError::ContainsMarkup)
        );
        assert_eq!(validate_replacement_text("hello &amp; &lt;tag"), Ok(()));
        assert_eq!(
            validate_replacement_text("bad \u{0} char"),
            Err(ReplacementError::IllegalCharacter { scalar: 0 })
        );
    }

    #[test]
    fn xml_character_boundaries() {
        assert!(is_xml_char('\t'));
        assert!(is_xml_char('\n'));
        assert!(is_xml_char('\r'));
        assert!(is_xml_char(' '));
        assert!(is_xml_char('a'));
        assert!(is_xml_char('\u{FFFD}'));
        assert!(is_xml_char('\u{10000}'));
        assert!(!is_xml_char('\u{0}'));
        assert!(!is_xml_char('\u{1F}'));
        assert!(!is_xml_char('\u{FFFF}'));
        // Surrogate code points D800-DFFF and values above 10FFFF are not
        // representable as Rust chars, so they can never reach this check.
    }

    #[test]
    fn declaration_limit_is_document_wide() {
        let mut state = EntityExpansionState::new();
        let limits = limits();
        assert!(state.record_declaration(3, 3, limits).is_ok());
        assert!(state.record_declaration(3, 3, limits).is_ok());
        assert_eq!(
            state.record_declaration(3, 3, limits),
            Err(ExpansionBreach::DeclarationLimit)
        );
    }

    #[test]
    fn depth_and_reference_limits_apply() {
        let mut state = EntityExpansionState::new();
        let limits = limits();
        assert!(state.record_declaration(2, 2, limits).is_ok());
        assert!(state.enter_reference(2, 2, limits).is_ok());
        assert!(state.enter_reference(2, 2, limits).is_ok());
        assert_eq!(
            state.enter_reference(2, 2, limits),
            Err(ExpansionBreach::DepthLimit)
        );
        state.leave_reference();
        state.leave_reference();
        assert!(state.enter_reference(2, 2, limits).is_ok());
        assert!(state.enter_reference(2, 2, limits).is_ok());
        assert_eq!(
            state.enter_reference(2, 2, limits),
            Err(ExpansionBreach::ReferenceLimit)
        );
    }

    #[test]
    fn amplification_ratio_bounds_expansion() {
        let mut state = EntityExpansionState::new();
        let limits = limits();
        assert!(state.record_declaration(5, 5, limits).is_ok());
        // 5 declared bytes at ratio 10 allow at most 50 expanded bytes.
        assert!(state.enter_reference(45, 45, limits).is_ok());
        assert_eq!(
            state.enter_reference(6, 6, limits),
            Err(ExpansionBreach::Amplification)
        );
    }

    #[test]
    fn byte_and_scalar_budgets_apply() {
        let mut state = EntityExpansionState::new();
        let mut permissive = limits();
        permissive.max_amplification_ratio = u64::MAX;
        assert!(state.record_declaration(1, 1, permissive).is_ok());
        assert!(state.enter_reference(99, 1, permissive).is_ok());
        assert_eq!(
            state.enter_reference(2, 1, permissive),
            Err(ExpansionBreach::ExpandedBytes)
        );

        let mut state = EntityExpansionState::new();
        assert!(state.record_declaration(1, 1, permissive).is_ok());
        assert!(state.enter_reference(1, 99, permissive).is_ok());
        assert_eq!(
            state.enter_reference(1, 2, permissive),
            Err(ExpansionBreach::ExpandedScalars)
        );
    }
}
