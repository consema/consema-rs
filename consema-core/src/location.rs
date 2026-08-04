//! Portable value and association locations.

/// One segment of a root-relative portable value path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ValuePathSegment {
    /// Value of a uniquely named object entry.
    ObjectValue(String),
    /// Sequence element at a non-negative index.
    SequenceElement(u64),
    /// Key value of an entry-mapping association.
    EntryKey(u64),
    /// Value of an entry-mapping association.
    EntryValue(u64),
}

/// A path to a value; the empty path denotes the root.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValuePath(Vec<ValuePathSegment>);

impl ValuePath {
    /// Root path.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Returns path segments.
    #[must_use]
    pub fn segments(&self) -> &[ValuePathSegment] {
        &self.0
    }

    /// Creates a child path without modifying this path.
    #[must_use]
    pub fn child(&self, segment: ValuePathSegment) -> Self {
        let mut segments = self.0.clone();
        segments.push(segment);
        Self(segments)
    }
}

/// Association kind independent from child values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AssociationRole {
    /// Whole object entry.
    ObjectEntry,
    /// The name role of an object entry.
    ObjectKey,
    /// Whole entry-mapping association.
    EntryMappingEntry,
}

/// Location of an association, not a portable value node.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssociationLocation {
    container: ValuePath,
    ordinal: u64,
    role: AssociationRole,
}

impl AssociationLocation {
    /// Creates an association location.
    #[must_use]
    pub const fn new(container: ValuePath, ordinal: u64, role: AssociationRole) -> Self {
        Self {
            container,
            ordinal,
            role,
        }
    }

    /// Path of the containing value.
    #[must_use]
    pub const fn container(&self) -> &ValuePath {
        &self.container
    }

    /// Structural association ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Association role.
    #[must_use]
    pub const fn role(&self) -> AssociationRole {
        self.role
    }
}
