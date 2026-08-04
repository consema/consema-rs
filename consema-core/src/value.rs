//! Immutable PortableValue v1 implementation.

use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Sign of an arbitrary precision integer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum IntegerSign {
    Negative,
    Zero,
    Positive,
}

/// Canonical arbitrary-precision signed integer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BigInteger {
    sign: IntegerSign,
    magnitude: Arc<[u8]>,
}

impl BigInteger {
    /// Canonical zero.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            sign: IntegerSign::Zero,
            magnitude: Arc::from([]),
        }
    }

    /// Builds an integer from canonical sign and a big-endian magnitude.
    ///
    /// `sign` is `-1`, `0`, or `1`. Leading zero octets are removed. Zero is
    /// always normalized to an empty magnitude and sign `0`.
    pub fn from_sign_and_magnitude(sign: i8, magnitude: &[u8]) -> Result<Self, ValueBuildError> {
        if !(-1..=1).contains(&sign) {
            return Err(ValueBuildError::InvalidIntegerSign(sign));
        }
        let first_nonzero = magnitude
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(magnitude.len());
        let magnitude = &magnitude[first_nonzero..];
        if magnitude.is_empty() {
            return Ok(Self::zero());
        }
        if sign == 0 {
            return Err(ValueBuildError::ZeroSignWithMagnitude);
        }
        Ok(Self {
            sign: if sign < 0 {
                IntegerSign::Negative
            } else {
                IntegerSign::Positive
            },
            magnitude: Arc::from(magnitude),
        })
    }

    /// Parses a canonical value from a base-ten string with an optional sign.
    pub fn parse_decimal(text: &str) -> Result<Self, ValueBuildError> {
        let (sign, digits) = match text.as_bytes().first() {
            Some(b'-') => (-1, &text[1..]),
            Some(b'+') => (1, &text[1..]),
            _ => (1, text),
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ValueBuildError::InvalidInteger(text.to_owned()));
        }
        let mut magnitude = Vec::<u8>::new();
        for digit in digits.bytes().map(|byte| byte - b'0') {
            multiply_add_magnitude(&mut magnitude, 10, digit);
        }
        Self::from_sign_and_magnitude(sign, &magnitude)
    }

    /// Returns `-1`, `0`, or `1`.
    #[must_use]
    pub const fn signum(&self) -> i8 {
        match self.sign {
            IntegerSign::Negative => -1,
            IntegerSign::Zero => 0,
            IntegerSign::Positive => 1,
        }
    }

    /// Returns the minimal unsigned big-endian magnitude.
    #[must_use]
    pub fn magnitude(&self) -> &[u8] {
        &self.magnitude
    }

    /// Attempts an exact `i64` conversion.
    #[must_use]
    pub fn to_i64(&self) -> Option<i64> {
        if self.magnitude.len() > 8 {
            return None;
        }
        let unsigned = self
            .magnitude
            .iter()
            .fold(0_u64, |value, octet| (value << 8) | u64::from(*octet));
        match self.sign {
            IntegerSign::Zero => Some(0),
            IntegerSign::Positive => i64::try_from(unsigned).ok(),
            IntegerSign::Negative if unsigned == (1_u64 << 63) => Some(i64::MIN),
            IntegerSign::Negative => i64::try_from(unsigned).ok().map(i64::wrapping_neg),
        }
    }

    /// Attempts an exact `usize` conversion.
    #[must_use]
    pub fn to_usize(&self) -> Option<usize> {
        if self.sign == IntegerSign::Negative || self.magnitude.len() > size_of::<usize>() {
            return None;
        }
        let value = self
            .magnitude
            .iter()
            .fold(0_usize, |value, octet| (value << 8) | usize::from(*octet));
        Some(value)
    }

    /// Remainder of the absolute magnitude by a small positive divisor.
    #[must_use]
    pub fn magnitude_remainder(&self, divisor: u32) -> u32 {
        debug_assert!(divisor > 0);
        self.magnitude.iter().fold(0_u32, |remainder, octet| {
            ((remainder << 8) + u32::from(*octet)) % divisor
        })
    }

    fn add_one(&self) -> Self {
        match self.sign {
            IntegerSign::Zero => Self::from(1_i64),
            IntegerSign::Positive => {
                let mut bytes = self.magnitude.to_vec();
                add_one_magnitude(&mut bytes);
                Self::from_sign_and_magnitude(1, &bytes).expect("positive canonical magnitude")
            }
            IntegerSign::Negative => {
                let mut bytes = self.magnitude.to_vec();
                subtract_one_magnitude(&mut bytes);
                Self::from_sign_and_magnitude(-1, &bytes).expect("negative canonical magnitude")
            }
        }
    }

    fn divided_magnitude(&self, divisor: u32) -> Self {
        let (magnitude, remainder) = divide_magnitude(&self.magnitude, divisor);
        debug_assert_eq!(remainder, 0);
        Self::from_sign_and_magnitude(self.signum(), &magnitude)
            .expect("division preserves canonical sign")
    }

    fn absolute_decimal_digits(&self) -> usize {
        if self.sign == IntegerSign::Zero {
            1
        } else {
            magnitude_to_decimal(&self.magnitude).len()
        }
    }
}

impl From<i64> for BigInteger {
    fn from(value: i64) -> Self {
        if value == 0 {
            return Self::zero();
        }
        let sign = if value < 0 { -1 } else { 1 };
        let magnitude = value.unsigned_abs().to_be_bytes();
        Self::from_sign_and_magnitude(sign, &magnitude).expect("i64 has a valid sign")
    }
}

impl Display for BigInteger {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if self.sign == IntegerSign::Negative {
            formatter.write_str("-")?;
        }
        formatter.write_str(&magnitude_to_decimal(&self.magnitude))
    }
}

fn multiply_add_magnitude(bytes: &mut Vec<u8>, multiplier: u16, addend: u8) {
    let mut carry = u16::from(addend);
    for octet in bytes.iter_mut().rev() {
        let value = u16::from(*octet) * multiplier + carry;
        *octet = value as u8;
        carry = value >> 8;
    }
    while carry != 0 {
        bytes.insert(0, carry as u8);
        carry >>= 8;
    }
}

fn add_one_magnitude(bytes: &mut Vec<u8>) {
    for octet in bytes.iter_mut().rev() {
        let (next, overflow) = octet.overflowing_add(1);
        *octet = next;
        if !overflow {
            return;
        }
    }
    bytes.insert(0, 1);
}

fn subtract_one_magnitude(bytes: &mut Vec<u8>) {
    for octet in bytes.iter_mut().rev() {
        let (next, overflow) = octet.overflowing_sub(1);
        *octet = next;
        if !overflow {
            break;
        }
    }
    if bytes.first() == Some(&0) {
        bytes.remove(0);
    }
}

fn divide_magnitude(bytes: &[u8], divisor: u32) -> (Vec<u8>, u32) {
    let mut quotient = Vec::with_capacity(bytes.len());
    let mut remainder = 0_u32;
    for octet in bytes {
        let current = (remainder << 8) + u32::from(*octet);
        quotient.push((current / divisor) as u8);
        remainder = current % divisor;
    }
    let first_nonzero = quotient
        .iter()
        .position(|octet| *octet != 0)
        .unwrap_or(quotient.len());
    (quotient[first_nonzero..].to_vec(), remainder)
}

fn magnitude_to_decimal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_owned();
    }
    let mut current = bytes.to_vec();
    let mut digits = Vec::new();
    while !current.is_empty() {
        let (quotient, remainder) = divide_magnitude(&current, 10);
        digits.push(char::from(b'0' + remainder as u8));
        current = quotient;
    }
    digits.iter().rev().collect()
}

/// Canonical finite exact decimal `coefficient × 10^exponent`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Decimal {
    coefficient: BigInteger,
    exponent: BigInteger,
}

impl Decimal {
    /// Builds and normalizes a decimal.
    #[must_use]
    pub fn new(mut coefficient: BigInteger, mut exponent: BigInteger) -> Self {
        if coefficient.signum() == 0 {
            return Self {
                coefficient,
                exponent: BigInteger::zero(),
            };
        }
        while coefficient.magnitude_remainder(10) == 0 {
            coefficient = coefficient.divided_magnitude(10);
            exponent = exponent.add_one();
        }
        Self {
            coefficient,
            exponent,
        }
    }

    /// Parses JSON decimal-form syntax exactly.
    pub fn parse_json_number(text: &str) -> Result<Self, ValueBuildError> {
        let (mantissa, explicit_exponent) = match text.find(['e', 'E']) {
            Some(index) => (&text[..index], &text[index + 1..]),
            None => (text, "0"),
        };
        let exponent = BigInteger::parse_decimal(explicit_exponent)?;
        let negative = mantissa.starts_with('-');
        let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
        let (whole, fraction) = match unsigned.split_once('.') {
            Some(parts) => parts,
            None => (unsigned, ""),
        };
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ValueBuildError::InvalidDecimal(text.to_owned()));
        }
        let mut digits =
            String::with_capacity(whole.len() + fraction.len() + usize::from(negative));
        if negative {
            digits.push('-');
        }
        digits.push_str(whole);
        digits.push_str(fraction);
        let coefficient = BigInteger::parse_decimal(&digits)?;
        let exponent = add_signed_small(&exponent, -(fraction.len() as i64));
        Ok(Self::new(coefficient, exponent))
    }

    /// Canonical coefficient.
    #[must_use]
    pub const fn coefficient(&self) -> &BigInteger {
        &self.coefficient
    }

    /// Canonical exponent.
    #[must_use]
    pub const fn exponent(&self) -> &BigInteger {
        &self.exponent
    }

    fn is_fraction(&self) -> bool {
        if self.coefficient.signum() < 0 {
            return false;
        }
        if self.coefficient.signum() == 0 {
            return true;
        }
        match self.exponent.to_i64() {
            Some(exponent) => {
                exponent < 0
                    && i128::try_from(self.coefficient.absolute_decimal_digits())
                        .is_ok_and(|digits| digits + i128::from(exponent) <= 0)
            }
            None => self.exponent.signum() < 0,
        }
    }
}

fn add_signed_small(value: &BigInteger, amount: i64) -> BigInteger {
    if amount == 0 {
        return value.clone();
    }
    if let Some(current) = value.to_i64()
        && let Some(sum) = current.checked_add(amount)
    {
        return BigInteger::from(sum);
    }
    let mut result = value.clone();
    if amount > 0 {
        for _ in 0..amount.unsigned_abs() {
            result = result.add_one();
        }
    } else {
        result = negate(&negate(&result).add_one());
        for _ in 1..amount.unsigned_abs() {
            result = negate(&negate(&result).add_one());
        }
    }
    result
}

fn negate(value: &BigInteger) -> BigInteger {
    BigInteger::from_sign_and_magnitude(-value.signum(), value.magnitude())
        .expect("negation keeps a canonical sign")
}

/// Exact IEEE-754 binary32 datum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BinaryFloat32(u32);

impl BinaryFloat32 {
    /// Creates a value from the exact bit pattern.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the exact bit pattern.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Exact IEEE-754 binary64 datum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BinaryFloat64(u64);

impl BinaryFloat64 {
    /// Creates a value from the exact bit pattern.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns the exact bit pattern.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

/// Proleptic Gregorian date with astronomical year numbering.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Date {
    year: BigInteger,
    month: u8,
    day: u8,
}

impl Date {
    /// Validates and constructs a date.
    pub fn new(year: BigInteger, month: u8, day: u8) -> Result<Self, ValueBuildError> {
        if !(1..=12).contains(&month) {
            return Err(ValueBuildError::InvalidDate);
        }
        let leap = year.magnitude_remainder(4) == 0
            && (year.magnitude_remainder(100) != 0 || year.magnitude_remainder(400) == 0);
        let max_day = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if day == 0 || day > max_day {
            return Err(ValueBuildError::InvalidDate);
        }
        Ok(Self { year, month, day })
    }

    /// Astronomical year.
    #[must_use]
    pub const fn year(&self) -> &BigInteger {
        &self.year
    }

    /// Month number.
    #[must_use]
    pub const fn month(&self) -> u8 {
        self.month
    }

    /// Day number.
    #[must_use]
    pub const fn day(&self) -> u8 {
        self.day
    }
}

/// Wall-clock time without leap seconds or `24:00:00`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Time {
    hour: u8,
    minute: u8,
    second: u8,
    fractional_second: Decimal,
}

impl Time {
    /// Validates and constructs a time.
    pub fn new(
        hour: u8,
        minute: u8,
        second: u8,
        fractional_second: Decimal,
    ) -> Result<Self, ValueBuildError> {
        if hour > 23 || minute > 59 || second > 59 || !fractional_second.is_fraction() {
            return Err(ValueBuildError::InvalidTime);
        }
        Ok(Self {
            hour,
            minute,
            second,
            fractional_second,
        })
    }

    /// Hour.
    #[must_use]
    pub const fn hour(&self) -> u8 {
        self.hour
    }

    /// Minute.
    #[must_use]
    pub const fn minute(&self) -> u8 {
        self.minute
    }

    /// Second.
    #[must_use]
    pub const fn second(&self) -> u8 {
        self.second
    }

    /// Exact fractional second in `[0, 1)`.
    #[must_use]
    pub const fn fractional_second(&self) -> &Decimal {
        &self.fractional_second
    }
}

/// Date and time without an offset.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LocalDateTime {
    date: Date,
    time: Time,
}

impl LocalDateTime {
    /// Creates a local date-time.
    #[must_use]
    pub const fn new(date: Date, time: Time) -> Self {
        Self { date, time }
    }

    /// Date part.
    #[must_use]
    pub const fn date(&self) -> &Date {
        &self.date
    }

    /// Time part.
    #[must_use]
    pub const fn time(&self) -> &Time {
        &self.time
    }
}

/// Local date-time plus a fixed UTC offset in whole seconds.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OffsetDateTime {
    local: LocalDateTime,
    offset_seconds: i32,
}

impl OffsetDateTime {
    /// Validates and creates an offset date-time.
    pub fn new(local: LocalDateTime, offset_seconds: i32) -> Result<Self, ValueBuildError> {
        if offset_seconds.unsigned_abs() >= 24 * 60 * 60 {
            return Err(ValueBuildError::InvalidOffset);
        }
        Ok(Self {
            local,
            offset_seconds,
        })
    }

    /// Local date-time fields.
    #[must_use]
    pub const fn local(&self) -> &LocalDateTime {
        &self.local
    }

    /// Fixed UTC offset in seconds.
    #[must_use]
    pub const fn offset_seconds(&self) -> i32 {
        self.offset_seconds
    }
}

/// One uniquely named ordered object entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ObjectEntry {
    key: Arc<str>,
    value: PortableValue,
}

impl ObjectEntry {
    /// Entry key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Entry value.
    #[must_use]
    pub const fn value(&self) -> &PortableValue {
        &self.value
    }
}

/// One ordered, possibly duplicated arbitrary-key mapping association.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EntryMappingEntry {
    key: PortableValue,
    value: PortableValue,
}

impl EntryMappingEntry {
    /// Association key.
    #[must_use]
    pub const fn key(&self) -> &PortableValue {
        &self.key
    }

    /// Association value.
    #[must_use]
    pub const fn value(&self) -> &PortableValue {
        &self.value
    }
}

/// Closed PortableValue v1 kind registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PortableValueKind {
    /// Null.
    Null,
    /// Boolean.
    Boolean,
    /// Arbitrary precision integer.
    Integer,
    /// Exact finite decimal.
    Decimal,
    /// IEEE binary32 datum.
    BinaryFloat32,
    /// IEEE binary64 datum.
    BinaryFloat64,
    /// Unicode scalar sequence.
    String,
    /// Octet sequence.
    Bytes,
    /// Date.
    Date,
    /// Time.
    Time,
    /// Local date-time.
    LocalDateTime,
    /// Offset date-time.
    OffsetDateTime,
    /// Ordered value sequence.
    Sequence,
    /// Ordered unique-string-key object.
    Object,
    /// Ordered arbitrary-key association sequence.
    EntryMapping,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ValueNode {
    Null,
    Boolean(bool),
    Integer(BigInteger),
    Decimal(Decimal),
    BinaryFloat32(BinaryFloat32),
    BinaryFloat64(BinaryFloat64),
    String(Arc<str>),
    Bytes(Arc<[u8]>),
    Date(Date),
    Time(Time),
    LocalDateTime(LocalDateTime),
    OffsetDateTime(OffsetDateTime),
    Sequence(Arc<[PortableValue]>),
    Object(Arc<[ObjectEntry]>),
    EntryMapping(Arc<[EntryMappingEntry]>),
}

/// Immutable identity-free PortableValue tree.
#[derive(Clone, Debug)]
pub struct PortableValue(Arc<ValueNode>);

impl PartialEq for PortableValue {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PortableValue {}

impl Hash for PortableValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PortableValue {
    /// Null value.
    #[must_use]
    pub fn null() -> Self {
        Self(Arc::new(ValueNode::Null))
    }

    /// Boolean value.
    #[must_use]
    pub fn boolean(value: bool) -> Self {
        Self(Arc::new(ValueNode::Boolean(value)))
    }

    /// Integer value.
    #[must_use]
    pub fn integer(value: BigInteger) -> Self {
        Self(Arc::new(ValueNode::Integer(value)))
    }

    /// Decimal value.
    #[must_use]
    pub fn decimal(value: Decimal) -> Self {
        Self(Arc::new(ValueNode::Decimal(value)))
    }

    /// Binary32 value.
    #[must_use]
    pub fn binary_float32(value: BinaryFloat32) -> Self {
        Self(Arc::new(ValueNode::BinaryFloat32(value)))
    }

    /// Binary64 value.
    #[must_use]
    pub fn binary_float64(value: BinaryFloat64) -> Self {
        Self(Arc::new(ValueNode::BinaryFloat64(value)))
    }

    /// String value without normalization.
    #[must_use]
    pub fn string(value: impl Into<Arc<str>>) -> Self {
        Self(Arc::new(ValueNode::String(value.into())))
    }

    /// Raw octet value.
    #[must_use]
    pub fn bytes(value: impl Into<Arc<[u8]>>) -> Self {
        Self(Arc::new(ValueNode::Bytes(value.into())))
    }

    /// Date value.
    #[must_use]
    pub fn date(value: Date) -> Self {
        Self(Arc::new(ValueNode::Date(value)))
    }

    /// Time value.
    #[must_use]
    pub fn time(value: Time) -> Self {
        Self(Arc::new(ValueNode::Time(value)))
    }

    /// Local date-time value.
    #[must_use]
    pub fn local_date_time(value: LocalDateTime) -> Self {
        Self(Arc::new(ValueNode::LocalDateTime(value)))
    }

    /// Offset date-time value.
    #[must_use]
    pub fn offset_date_time(value: OffsetDateTime) -> Self {
        Self(Arc::new(ValueNode::OffsetDateTime(value)))
    }

    /// Ordered sequence value.
    #[must_use]
    pub fn sequence(values: impl Into<Arc<[PortableValue]>>) -> Self {
        Self(Arc::new(ValueNode::Sequence(values.into())))
    }

    /// Returns the closed core kind.
    #[must_use]
    pub fn kind(&self) -> PortableValueKind {
        match self.0.as_ref() {
            ValueNode::Null => PortableValueKind::Null,
            ValueNode::Boolean(_) => PortableValueKind::Boolean,
            ValueNode::Integer(_) => PortableValueKind::Integer,
            ValueNode::Decimal(_) => PortableValueKind::Decimal,
            ValueNode::BinaryFloat32(_) => PortableValueKind::BinaryFloat32,
            ValueNode::BinaryFloat64(_) => PortableValueKind::BinaryFloat64,
            ValueNode::String(_) => PortableValueKind::String,
            ValueNode::Bytes(_) => PortableValueKind::Bytes,
            ValueNode::Date(_) => PortableValueKind::Date,
            ValueNode::Time(_) => PortableValueKind::Time,
            ValueNode::LocalDateTime(_) => PortableValueKind::LocalDateTime,
            ValueNode::OffsetDateTime(_) => PortableValueKind::OffsetDateTime,
            ValueNode::Sequence(_) => PortableValueKind::Sequence,
            ValueNode::Object(_) => PortableValueKind::Object,
            ValueNode::EntryMapping(_) => PortableValueKind::EntryMapping,
        }
    }

    /// Boolean view.
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        match self.0.as_ref() {
            ValueNode::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// Integer view.
    #[must_use]
    pub fn as_integer(&self) -> Option<&BigInteger> {
        match self.0.as_ref() {
            ValueNode::Integer(value) => Some(value),
            _ => None,
        }
    }

    /// Decimal view.
    #[must_use]
    pub fn as_decimal(&self) -> Option<&Decimal> {
        match self.0.as_ref() {
            ValueNode::Decimal(value) => Some(value),
            _ => None,
        }
    }

    /// Binary32 view.
    #[must_use]
    pub fn as_binary_float32(&self) -> Option<BinaryFloat32> {
        match self.0.as_ref() {
            ValueNode::BinaryFloat32(value) => Some(*value),
            _ => None,
        }
    }

    /// Binary64 view.
    #[must_use]
    pub fn as_binary_float64(&self) -> Option<BinaryFloat64> {
        match self.0.as_ref() {
            ValueNode::BinaryFloat64(value) => Some(*value),
            _ => None,
        }
    }

    /// String view.
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self.0.as_ref() {
            ValueNode::String(value) => Some(value),
            _ => None,
        }
    }

    /// Bytes view.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self.0.as_ref() {
            ValueNode::Bytes(value) => Some(value),
            _ => None,
        }
    }

    /// Date view.
    #[must_use]
    pub fn as_date(&self) -> Option<&Date> {
        match self.0.as_ref() {
            ValueNode::Date(value) => Some(value),
            _ => None,
        }
    }

    /// Time view.
    #[must_use]
    pub fn as_time(&self) -> Option<&Time> {
        match self.0.as_ref() {
            ValueNode::Time(value) => Some(value),
            _ => None,
        }
    }

    /// Local date-time view.
    #[must_use]
    pub fn as_local_date_time(&self) -> Option<&LocalDateTime> {
        match self.0.as_ref() {
            ValueNode::LocalDateTime(value) => Some(value),
            _ => None,
        }
    }

    /// Offset date-time view.
    #[must_use]
    pub fn as_offset_date_time(&self) -> Option<&OffsetDateTime> {
        match self.0.as_ref() {
            ValueNode::OffsetDateTime(value) => Some(value),
            _ => None,
        }
    }

    /// Sequence view.
    #[must_use]
    pub fn as_sequence(&self) -> Option<&[PortableValue]> {
        match self.0.as_ref() {
            ValueNode::Sequence(value) => Some(value),
            _ => None,
        }
    }

    /// Object view.
    #[must_use]
    pub fn as_object(&self) -> Option<&[ObjectEntry]> {
        match self.0.as_ref() {
            ValueNode::Object(value) => Some(value),
            _ => None,
        }
    }

    /// Entry-mapping view.
    #[must_use]
    pub fn as_entry_mapping(&self) -> Option<&[EntryMappingEntry]> {
        match self.0.as_ref() {
            ValueNode::EntryMapping(value) => Some(value),
            _ => None,
        }
    }
}

/// Builder for a unique-key ordered object.
#[derive(Debug, Default)]
pub struct ObjectBuilder {
    entries: Vec<ObjectEntry>,
    keys: HashSet<String>,
}

impl ObjectBuilder {
    /// Empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one entry, rejecting a duplicate key.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: PortableValue,
    ) -> Result<&mut Self, ValueBuildError> {
        let key = key.into();
        if !self.keys.insert(key.clone()) {
            return Err(ValueBuildError::DuplicateObjectKey(key));
        }
        self.entries.push(ObjectEntry {
            key: Arc::from(key),
            value,
        });
        Ok(self)
    }

    /// Completes the immutable value.
    #[must_use]
    pub fn build(self) -> PortableValue {
        PortableValue(Arc::new(ValueNode::Object(Arc::from(self.entries))))
    }
}

/// Builder for an ordered arbitrary-key mapping.
#[derive(Debug, Default)]
pub struct EntryMappingBuilder {
    entries: Vec<EntryMappingEntry>,
}

impl EntryMappingBuilder {
    /// Empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends an association without deduplication.
    pub fn push(&mut self, key: PortableValue, value: PortableValue) -> &mut Self {
        self.entries.push(EntryMappingEntry { key, value });
        self
    }

    /// Completes the immutable value.
    #[must_use]
    pub fn build(self) -> PortableValue {
        PortableValue(Arc::new(ValueNode::EntryMapping(Arc::from(self.entries))))
    }
}

/// Builder for an ordered sequence.
#[derive(Debug, Default)]
pub struct SequenceBuilder(Vec<PortableValue>);

impl SequenceBuilder {
    /// Empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a value.
    pub fn push(&mut self, value: PortableValue) -> &mut Self {
        self.0.push(value);
        self
    }

    /// Completes the immutable value.
    #[must_use]
    pub fn build(self) -> PortableValue {
        PortableValue::sequence(self.0)
    }
}

/// Formally versioned extension value, separate from the closed core tree.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExtendedValue {
    type_id: Arc<str>,
    semantic_version: u32,
    payload_codec_id: Arc<str>,
    canonical_payload: Arc<[u8]>,
}

impl ExtendedValue {
    /// Creates an already validated canonical extension payload.
    #[must_use]
    pub fn new(
        type_id: impl Into<Arc<str>>,
        semantic_version: u32,
        payload_codec_id: impl Into<Arc<str>>,
        canonical_payload: impl Into<Arc<[u8]>>,
    ) -> Self {
        Self {
            type_id: type_id.into(),
            semantic_version,
            payload_codec_id: payload_codec_id.into(),
            canonical_payload: canonical_payload.into(),
        }
    }

    /// Stable extension type identifier.
    #[must_use]
    pub fn type_id(&self) -> &str {
        &self.type_id
    }

    /// Semantic contract version.
    #[must_use]
    pub const fn semantic_version(&self) -> u32 {
        self.semantic_version
    }

    /// Canonical payload codec identifier.
    #[must_use]
    pub fn payload_codec_id(&self) -> &str {
        &self.payload_codec_id
    }

    /// Canonical payload bytes.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

/// Portable value construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueBuildError {
    /// Integer text was malformed.
    InvalidInteger(String),
    /// Sign was not -1, 0 or 1.
    InvalidIntegerSign(i8),
    /// A non-empty magnitude used sign zero.
    ZeroSignWithMagnitude,
    /// Decimal text was malformed.
    InvalidDecimal(String),
    /// Date fields were outside the calendar.
    InvalidDate,
    /// Time fields were outside the supported range.
    InvalidTime,
    /// UTC offset was not less than 24 hours in magnitude.
    InvalidOffset,
    /// Object key was duplicated.
    DuplicateObjectKey(String),
}

impl Display for ValueBuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ValueBuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash(value: &PortableValue) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn arbitrary_integer_round_trip() {
        let text = "-340282366920938463463374607431768211457";
        assert_eq!(BigInteger::parse_decimal(text).unwrap().to_string(), text);
    }

    #[test]
    fn decimal_normalization_controls_equality_and_hash() {
        let left = PortableValue::decimal(Decimal::parse_json_number("1.00").unwrap());
        let right = PortableValue::decimal(Decimal::parse_json_number("10e-1").unwrap());
        assert_eq!(left, right);
        assert_eq!(hash(&left), hash(&right));
    }

    #[test]
    fn float_bits_are_strict() {
        let positive = PortableValue::binary_float64(BinaryFloat64::from_bits(0));
        let negative = PortableValue::binary_float64(BinaryFloat64::from_bits(1_u64 << 63));
        assert_ne!(positive, negative);
    }

    #[test]
    fn object_order_is_strict_and_duplicates_fail() {
        let mut first = ObjectBuilder::new();
        first.insert("a", PortableValue::null()).unwrap();
        first.insert("b", PortableValue::null()).unwrap();
        let mut second = ObjectBuilder::new();
        second.insert("b", PortableValue::null()).unwrap();
        second.insert("a", PortableValue::null()).unwrap();
        assert_ne!(first.build(), second.build());

        let mut duplicate = ObjectBuilder::new();
        duplicate.insert("x", PortableValue::null()).unwrap();
        assert!(matches!(
            duplicate.insert("x", PortableValue::null()),
            Err(ValueBuildError::DuplicateObjectKey(key)) if key == "x"
        ));
    }

    #[test]
    fn negative_year_leap_rule_uses_absolute_remainders() {
        assert!(Date::new(BigInteger::from(-400_i64), 2, 29).is_ok());
        assert!(Date::new(BigInteger::from(-100_i64), 2, 29).is_err());
    }
}
