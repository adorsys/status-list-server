/// A strongly-typed wrapper for valid BitFlag values (1, 2, 4, or 8).
///
/// This struct ensures that only valid single-bit values are used,
/// preventing invalid values like 3, 5, or 6 from being constructed.
///
/// Use `BitFlag::new` or implement `TryFrom<u8>` to safely create an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitFlag(u8);

impl BitFlag {
    /// Attempts to create a new `BitFlag` instance from a given `u8` value.
    ///
    /// # Arguments
    ///
    /// * `value` - A `u8` representing the BitFlag. Must be one of: 1, 2, 4, or 8.
    ///
    /// # Returns
    ///
    /// * `Some(BitFlag)` if the value is valid.
    /// * `None` if the value is not a supported BitFlag.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::status_list_server::utils::bits_validation::BitFlag;
    /// let valid = BitFlag::new(4);
    /// assert!(valid.is_some());
    ///
    /// let invalid = BitFlag::new(3);
    /// assert!(invalid.is_none());
    /// ```
    pub fn new(value: u8) -> Option<Self> {
        match value {
            1 | 2 | 4 | 8 => Some(BitFlag(value)),
            _ => None,
        }
    }

    /// Returns the inner `u8` value of the `BitFlag`.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::status_list_server::utils::bits_validation::BitFlag;
    /// let bit = BitFlag::new(2).unwrap();
    /// assert_eq!(bit.value(), 2);
    /// ```
    pub fn value(self) -> u8 {
        self.0
    }
}
