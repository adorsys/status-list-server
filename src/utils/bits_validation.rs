use serde::{Deserialize, Serialize};

/// Bits per status entry: 1, 2, 4 or 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitFlag(u8);

impl BitFlag {
    pub fn new(value: u8) -> Option<Self> {
        match value {
            1 | 2 | 4 | 8 => Some(BitFlag(value)),
            _ => None,
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::BitFlag;

    #[test]
    fn new_accepts_only_supported_widths() {
        for bits in [1, 2, 4, 8] {
            assert_eq!(BitFlag::new(bits).map(BitFlag::value), Some(bits));
        }
        for bits in [0, 3, 5, 16] {
            assert!(BitFlag::new(bits).is_none(), "{bits} must be rejected");
        }
    }
}
