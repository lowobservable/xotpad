//! X.121 addressing.
//!
//! This module provides functionality for handling X.121 addresses.

use std::fmt;
use std::str::FromStr;

/// X.121 address.
pub struct X121Addr {
    addr: String,
}

impl X121Addr {
    /// Creates a new `X121Addr` from digits.
    pub fn from_digits(digits: &[u8]) -> Result<Self, String> {
        if digits.len() > 15 {
            return Err("too many digits".into());
        }

        if !digits.iter().all(|&d| d <= 9) {
            return Err("digits must be between 0 and 9".into());
        }

        let addr: String = digits.iter().map(|d| d.to_string()).collect();

        Self::from_str(&addr)
    }

    /// Returns the number of digits.
    pub fn len(&self) -> usize {
        self.addr.len()
    }

    /// Returns `true` if the address has no digits, and `false` otherwise.
    pub fn is_null(&self) -> bool {
        self.addr.is_empty()
    }

    /// Returns an iterator over the digits.
    pub fn digits(&self) -> impl Iterator<Item = u8> + '_ {
        self.addr.chars().map(|c| c.to_digit(10).unwrap() as u8)
    }
}

impl fmt::Display for X121Addr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(fmt)
    }
}

impl FromStr for X121Addr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if s.len() > 15 {
            return Err("too long".into());
        }

        // TODO: are leading zeros valid?
        if !s.chars().all(|c| c.is_ascii_digit()) {
            return Err("all characters must be digits between 0 and 9".into());
        }

        Ok(Self { addr: s.into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_with_null_input() {
        let addr = X121Addr::from_str("");

        assert!(addr.is_ok());

        assert_eq!(addr.unwrap().to_string(), "");
    }

    #[test]
    fn from_str_with_valid_input() {
        let addr = X121Addr::from_str("73741100");

        assert!(addr.is_ok());

        assert_eq!(addr.unwrap().to_string(), "73741100");
    }

    #[test]
    fn from_str_with_too_long_input() {
        let addr = X121Addr::from_str("1234567890123456");

        assert!(addr.is_err());
    }

    #[test]
    fn from_str_with_non_digit_input() {
        let addr = X121Addr::from_str("123abc");

        assert!(addr.is_err());
    }

    #[test]
    fn from_digits_with_null_input() {
        let addr = X121Addr::from_digits(&[]);

        assert!(addr.is_ok());

        assert_eq!(addr.unwrap().to_string(), "");
    }

    #[test]
    fn from_digits_with_valid_input() {
        let addr = X121Addr::from_digits(&[7, 3, 7, 4, 1, 1, 0, 0]);

        assert!(addr.is_ok());

        assert_eq!(addr.unwrap().to_string(), "73741100");
    }

    #[test]
    fn from_digits_with_too_long_input() {
        let addr = X121Addr::from_digits(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);

        assert!(addr.is_err());
    }

    #[test]
    fn from_digits_with_out_of_range_digit_input() {
        let addr = X121Addr::from_digits(&[1, 2, 3, 10, 20, 100]);

        assert!(addr.is_err());
    }

    #[test]
    fn is_null_true() {
        let addr = X121Addr::from_str("").unwrap();

        assert!(addr.is_null());
    }

    #[test]
    fn is_null_false() {
        let addr = X121Addr::from_str("73741100").unwrap();

        assert!(!addr.is_null());
    }

    #[test]
    fn digits() {
        let addr = X121Addr::from_str("73741100").unwrap();

        let digits: Vec<u8> = addr.digits().collect();

        assert_eq!(digits, [7, 3, 7, 4, 1, 1, 0, 0]);
    }
}
