//! X.121 addressing.
//!
//! This module provides functionality for handling X.121 addresses.

use std::fmt;
use std::str::FromStr;

/// X.121 address.
pub struct X121Address {
    address: String,
}

impl X121Address {
    /// Creates a new `X121Address` from digits.
    pub fn from_digits<I: IntoIterator<Item = u8>>(digits: I) -> Result<Self, String> {
        let digits: Vec<u8> = digits.into_iter().collect();

        if digits.len() > 15 {
            return Err("too many digits".into());
        }

        // TODO: are leading zeros valid?
        if !digits.iter().all(|&d| d <= 9) {
            return Err("digits must be between 0 and 9".into());
        }

        let address: String = digits.iter().map(|d| d.to_string()).collect();

        Ok(Self { address })
    }

    /// Returns `true` if the address has no digits, and `false` otherwise.
    pub fn is_null(&self) -> bool {
        self.address.is_empty()
    }

    /// Returns an iterator over the digits.
    pub fn digits(&self) -> impl Iterator<Item = u8> + '_ {
        self.address.chars().map(|c| c.to_digit(10).unwrap() as u8)
    }
}

impl fmt::Display for X121Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.address.fmt(f)
    }
}

impl FromStr for X121Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if s.len() > 15 {
            return Err("too long".into());
        }

        if !s.chars().all(|c| c.is_ascii_digit()) {
            return Err("all characters must be digits between 0 and 9".into());
        }

        Ok(Self { address: s.into() })
    }
}
