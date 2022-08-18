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
    pub fn from_digits<I: IntoIterator<Item = u8>>(digits: I) -> Result<Self, String> {
        let digits: Vec<u8> = digits.into_iter().collect();

        if digits.len() > 15 {
            return Err("too many digits".into());
        }

        if !digits.iter().all(|&d| d <= 9) {
            return Err("digits must be between 0 and 9".into());
        }

        let addr: String = digits.iter().map(|d| d.to_string()).collect();

        Self::from_str(&addr)
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

    // ...
}
