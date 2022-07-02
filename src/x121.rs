use std::fmt;
use std::iter::IntoIterator;
use std::str::FromStr;

// TODO: are leading zeros valid?

/// A X.121 address.
#[derive(Clone, Debug)]
pub struct X121Address {
    address: String,
}

impl X121Address {
    /// Parse an address from a series of digits.
    pub fn from_digits<I: IntoIterator<Item = u8>>(digits: I) -> Result<X121Address, String> {
        let digits: Vec<u8> = digits.into_iter().collect();

        if digits.len() > 15 {
            return Err("too long!".into());
        }

        if !digits.iter().all(|&d| d <= 9) {
            return Err("all digits must be between 0 and 9!".into());
        }

        let address: String = digits.iter().map(|d| d.to_string()).collect();

        Ok(X121Address { address })
    }

    pub fn len(&self) -> usize {
        self.address.len()
    }

    /// Returns `true` if this address has no digits, and `false` otherwise.
    pub fn is_null(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the address digits.
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

    /// Parse an address from a string.
    fn from_str(address: &str) -> Result<X121Address, String> {
        if address.len() > 15 {
            return Err("too long!".into());
        }

        if !address.chars().all(|c| c.is_ascii_digit()) {
            return Err("all digits must be between 0 and 9!".into());
        }

        Ok(X121Address {
            address: address.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_digits_with_null_input() {
        let address = X121Address::from_digits([]);

        assert!(address.is_ok());

        assert_eq!(address.unwrap().to_string(), "");
    }

    #[test]
    fn test_from_digits_with_valid_input() {
        let address = X121Address::from_digits([7, 3, 7, 1, 0, 1]);

        assert!(address.is_ok());

        assert_eq!(address.unwrap().to_string(), "737101");
    }

    #[test]
    fn test_from_digits_with_too_long_input() {
        let address = X121Address::from_digits([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);

        assert!(address.is_err());
    }

    #[test]
    fn test_from_digits_with_out_of_range_input() {
        let address = X121Address::from_digits([7, 3, 7, 10]);

        assert!(address.is_err());
    }

    #[test]
    fn test_from_str_with_null_input() {
        let address = X121Address::from_str("");

        assert!(address.is_ok());

        assert_eq!(address.unwrap().to_string(), "");
    }

    #[test]
    fn test_from_str_with_valid_input() {
        let address = X121Address::from_str("737101");

        assert!(address.is_ok());

        assert_eq!(address.unwrap().to_string(), "737101");
    }

    #[test]
    fn test_from_str_with_too_long_input() {
        let address = X121Address::from_str("1234567890123456");

        assert!(address.is_err());
    }

    #[test]
    fn test_from_str_with_out_of_range_input() {
        let address = X121Address::from_str("12a");

        assert!(address.is_err());
    }
}
