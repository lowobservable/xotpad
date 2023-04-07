use regex::{Captures, Regex};

use crate::x121::X121Addr;

#[derive(Debug)]
pub struct XotResolver {
    rules: Vec<(Regex, String)>,
}

impl XotResolver {
    pub fn new() -> Self {
        XotResolver { rules: vec![] }
    }

    pub fn add(&mut self, x25_addr: &str, gateway: &str) -> Result<(), String> {
        let regex = Regex::new(x25_addr).map_err(|e| "TODO")?;

        self.rules.push((regex, gateway.into()));

        Ok(())
    }

    pub fn lookup(&self, x25_addr: &X121Addr) -> Option<String> {
        let x25_addr = x25_addr.to_string();

        for (regex, gateway) in self.rules.iter() {
            if let Some(captures) = regex.captures(&x25_addr) {
                return Some(template_replace(gateway, captures));
            }
        }

        None
    }
}

impl Default for XotResolver {
    fn default() -> Self {
        XotResolver::new()
    }
}

fn template_replace(template: &str, captures: Captures) -> String {
    let mut value = template.to_string();

    for (index, replacement) in captures.iter().enumerate().skip(1) {
        let pattern = format!("\\{index}");

        value = value.replace(&pattern, replacement.unwrap().into());
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn lookup_hit_with_default() {
        let mut resolver = XotResolver::new();

        let _ = resolver.add(".*", "gateway");

        let x25_addr = X121Addr::from_str("12345678").unwrap();

        assert_eq!(resolver.lookup(&x25_addr), Some("gateway".into()));
    }

    #[test]
    fn lookup_hit_with_replacement() {
        let mut resolver = XotResolver::new();

        let _ = resolver.add("^(...)(...)..", "\\2.\\1.x25.org");

        let x25_addr = X121Addr::from_str("12345678").unwrap();

        assert_eq!(resolver.lookup(&x25_addr), Some("456.123.x25.org".into()));
    }

    #[test]
    fn lookup_miss() {
        let mut resolver = XotResolver::new();

        let _ = resolver.add("11111111", "gateway1");
        let _ = resolver.add("22222222", "gateway2");

        let x25_addr = X121Addr::from_str("33333333").unwrap();

        assert_eq!(resolver.lookup(&x25_addr), None);
    }
}
