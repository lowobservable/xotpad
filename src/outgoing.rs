use regex::{Captures, Regex};

use xotpad::pad::Resolver;
use xotpad::x121::X121Address;

pub struct OutgoingTable {
    rules: Vec<(Regex, String)>,
}

impl OutgoingTable {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add(&mut self, address: &str, gateway: String) {
        let regex = Regex::new(address).unwrap();

        self.rules.push((regex, gateway));
    }
}

impl Resolver for OutgoingTable {
    fn lookup(&self, address: &X121Address) -> Option<String> {
        let address = address.to_string();

        for (regex, gateway_template) in self.rules.iter() {
            let captures = regex.captures(&address);

            if captures.is_none() {
                continue;
            }

            let gateway = xot_template_replace(gateway_template, captures.unwrap());

            return Some(gateway);
        }

        None
    }
}

impl Default for OutgoingTable {
    fn default() -> Self {
        OutgoingTable::new()
    }
}

fn xot_template_replace(template: &str, captures: Captures) -> String {
    let mut address = template.to_string();

    for index in 1..captures.len() {
        let pattern = "\\".to_owned() + &index.to_string();
        let replacement = captures.get(index).unwrap().as_str();

        address = address.replace(&pattern, replacement);
    }

    address
}
