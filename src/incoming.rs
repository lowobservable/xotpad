use regex::Regex;

use xotpad::x25::X25CallRequest;

pub struct IncomingTable {
    rules: Vec<(Regex, String)>,
}

impl IncomingTable {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add(&mut self, called_address: &str, command: String) -> Result<(), String> {
        let called_address = Regex::new(called_address).unwrap();

        self.rules.push((called_address, command));

        Ok(())
    }

    pub fn lookup(&self, call_request: &X25CallRequest) -> Option<String> {
        let called_address = call_request.called_address.to_string();

        for (called_address_expression, command) in self.rules.iter() {
            if !called_address_expression.is_match(&called_address) {
                continue;
            }

            // TODO: match on CUD...

            return Some(command.clone());
        }

        None
    }
}

impl Default for IncomingTable {
    fn default() -> Self {
        IncomingTable::new()
    }
}
