use crate::x121::X121Addr;

#[derive(Debug)]
pub struct XotResolver {
    xot_gateway: String,
}

impl XotResolver {
    pub fn new(xot_gateway: &str) -> Self {
        XotResolver {
            xot_gateway: xot_gateway.to_owned(),
        }
    }

    pub fn lookup(&self, x25_addr: &X121Addr) -> Option<String> {
        Some(self.xot_gateway.clone())
    }
}
