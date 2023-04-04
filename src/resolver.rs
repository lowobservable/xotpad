use crate::x121::X121Addr;

#[derive(Debug)]
pub struct Resolver {
    xot_gateway: String,
}

impl Resolver {
    pub fn new(xot_gateway: &str) -> Self {
        Resolver {
            xot_gateway: xot_gateway.to_owned(),
        }
    }

    pub fn lookup(&self, x25_addr: &X121Addr) -> Option<String> {
        Some(self.xot_gateway.clone())
    }
}
