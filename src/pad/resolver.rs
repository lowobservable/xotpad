use crate::x121::X121Address;

pub trait Resolver {
    fn lookup(&self, address: &X121Address) -> Option<String>;
}
