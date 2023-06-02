//! X.3 PAD parameters.
//!
//! TODO

pub trait X3Params {
    fn get(&self, param: u8) -> Option<u8>;

    fn set(&mut self, param: u8, value: u8) -> Result<(), X3ParamError>;

    fn all(&self) -> Vec<(u8, u8)>;
}

#[derive(Debug)]
pub enum X3ParamError {
    Unsupported,
    InvalidValue,
}
