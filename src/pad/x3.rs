pub const PARAMS: [u8; 3] = [2, 3, 4];

#[derive(Clone, Debug)]
pub struct X3Params {
    pub echo: bool,

    pub forward: u8,

    pub idle: u8,
}

impl X3Params {
    pub fn get(&self, param: u8) -> Option<u8> {
        match param {
            2 => Some(u8::from(self.echo)),
            3 => Some(self.forward),
            4 => Some(self.idle),
            _ => None,
        }
    }

    pub fn set(&mut self, param: u8, value: u8) -> Result<(), String> {
        match param {
            2 => {
                self.echo = match value {
                    0 => false,
                    1 => true,
                    _ => return Err("unsupported parameter value".into()),
                }
            }
            3 => self.forward = value,
            4 => self.idle = value,
            _ => return Err("unsupported parameter".into()),
        };

        Ok(())
    }
}
