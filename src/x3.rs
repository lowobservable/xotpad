//! X.3 PAD parameters.
//!
//! The X.3 parameters are specified in [ITU-T Rec. X.3 (03/00)].
//!
//! [ITU-T Rec. X.3 (03/00)]: https://www.itu.int/rec/T-REC-X.3-200003-I

use libxotpad::x3::X3ParamError;
use std::ops::Deref;
use std::time::Duration;

const PARAMS: [u8; 8] = [2, 3, 4, 13, 15, 16, 17, 18];

#[derive(Clone, Debug)]
pub struct X3Params {
    pub echo: X3Echo,

    pub forward: X3Forward,

    pub idle: X3Idle,

    pub lf_insert: X3LfInsert,

    pub editing: X3Editing,

    pub char_delete: X3CharDelete,

    pub line_delete: X3LineDelete,

    pub line_display: X3LineDisplay,
}

impl libxotpad::x3::X3Params for X3Params {
    fn get(&self, param: u8) -> Option<u8> {
        match param {
            2 => Some(*self.echo),
            3 => Some(*self.forward),
            4 => Some(*self.idle),
            13 => Some(*self.lf_insert),
            15 => Some(*self.editing),
            16 => Some(*self.char_delete),
            17 => Some(*self.line_delete),
            18 => Some(*self.line_display),
            _ => None,
        }
    }

    fn set(&mut self, param: u8, value: u8) -> Result<(), X3ParamError> {
        match param {
            2 => self.echo = X3Echo::try_from(value)?,
            3 => self.forward = X3Forward::try_from(value)?,
            4 => self.idle = X3Idle::from(value),
            13 => self.lf_insert = X3LfInsert::try_from(value)?,
            15 => self.editing = X3Editing::try_from(value)?,
            16 => self.char_delete = X3CharDelete::try_from(value)?,
            17 => self.line_delete = X3LineDelete::try_from(value)?,
            18 => self.line_display = X3LineDisplay::try_from(value)?,
            _ => return Err(X3ParamError::Unsupported),
        };

        Ok(())
    }

    fn all(&self) -> Vec<(u8, u8)> {
        let mut params = Vec::new();

        for param in PARAMS {
            params.push((param, self.get(param).unwrap()));
        }

        params
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3Echo(u8);

impl Deref for X3Echo {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3Echo {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 | 1 => Ok(X3Echo(value)),
            _ => Err(X3ParamError::InvalidValue),
        }
    }
}

impl From<X3Echo> for bool {
    fn from(echo: X3Echo) -> Self {
        match echo {
            X3Echo(0) => false,
            X3Echo(1) => true,
            _ => unreachable!(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3Forward(u8);

impl Deref for X3Forward {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3Forward {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 127 {
            return Err(X3ParamError::InvalidValue);
        }

        Ok(X3Forward(value))
    }
}

impl X3Forward {
    pub fn is_match(&self, byte: u8) -> bool {
        let forward = self.0;

        if forward & 1 == 1 && byte.is_ascii_alphanumeric() {
            return true;
        }

        // CR (0x0d)
        if forward & 2 == 2 && byte == 0x0d {
            return true;
        }

        // ESC (0x1b) BEL (0x07) ENQ (0x05) ACK (0x06)
        if forward & 4 == 4 && [0x1b, 0x07, 0x05, 0x06].contains(&byte) {
            return true;
        }

        // DEL (0x7f), CAN (0x18), DC2 (0x12)
        if forward & 8 == 8 && [0x7f, 0x18, 0x12].contains(&byte) {
            return true;
        }

        // EOT (0x04), ETX (0x03)
        if forward & 16 == 16 && [0x04, 0x03].contains(&byte) {
            return true;
        }

        // HT (0x09), LF (0x0a), VT (0x0b), FF (0x0c)
        if forward & 32 == 32 && [0x09, 0x0a, 0x0b, 0x0c].contains(&byte) {
            return true;
        }

        // Everything else from IA5 columns 0 and 1...
        if forward & 64 == 64
            && [
                0x00, 0x01, 0x02, 0x08, 0x0e, 0x0f, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19,
                0x1a, 0x1c, 0x1d, 0x1e, 0x1f,
            ]
            .contains(&byte)
        {
            return true;
        }

        false
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3Idle(u8);

impl Deref for X3Idle {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u8> for X3Idle {
    fn from(value: u8) -> Self {
        X3Idle(value)
    }
}

impl From<X3Idle> for Option<Duration> {
    fn from(idle: X3Idle) -> Self {
        match idle {
            X3Idle(0) => None,
            X3Idle(delay) => Some(Duration::from_millis(u64::from(delay) * 50)),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3LfInsert(u8);

impl Deref for X3LfInsert {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3LfInsert {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 7 {
            return Err(X3ParamError::InvalidValue);
        }

        Ok(X3LfInsert(value))
    }
}

impl X3LfInsert {
    pub fn after_recv(&self, byte: u8) -> bool {
        byte == /* CR */ 0x0d && (self.0 & 1 == 1)
    }

    pub fn after_send(&self, byte: u8) -> bool {
        byte == /* CR */ 0x0d && (self.0 & 2 == 2)
    }

    pub fn after_echo(&self, byte: u8) -> bool {
        byte == /* CR */ 0x0d && (self.0 & 4 == 4)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3Editing(u8);

impl Deref for X3Editing {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3Editing {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 | 1 => Ok(X3Editing(value)),
            _ => Err(X3ParamError::InvalidValue),
        }
    }
}

impl From<X3Editing> for bool {
    fn from(editing: X3Editing) -> Self {
        match editing {
            X3Editing(0) => false,
            X3Editing(1) => true,
            _ => unreachable!(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3CharDelete(u8);

impl Deref for X3CharDelete {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3CharDelete {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            127 => Ok(X3CharDelete(value)),
            _ => Err(X3ParamError::InvalidValue),
        }
    }
}

impl X3CharDelete {
    pub fn is_match(&self, byte: u8) -> bool {
        byte == self.0
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3LineDelete(u8);

impl Deref for X3LineDelete {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3LineDelete {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 127 {
            return Err(X3ParamError::InvalidValue);
        }

        Ok(X3LineDelete(value))
    }
}

impl X3LineDelete {
    pub fn is_match(&self, byte: u8) -> bool {
        byte == self.0
    }
}

#[derive(Copy, Clone, Debug)]
pub struct X3LineDisplay(u8);

impl Deref for X3LineDisplay {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<u8> for X3LineDisplay {
    type Error = X3ParamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 127 {
            return Err(X3ParamError::InvalidValue);
        }

        Ok(X3LineDisplay(value))
    }
}

impl X3LineDisplay {
    pub fn is_match(&self, byte: u8) -> bool {
        byte == self.0
    }
}
