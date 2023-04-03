use bytes::Bytes;

pub enum X29Command {
    ClearInvitation,
}

impl X29Command {
    pub fn decode(buf: Bytes) -> Result<Self, String> {
        match &buf[..] {
            b"\x01" => Ok(X29Command::ClearInvitation),
            _ => Err("unrecognized X.29 command".into()),
        }
    }
}
