use bytes::Bytes;

pub enum X29PadMessage {
    ClearInvitation,
}

impl X29PadMessage {
    pub fn decode(buf: Bytes) -> Result<Self, String> {
        match &buf[..] {
            b"\x01" => Ok(X29PadMessage::ClearInvitation),
            _ => Err("unrecognized X.29 PAD message".into()),
        }
    }
}
