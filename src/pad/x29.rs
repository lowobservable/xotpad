use bytes::{Buf, Bytes};

pub enum X29PadMessage {
    ClearInvitation,
}

impl X29PadMessage {
    pub fn decode(mut buf: Bytes) -> Result<Self, String> {
        #[allow(clippy::len_zero)]
        if buf.len() < 1 {
            return Err("message too short".into());
        }

        let code = buf.get_u8();

        match code {
            0x01 => Ok(X29PadMessage::ClearInvitation),
            _ => Err("unrecognized X.29 PAD message".into()),
        }
    }
}
