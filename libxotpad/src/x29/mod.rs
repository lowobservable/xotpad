mod message;
mod pad;

pub use self::pad::{X29Pad, X29PadSignal};

#[cfg(fuzzing)]
pub mod fuzzing {
    use bytes::Bytes;

    use super::message::X29PadMessage;

    pub fn pad_message_decode(buf: Bytes) -> Result<X29PadMessage, String> {
        X29PadMessage::decode(buf)
    }
}
