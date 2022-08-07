use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

use crate::x25;

pub const TCP_PORT: u16 = 1998;

pub struct XotCodec {
    decoder_state: DecoderState,
}

enum DecoderState {
    Header,
    Data(usize),
}

const XOT_HEADER_LENGTH: usize = 4;

impl XotCodec {
    pub fn new() -> Self {
        Self {
            decoder_state: DecoderState::Header,
        }
    }
}

impl Default for XotCodec {
    fn default() -> Self {
        XotCodec::new()
    }
}

impl Encoder<Bytes> for XotCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buffer: &mut BytesMut) -> io::Result<()> {
        let version: u16 = 0;
        let length = data.len();

        if length < x25::MIN_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data less than minimum X.25 packet length",
            ));
        }

        if length > x25::MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data greater than maximum X.25 packet length",
            ));
        }

        buffer.reserve(XOT_HEADER_LENGTH + length);

        buffer.put_u16(version);
        buffer.put_u16(length as u16);
        buffer.put(data);

        Ok(())
    }
}

impl Decoder for XotCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, buffer: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if let DecoderState::Header = self.decoder_state {
            let length = match decode_header(buffer)? {
                Some((_, length)) => length,
                None => return Ok(None),
            };

            self.decoder_state = DecoderState::Data(length);

            buffer.reserve(length);
        }

        if let DecoderState::Data(length) = self.decoder_state {
            if buffer.len() < length {
                return Ok(None);
            }

            let data = buffer.split_to(length).freeze();

            self.decoder_state = DecoderState::Header;

            buffer.reserve(XOT_HEADER_LENGTH);

            Ok(Some(data))
        } else {
            Ok(None)
        }
    }
}

fn decode_header(buffer: &mut BytesMut) -> io::Result<Option<(u16, usize)>> {
    if buffer.len() < XOT_HEADER_LENGTH {
        return Ok(None);
    }

    let version = buffer.get_u16();
    let length = buffer.get_u16() as usize;

    if version != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid XOT version",
        ));
    }

    if length < x25::MIN_PACKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "length less than minimum X.25 packet length",
        ));
    }

    if length > x25::MAX_PACKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "length greater than maximum X.25 packet length",
        ));
    }

    Ok(Some((version, length)))
}
