use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(PartialEq, Debug)]
pub enum X29PadMessage {
    Set(Vec<(u8, u8)>),
    Read(Vec<u8>),
    SetRead(Vec<(u8, u8)>),
    Indicate(Vec<(u8, u8)>),
    ClearInvitation,
}

impl X29PadMessage {
    pub fn encode(&self, buf: &mut BytesMut) -> usize {
        match self {
            X29PadMessage::Indicate(params) => {
                buf.put_u8(0x00);

                let len = encode_params(params, buf);

                1 + len
            }
            _ => unimplemented!(),
        }
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, String> {
        #[allow(clippy::len_zero)]
        if buf.len() < 1 {
            return Err("message too short".into());
        }

        let code = buf.get_u8();

        match code {
            0x02 => {
                let params = decode_params(buf)?;

                let params = params.iter().map(|p| (p.0 & 0x7f, p.1)).collect();

                Ok(X29PadMessage::Set(params))
            }
            0x04 => {
                let params = decode_params(buf)?;

                if params.iter().any(|p| p.1 != 0) {
                    return Err("invalid param".into());
                }

                let params = params.iter().map(|p| p.0 & 0x7f).collect();

                Ok(X29PadMessage::Read(params))
            }
            0x06 => {
                let params = decode_params(buf)?;

                let params = params.iter().map(|p| (p.0 & 0x7f, p.1)).collect();

                Ok(X29PadMessage::SetRead(params))
            }
            0x01 => {
                #[allow(clippy::len_zero)]
                if buf.len() > 0 {
                    return Err("message too long".into());
                }

                Ok(X29PadMessage::ClearInvitation)
            }
            _ => Err("unrecognized X.29 PAD message".into()),
        }
    }
}

fn encode_params(params: &[(u8, u8)], buf: &mut BytesMut) -> usize {
    let mut len = 0;

    buf.reserve(params.len() * 2);

    for &(param, value) in params {
        buf.put_u8(param);
        buf.put_u8(value);

        len += 2;
    }

    len
}

fn decode_params(mut buf: Bytes) -> Result<Vec<(u8, u8)>, String> {
    if buf.len() % 2 != 0 {
        return Err("TODO".into());
    }

    let mut params = Vec::new();

    while !buf.is_empty() {
        let (param, value) = (buf.get_u8(), buf.get_u8());

        params.push((param, value));
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_set() {
        let buf = Bytes::from_static(b"\x02\x01\x00\x02\x7e");

        assert_eq!(
            X29PadMessage::decode(buf),
            Ok(X29PadMessage::Set(vec![(1, 0), (2, 126)]))
        );
    }

    #[test]
    fn decode_read() {
        let buf = Bytes::from_static(b"\x04\x01\x00\x02\x00");

        assert_eq!(
            X29PadMessage::decode(buf),
            Ok(X29PadMessage::Read(vec![1, 2]))
        );
    }

    #[test]
    fn decode_set_read() {
        let buf = Bytes::from_static(b"\x06\x01\x00\x02\x7e");

        assert_eq!(
            X29PadMessage::decode(buf),
            Ok(X29PadMessage::SetRead(vec![(1, 0), (2, 126)]))
        );
    }

    #[test]
    fn encode_indicate() {
        let message = X29PadMessage::Indicate(vec![(1, 0), (2, 126)]);

        let mut buf = BytesMut::new();

        assert_eq!(message.encode(&mut buf), 5);

        assert_eq!(&buf[..], b"\x00\x01\x00\x02\x7e");
    }

    #[test]
    fn decode_clear_invitation() {
        let buf = Bytes::from_static(b"\x01");

        assert_eq!(
            X29PadMessage::decode(buf),
            Ok(X29PadMessage::ClearInvitation)
        );
    }
}
