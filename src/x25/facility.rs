//! X.25 facilities.
//!
//! This module provides functionality for encoding and decoding X.25 facilities.
//!
//! X.25 facilities can be included in _call request_, _call accepted_, _clear request_
//! and _clear confirmation_ packets.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;
use std::convert::TryFrom;

/// An X.25 facility.
#[derive(PartialEq, Debug)]
pub enum X25Facility {
    /// The maximum data field length of _data_ packets.
    PacketSize {
        from_called: usize,
        from_calling: usize,
    },

    /// The window size.
    WindowSize { from_called: u8, from_calling: u8 },

    /// A generic _class A_ facility, contains a single byte parameter.
    ClassA(u8, (u8,)),

    /// A generic _class B_ facility, contains 2 byte params.
    ClassB(u8, (u8, u8)),

    /// A generic _class C_ facility, contains 3 byte params.
    ClassC(u8, (u8, u8, u8)),

    /// A generic _class D_ facility, contains a variable length parameter.
    ClassD(u8, Bytes),
}

impl X25Facility {
    fn get_code(&self) -> u8 {
        match self {
            X25Facility::PacketSize { .. } => 0x42,
            X25Facility::WindowSize { .. } => 0x43,
            X25Facility::ClassA(code, _)
            | X25Facility::ClassB(code, _)
            | X25Facility::ClassC(code, _)
            | X25Facility::ClassD(code, _) => *code,
        }
    }
}

/// Encode facilities for a X.25 facilities block, returning how many bytes were
/// encoded.
///
/// *Warning*: on a failure to encode facilities the buffer will be left in a bad state.
pub fn encode_facilities(facilities: &[X25Facility], buf: &mut BytesMut) -> Result<usize, String> {
    let mut codes: HashSet<u8> = HashSet::new();
    let mut len: usize = 0;

    for facility in facilities {
        let code = facility.get_code();

        // Ensure that facilities are unique.
        if !codes.insert(code) {
            return Err("facilities must be unique".into());
        }

        buf.put_u8(code);

        let params_len = match facility {
            X25Facility::PacketSize {
                from_called,
                from_calling,
            } => {
                let from_called = encode_packet_size(*from_called)?;
                let from_calling = encode_packet_size(*from_calling)?;

                encode_class_b_params((from_called, from_calling), buf)
            }

            X25Facility::WindowSize {
                from_called,
                from_calling,
            } => {
                // This does not account for the window size limit based on modulo,
                // that validation should be performed in the virtual circuit layer.
                if !(1..=127).contains(from_called) {
                    return Err("invalid window size".into());
                }

                if !(1..=127).contains(from_calling) {
                    return Err("invalid window size".into());
                }

                encode_class_b_params((*from_called, *from_calling), buf)
            }

            X25Facility::ClassA(_, params) => {
                assert!(is_class_a_code(code));

                encode_class_a_params(*params, buf)
            }

            X25Facility::ClassB(_, params) => {
                assert!(is_class_b_code(code));

                encode_class_b_params(*params, buf)
            }

            X25Facility::ClassC(_, params) => {
                assert!(is_class_c_code(code));

                encode_class_c_params(*params, buf)
            }

            X25Facility::ClassD(_, params) => {
                assert!(is_class_d_code(code));

                encode_class_d_params(params, buf)?
            }
        };

        len += 1 + params_len;
    }

    Ok(len)
}

/// Decode facilities from an X.25 facilities block.
pub fn decode_facilities(mut buf: Bytes) -> Result<Vec<X25Facility>, String> {
    let mut facilities: Vec<X25Facility> = Vec::new();
    let mut codes: HashSet<u8> = HashSet::new();

    while !buf.is_empty() {
        let code = buf.get_u8();

        // Ensure that facilities are unique.
        if !codes.insert(code) {
            return Err("facilities must be unique".into());
        }

        let facility = if code == 0x42 {
            let (from_called, from_calling) = decode_class_b_params(&mut buf)?;

            let from_called = decode_packet_size(from_called)?;
            let from_calling = decode_packet_size(from_calling)?;

            X25Facility::PacketSize {
                from_called,
                from_calling,
            }
        } else if code == 0x43 {
            let (from_called, from_calling) = decode_class_b_params(&mut buf)?;

            // This does not account for the window size limit based on modulo,
            // that validation should be performed in the virtual circuit layer.
            if !(1..=127).contains(&from_called) {
                return Err("invalid window size".into());
            }

            if !(1..=127).contains(&from_calling) {
                return Err("invalid window size".into());
            }

            X25Facility::WindowSize {
                from_called,
                from_calling,
            }
        } else if is_class_a_code(code) {
            let params = decode_class_a_params(&mut buf)?;

            X25Facility::ClassA(code, params)
        } else if is_class_b_code(code) {
            let params = decode_class_b_params(&mut buf)?;

            X25Facility::ClassB(code, params)
        } else if is_class_c_code(code) {
            let params = decode_class_c_params(&mut buf)?;

            X25Facility::ClassC(code, params)
        } else if is_class_d_code(code) {
            let params = decode_class_d_params(&mut buf)?;

            X25Facility::ClassD(code, params)
        } else {
            unreachable!();
        };

        facilities.push(facility);
    }

    Ok(facilities)
}

fn is_class_a_code(code: u8) -> bool {
    (code & 0xc0) >> 6 == 0
}

fn is_class_b_code(code: u8) -> bool {
    (code & 0xc0) >> 6 == 1
}

fn is_class_c_code(code: u8) -> bool {
    (code & 0xc0) >> 6 == 2
}

fn is_class_d_code(code: u8) -> bool {
    (code & 0xc0) >> 6 == 3
}

fn encode_class_a_params(params: (u8,), buf: &mut BytesMut) -> usize {
    buf.put_u8(params.0);

    1
}

fn decode_class_a_params(buf: &mut Bytes) -> Result<(u8,), String> {
    if buf.is_empty() {
        return Err("facility too short".into());
    }

    Ok((buf.get_u8(),))
}

fn encode_class_b_params(params: (u8, u8), buf: &mut BytesMut) -> usize {
    buf.put_u8(params.0);
    buf.put_u8(params.1);

    2
}

fn decode_class_b_params(buf: &mut Bytes) -> Result<(u8, u8), String> {
    if buf.len() < 2 {
        return Err("facility too short".into());
    }

    Ok((buf.get_u8(), buf.get_u8()))
}

fn encode_class_c_params(params: (u8, u8, u8), buf: &mut BytesMut) -> usize {
    buf.put_u8(params.0);
    buf.put_u8(params.1);
    buf.put_u8(params.2);

    3
}

fn decode_class_c_params(buf: &mut Bytes) -> Result<(u8, u8, u8), String> {
    if buf.len() < 3 {
        return Err("facility too short".into());
    }

    Ok((buf.get_u8(), buf.get_u8(), buf.get_u8()))
}

fn encode_class_d_params(params: &Bytes, buf: &mut BytesMut) -> Result<usize, String> {
    if params.len() > 255 {
        return Err("parameters too long".into());
    }

    let len = 1 + params.len();

    buf.reserve(len);

    buf.put_u8(u8::try_from(params.len()).unwrap());
    buf.put_slice(params);

    Ok(len)
}

fn decode_class_d_params(buf: &mut Bytes) -> Result<Bytes, String> {
    if buf.is_empty() {
        return Err("facility too short".into());
    }

    let len = buf.get_u8() as usize;

    if buf.len() < len {
        return Err("facility too short".into());
    }

    Ok(buf.copy_to_bytes(len))
}

fn encode_packet_size(size: usize) -> Result<u8, String> {
    // TODO: This could be replaced with log2 when available...
    match size {
        16 => Ok(4),
        32 => Ok(5),
        64 => Ok(6),
        128 => Ok(7),
        256 => Ok(8),
        512 => Ok(9),
        1024 => Ok(10),
        2048 => Ok(11),
        4096 => Ok(12),
        _ => Err("invalid packet size".into()),
    }
}

fn decode_packet_size(size: u8) -> Result<usize, String> {
    if !(4..=12).contains(&size) {
        return Err("invalid packet size".into());
    }

    Ok(usize::pow(2, u32::from(size)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_facilities() {
        let facilities = [
            X25Facility::PacketSize {
                from_called: 128,
                from_calling: 1024,
            },
            X25Facility::WindowSize {
                from_called: 2,
                from_calling: 4,
            },
            X25Facility::ClassA(0x01, (0x12,)),
            X25Facility::ClassB(0x41, (0x12, 0x34)),
            X25Facility::ClassC(0x81, (0x12, 0x34, 0x56)),
            X25Facility::ClassD(0xc1, Bytes::from_static(b"\x12\x34\x56\x78")),
        ];

        let mut buf = BytesMut::new();

        assert_eq!(super::encode_facilities(&facilities, &mut buf), Ok(21));

        assert_eq!(
            &buf[..],
            b"\x42\x07\x0a\x43\x02\x04\x01\x12\x41\x12\x34\x81\x12\x34\x56\xc1\x04\x12\x34\x56\x78"
        );
    }

    #[test]
    fn decode_facilities() {
        let buf = Bytes::from_static(
            b"\x42\x07\x0a\x43\x02\x04\x01\x12\x41\x12\x34\x81\x12\x34\x56\xc1\x04\x12\x34\x56\x78",
        );

        let expected_facilities = vec![
            X25Facility::PacketSize {
                from_called: 128,
                from_calling: 1024,
            },
            X25Facility::WindowSize {
                from_called: 2,
                from_calling: 4,
            },
            X25Facility::ClassA(0x01, (0x12,)),
            X25Facility::ClassB(0x41, (0x12, 0x34)),
            X25Facility::ClassC(0x81, (0x12, 0x34, 0x56)),
            X25Facility::ClassD(0xc1, Bytes::from_static(b"\x12\x34\x56\x78")),
        ];

        assert_eq!(super::decode_facilities(buf), Ok(expected_facilities));
    }
}
