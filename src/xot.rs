//! X.25 over TCP.
//!
//! This module provides functionality to transmit X.25 packets over TCP.
//!
//! The XOT protocol is specified in [IETF RFC 1613].
//!
//! [IETF RFC 1613]: https://tools.ietf.org/html/rfc1613

use bytes::{BufMut, Bytes, BytesMut};
use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::x25;

/// Registered XOT TCP port number.
pub const TCP_PORT: u16 = 1998;

/// XOT link allowing X.25 packets to be transmitted over a `TcpStream`.
pub struct XotLink {
    stream: TcpStream,
    recv_buf: BytesMut,
}

impl XotLink {
    /// Creates a new `XotLink` over the underlying `TcpStream`.
    pub fn new(stream: TcpStream) -> Self {
        XotLink {
            stream,
            recv_buf: BytesMut::new(),
        }
    }

    /// Sends an X.25 packet.
    pub fn send(&mut self, x25_packet: &[u8]) -> io::Result<()> {
        let mut buf = BytesMut::new();

        encode(x25_packet, &mut buf)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        self.stream.write_all(&buf)
    }

    /// Receives an X.25 packet.
    pub fn recv(&mut self) -> io::Result<Bytes> {
        loop {
            let x25_packet = decode(&mut self.recv_buf)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

            if let Some(x25_packet) = x25_packet {
                return Ok(x25_packet);
            }

            let mut buf = [0; 1024];

            let len = self.stream.read(&mut buf)?;

            if len == 0 {
                return Err(io::Error::from(io::ErrorKind::ConnectionReset));
            }

            self.recv_buf.extend(&buf[..len]);
        }
    }

    /// Unwraps this `XotLink`, returning the underlying `TcpStream`.
    ///
    /// Note that any leftover data in the internal buffer is lost. Therefore, a
    /// following read from the underlying `TcpStream` may lead to data loss.
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

const XOT_HEADER_LEN: usize = 4;

fn encode(x25_packet: &[u8], buf: &mut BytesMut) -> Result<usize, String> {
    let version: u16 = 0;
    let len = x25_packet.len();

    if len < x25::MIN_PACKET_LEN {
        return Err("packet too short".into());
    }

    if len > x25::MAX_PACKET_LEN {
        return Err("packet too long".into());
    }

    buf.reserve(XOT_HEADER_LEN + len);

    buf.put_u16(version);
    buf.put_u16(u16::try_from(len).unwrap());
    buf.put_slice(x25_packet);

    Ok(XOT_HEADER_LEN + len)
}

fn decode(buf: &mut BytesMut) -> Result<Option<Bytes>, String> {
    if buf.len() < XOT_HEADER_LEN {
        return Ok(None);
    }

    let mut version = [0; 2];

    version.copy_from_slice(&buf[0..2]);

    let version = u16::from_be_bytes(version);

    if version != 0 {
        return Err("unsupported version".into());
    }

    let mut len = [0; 2];

    len.copy_from_slice(&buf[2..4]);

    let len = u16::from_be_bytes(len) as usize;

    if len < x25::MIN_PACKET_LEN {
        return Err("packet too short".into());
    }

    if len > x25::MAX_PACKET_LEN {
        return Err("packet too long".into());
    }

    if buf.len() < XOT_HEADER_LEN + len {
        return Ok(None);
    }

    // This is the complete XOT packet, including header.
    let mut packet = buf.split_to(XOT_HEADER_LEN + len);

    let x25_packet = packet.split_off(XOT_HEADER_LEN);

    Ok(Some(x25_packet.freeze()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_with_valid_x25_packet() {
        let x25_packet = b"\x10\x01\xe5"; // Modulo 8 Receive Ready
        let mut buf = BytesMut::new();

        assert_eq!(encode(x25_packet, &mut buf), Ok(7));

        assert_eq!(&buf[..], b"\x00\x00\x00\x03\x10\x01\xe5");
    }

    #[test]
    fn encode_with_too_short_x25_packet() {
        let x25_packet = b"\x00\x01";
        let mut buf = BytesMut::new();

        assert!(encode(x25_packet, &mut buf).is_err());
    }

    #[test]
    fn encode_with_too_long_x25_packet() {
        let x25_packet = [0; 4104];
        let mut buf = BytesMut::new();

        assert!(encode(&x25_packet, &mut buf).is_err());
    }

    #[test]
    fn decode_with_incomplete_header() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_ok());
        assert!(x25_packet.unwrap().is_none());
    }

    #[test]
    fn decode_with_unsupported_version() {
        let mut buf = BytesMut::from(&b"\x00\x01\x00\x03\x10\x01\xe5"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_err());
    }

    #[test]
    fn decode_with_too_short_x25_packet() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x02\x00\x01"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_err());
    }

    #[test]
    fn decode_with_too_long_x25_packet() {
        let mut buf = BytesMut::from(&b"\x00\x00\x10\x08\x00\x01"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_err());
    }

    #[test]
    fn decode_with_incomplete_x25_packet() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x03\x10\x01"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_ok());
        assert!(x25_packet.unwrap().is_none());
    }

    #[test]
    fn decode_with_complete_x25_packet() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x03\x10\x01\xe5"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_ok());
        assert!(x25_packet.as_ref().unwrap().is_some());

        let x25_packet = x25_packet.unwrap().unwrap();

        assert_eq!(&x25_packet[..], b"\x10\x01\xe5");
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_with_complete_x25_packet_and_partial_xot_header() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x03\x10\x01\xe5\x00"[..]);

        let x25_packet = decode(&mut buf);

        assert!(x25_packet.is_ok());
        assert!(x25_packet.as_ref().unwrap().is_some());

        let x25_packet = x25_packet.unwrap().unwrap();

        assert_eq!(&x25_packet[..], b"\x10\x01\xe5");
        assert_eq!(&buf[..], b"\x00");
    }
}

#[cfg(fuzzing)]
pub mod fuzzing {
    use super::*;

    pub fn decode(buf: &mut BytesMut) -> Result<Option<Bytes>, String> {
        super::decode(buf)
    }
}
