use bytes::{BufMut, Bytes, BytesMut};
use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::x25;

pub const TCP_PORT: u16 = 1998;

pub struct XotLinkLayer {
    stream: TcpStream,
    recv_buf: BytesMut,
}

impl XotLinkLayer {
    /// Creates a new `XotLinkLayer` over the underlying `TcpStream`.
    pub fn new(stream: TcpStream) -> Self {
        Self {
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

    /// Unwraps this `XotLinkLayer`, returning the underlying `TcpStream`.
    ///
    /// Note that any leftover data in the internal buffer is lost. Therefore, a
    /// following read from the underlying `TcpStream` may lead to data loss.
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

const XOT_HEADER_LEN: usize = 4;

fn encode(x25_packet: &[u8], buf: &mut BytesMut) -> Result<(), String> {
    let version: u16 = 0;
    let len = x25_packet.len();

    if len < x25::MIN_PACKET_LEN {
        return Err("packet too small".into());
    }

    if len > x25::MAX_PACKET_LEN {
        return Err("packet too big".into());
    }

    buf.reserve(XOT_HEADER_LEN + len);

    buf.put_u16(version);
    buf.put_u16(len as u16);
    buf.put_slice(x25_packet);

    Ok(())
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
        return Err("packet too small".into());
    }

    if len > x25::MAX_PACKET_LEN {
        return Err("packet too big".into());
    }

    if buf.len() < XOT_HEADER_LEN + len {
        return Ok(None);
    }

    // This is the complete XOT packet, including header.
    let mut packet = buf.split_to(XOT_HEADER_LEN + len);

    let x25_packet = packet.split_off(XOT_HEADER_LEN);

    Ok(Some(x25_packet.freeze()))
}
