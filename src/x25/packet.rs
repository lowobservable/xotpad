//! X.25 packets.
//!
//! This module provides functionality for encoding and decoding X.25 packets.

use bytes::{BufMut, Bytes, BytesMut};

use crate::x121::X121Addr;
use crate::x25::facility::{encode_facilities, X25Facility};

/// Minimum X.25 packet length.
pub const MIN_PACKET_LEN: usize = 3;

/// Maximum X.25 packet length.
///
/// This length is based on a super extended header (7 bytes) and maximum data
/// field length (4096 bytes).
pub const MAX_PACKET_LEN: usize = 7 + 4096;

/// Maximum X.25 channel number.
pub const MAX_CHANNEL: u16 = 4095;

/// X.25 packet.
pub enum X25Packet {
    CallRequest(X25CallRequest),
}

/// X.25 packet type.
pub enum X25PacketType {
    CallRequest,
    CallAccepted,
    ClearRequest,
    ClearConfirmation,
    Data,
    // TODO: Interrupt
    // TODO: InterruptConfirmation
    ReceiveReady,
    ReceiveNotReady,
    // TODO: Reject
    ResetRequest,
    ResetConfirmation,
    // TODO: RestartRequest
    // TODO: RestartConfirmation
    Diagnostic,
}

/// X.25 packet sequence numbering scheme.
///
/// The sequence numbering scheme specifies the range of sequence numbers, and
/// in some cases the packet format as a result.
///
/// Only normal and extended schemes are currently supported, super extended is
/// not supported.
#[derive(Clone, Copy)]
pub enum X25Modulo {
    /// Numbers cycle through the entire range 0 to 7.
    Normal = 8,

    /// Numbers cycle through the entire range 0 to 127.
    Extended = 128,
}

impl X25Packet {
    /// Returns the type of this `X25Packet`.
    pub fn packet_type(&self) -> X25PacketType {
        match self {
            X25Packet::CallRequest(_) => X25PacketType::CallRequest,
        }
    }

    /// Returns the sequence numbering scheme of this `X25Packet`.
    pub fn modulo(&self) -> X25Modulo {
        match self {
            X25Packet::CallRequest(call_request) => call_request.modulo,
        }
    }

    /// Encodes this `X25Packet` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        match self {
            X25Packet::CallRequest(call_request) => call_request.encode(buf),
        }
    }
}

impl From<X25CallRequest> for X25Packet {
    fn from(call_request: X25CallRequest) -> X25Packet {
        X25Packet::CallRequest(call_request)
    }
}

/// X.25 _call request_ packet.
pub struct X25CallRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub called_addr: X121Addr,
    pub calling_addr: X121Addr,
    pub facilities: Vec<X25Facility>,
    pub call_user_data: Bytes,
}

impl X25CallRequest {
    /// Encodes this `X25CallRequest` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x0b, buf)?;
        len += encode_addr_block(&self.called_addr, &self.calling_addr, buf);

        if !self.facilities.is_empty() || !self.call_user_data.is_empty() {
            len += encode_facilities_block(&self.facilities, buf)?;
        }

        if !self.call_user_data.is_empty() {
            buf.put_slice(&self.call_user_data);

            len += self.call_user_data.len();
        }

        if len > 259 {
            return Err("packet too big".into());
        }

        Ok(len)
    }
}

fn encode_packet_header(
    modulo: X25Modulo,
    gfi_overlay: u8,
    channel: u16,
    type_: u8,
    buf: &mut BytesMut,
) -> Result<usize, String> {
    if channel > MAX_CHANNEL {
        return Err("channel out of range".into());
    }

    let gfi: u8 = match modulo {
        X25Modulo::Normal => 0b01,
        X25Modulo::Extended => 0b10,
    };

    buf.put_u8(((gfi | gfi_overlay) << 4) | (((channel & 0x0f00) >> 8) as u8));
    buf.put_u8((channel & 0x00ff) as u8);
    buf.put_u8(type_);

    Ok(3)
}

fn encode_addr_block(called: &X121Addr, calling: &X121Addr, buf: &mut BytesMut) -> usize {
    buf.put_u8(((calling.len() as u8) << 4) | (called.len() as u8));

    let mut len = 1;

    // Combine called and calling address digits.
    let digits: Vec<u8> = called.digits().chain(calling.digits()).collect();

    for pair in digits.chunks(2) {
        let high = pair[0];
        let low = if pair.len() > 1 { pair[1] } else { 0 };

        buf.put_u8((high << 4) | low);

        len += 1;
    }

    len
}

fn encode_facilities_block(
    facilities: &[X25Facility],
    buf: &mut BytesMut,
) -> Result<usize, String> {
    let mut facilities_buf = BytesMut::new();

    let len = encode_facilities(facilities, &mut facilities_buf)?;

    if len > 255 {
        return Err("facilities too big".into());
    }

    buf.put_u8(len as u8);
    buf.put(facilities_buf);

    Ok(1 + len)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn encode_x25_call_request() {
        let call_request = X25CallRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: Vec::new(),
            call_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        let len = call_request.encode(&mut buf);

        assert!(len.is_ok());

        assert_eq!(len.unwrap(), 8);
    }
}
