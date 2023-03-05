//! X.25 packets.
//!
//! This module provides functionality for encoding and decoding X.25 packets.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::x121::X121Addr;
use crate::x25::facility::{decode_facilities, encode_facilities, X25Facility};

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
#[derive(Debug)]
pub enum X25Packet {
    CallRequest(X25CallRequest),
    // TODO: CallAccepted,
    ClearRequest(X25ClearRequest),
    // TODO: ClearConfirmation,
    // TODO: Data,
    // TODO: Interrupt
    // TODO: InterruptConfirmation
    // TODO: ReceiveReady,
    // TODO: ReceiveNotReady,
    // TODO: Reject
    // TODO: ResetRequest,
    // TODO: ResetConfirmation,
    // TODO: RestartRequest
    // TODO: RestartConfirmation
    // TODO: Diagnostic,
}

/// X.25 packet type.
#[derive(PartialEq, Debug)]
pub enum X25PacketType {
    CallRequest,
    // TODO: CallAccepted,
    ClearRequest,
    // TODO: ClearConfirmation,
    // TODO: Data,
    // TODO: Interrupt
    // TODO: InterruptConfirmation
    // TODO: ReceiveReady,
    // TODO: ReceiveNotReady,
    // TODO: Reject
    // TODO: ResetRequest,
    // TODO: ResetConfirmation,
    // TODO: RestartRequest
    // TODO: RestartConfirmation
    // TODO: Diagnostic,
}

/// X.25 packet sequence numbering scheme.
///
/// The sequence numbering scheme specifies the range of sequence numbers, and
/// in some cases the packet format as a result.
///
/// Only normal and extended schemes are currently supported, super extended is
/// not supported.
#[derive(Clone, Copy, PartialEq, Debug)]
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
            X25Packet::ClearRequest(_) => X25PacketType::ClearRequest,
        }
    }

    /// Returns the sequence numbering scheme of this `X25Packet`.
    pub fn modulo(&self) -> X25Modulo {
        match self {
            X25Packet::CallRequest(call_request) => call_request.modulo,
            X25Packet::ClearRequest(clear_request) => clear_request.modulo,
        }
    }

    /// Encodes this `X25Packet` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        match self {
            X25Packet::CallRequest(call_request) => call_request.encode(buf),
            X25Packet::ClearRequest(clear_request) => clear_request.encode(buf),
        }
    }

    /// Decodes an `X25Packet` from the buffer provided.
    pub fn decode(buf: Bytes) -> Result<Self, String> {
        if buf.len() < MIN_PACKET_LEN {
            return Err("packet too small".into());
        }

        if buf.len() > MAX_PACKET_LEN {
            return Err("packet too big".into());
        }

        let (modulo, gfi, channel, type_) = decode_packet_header(&buf)?;

        if type_ & 0x01 == 0x00 {
            todo!("DATA")
        } else if type_ == 0x0b {
            let call_request = X25CallRequest::decode(buf, modulo, channel)?;

            Ok(X25Packet::CallRequest(call_request))
        } else if type_ == 0x13 {
            let clear_request = X25ClearRequest::decode(buf, modulo, channel)?;

            Ok(X25Packet::ClearRequest(clear_request))
        } else {
            Err("unsupported packet type".into())
        }
    }
}

/// X.25 _call request_ packet.
#[derive(Debug)]
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
        len += encode_facilities_block(&self.facilities, buf)?;

        if !self.call_user_data.is_empty() {
            buf.put_slice(&self.call_user_data);
            len += self.call_user_data.len();
        }

        if len > 259 {
            return Err("packet too big".into());
        }

        Ok(len)
    }

    fn decode(mut buf: Bytes, modulo: X25Modulo, channel: u16) -> Result<Self, String> {
        if buf.len() < 5 {
            return Err("packet too small".into());
        }

        if buf.len() > 259 {
            return Err("packet too big".into());
        }

        buf.advance(3);

        let (called_addr, calling_addr) = decode_addr_block(&mut buf)?;
        let facilities = decode_facilities_block(&mut buf)?;

        let call_user_data = if buf.has_remaining() {
            buf
        } else {
            Bytes::new()
        };

        Ok(X25CallRequest {
            modulo,
            channel,
            called_addr,
            calling_addr,
            facilities,
            call_user_data,
        })
    }
}

impl From<X25CallRequest> for X25Packet {
    fn from(call_request: X25CallRequest) -> X25Packet {
        X25Packet::CallRequest(call_request)
    }
}

/// X.25 _clear request_ packet.
#[derive(Debug)]
pub struct X25ClearRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub cause: u8,
    pub diagnostic_code: u8,
    pub called_addr: X121Addr,
    pub calling_addr: X121Addr,
    pub facilities: Vec<X25Facility>,
    pub clear_user_data: Bytes,
}

impl X25ClearRequest {
    /// Encodes this `X25ClearRequest` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x13, buf)?;

        buf.put_u8(self.cause);
        len += 1;

        let has_diagnostic_code = self.diagnostic_code > 0;
        let has_addr = !self.called_addr.is_null() || !self.calling_addr.is_null();
        let has_facilities = !self.facilities.is_empty();
        let has_clear_user_data = !self.clear_user_data.is_empty();

        if has_diagnostic_code || has_addr || has_facilities || has_clear_user_data {
            buf.put_u8(self.diagnostic_code);
            len += 1;
        }

        // When the extended format is used, the address block and the facilities
        // block must be present.
        if has_addr || has_facilities || has_clear_user_data {
            len += encode_addr_block(&self.called_addr, &self.calling_addr, buf);
            len += encode_facilities_block(&self.facilities, buf)?;
        }

        if has_clear_user_data {
            buf.put_slice(&self.clear_user_data);
            len += self.clear_user_data.len();
        }

        if len > 259 {
            return Err("packet too big".into());
        }

        Ok(len)
    }

    fn decode(mut buf: Bytes, modulo: X25Modulo, channel: u16) -> Result<Self, String> {
        if buf.len() < 4 {
            return Err("packet too small".into());
        }

        if buf.len() > 259 {
            return Err("packet too big".into());
        }

        buf.advance(3);

        let cause = buf.get_u8();

        let diagnostic_code = if buf.has_remaining() { buf.get_u8() } else { 0 };

        let (called_addr, calling_addr) = if buf.has_remaining() {
            decode_addr_block(&mut buf)?
        } else {
            (X121Addr::null(), X121Addr::null())
        };

        let facilities = if buf.has_remaining() {
            decode_facilities_block(&mut buf)?
        } else {
            Vec::new()
        };

        let clear_user_data = if buf.has_remaining() {
            buf
        } else {
            Bytes::new()
        };

        Ok(X25ClearRequest {
            modulo,
            channel,
            cause,
            diagnostic_code,
            called_addr,
            calling_addr,
            facilities,
            clear_user_data,
        })
    }
}

impl From<X25ClearRequest> for X25Packet {
    fn from(clear_request: X25ClearRequest) -> X25Packet {
        X25Packet::ClearRequest(clear_request)
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

fn decode_packet_header(buf: &Bytes) -> Result<(X25Modulo, u8, u16, u8), String> {
    if buf.len() < 3 {
        return Err("packet too short".into());
    }

    let gfi = (buf[0] & 0xf0) >> 4;
    let channel = ((buf[0] as u16 & 0x0f) << 8) | buf[1] as u16;
    let type_ = buf[2];

    let modulo = match gfi & 0x03 {
        0b01 => X25Modulo::Normal,
        0b10 => X25Modulo::Extended,
        _ => return Err("unsupported modulo".into()),
    };

    Ok((modulo, gfi, channel, type_))
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

fn decode_addr_block(buf: &mut Bytes) -> Result<(X121Addr, X121Addr), String> {
    if buf.len() < 1 {
        return Err("addr block too small".into());
    }

    let len = buf.get_u8();

    let calling_len = ((len & 0xf0) >> 4) as usize;
    let called_len = (len & 0x0f) as usize;

    // Convert the length in digits to the length in packed bytes.
    let len = called_len + calling_len;
    let len = (len / 2) + (len % 2);

    if buf.len() < len {
        return Err("addr block too small".into());
    }

    let addr_buf = buf.split_to(len);

    // Unpack the digits.
    let mut digits = addr_buf.iter().flat_map(|b| [(b & 0xf0) >> 4, b & 0x0f]);

    let called_digits: Vec<u8> = digits.by_ref().take(called_len).collect();
    let calling_digits: Vec<u8> = digits.take(calling_len).collect();

    // Convert the digits to addresses.
    let called = X121Addr::from_digits(&called_digits)?;
    let calling = X121Addr::from_digits(&calling_digits)?;

    Ok((called, calling))
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

fn decode_facilities_block(buf: &mut Bytes) -> Result<Vec<X25Facility>, String> {
    if buf.len() < 1 {
        return Err("facilities block too small".into());
    }

    let len = buf.get_u8() as usize;

    if buf.len() < len {
        return Err("facilities block too small".into());
    }

    let facilities_buf = buf.split_to(len);

    decode_facilities(facilities_buf)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn encode_call_request() {
        let call_request = X25CallRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: Vec::new(),
            call_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_request.encode(&mut buf), Ok(9));

        assert_eq!(&buf[..], b"\x10\x01\x0b\x34\x12\x34\x56\x70\x00");
    }

    #[test]
    fn encode_call_request_with_facilities() {
        let call_request = X25CallRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: vec![
                X25Facility::PacketSize {
                    from_called: 128,
                    from_calling: 128,
                },
                X25Facility::WindowSize {
                    from_called: 2,
                    from_calling: 2,
                },
            ],
            call_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_request.encode(&mut buf), Ok(15));

        assert_eq!(
            &buf[..],
            b"\x10\x01\x0b\x34\x12\x34\x56\x70\x06\x42\x07\x07\x43\x02\x02"
        );
    }

    #[test]
    fn encode_call_request_with_call_user_data() {
        let call_request = X25CallRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: Vec::new(),
            call_user_data: Bytes::from_static(b"\x01\x00\x00\x00"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_request.encode(&mut buf), Ok(13));

        assert_eq!(
            &buf[..],
            b"\x10\x01\x0b\x34\x12\x34\x56\x70\x00\x01\x00\x00\x00"
        );
    }

    #[test]
    fn decode_call_request() {
        let buf = Bytes::from_static(b"\x10\x01\x0b\x34\x12\x34\x56\x70\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallRequest);

        let X25Packet::CallRequest(call_request) = packet else { unreachable!() };

        assert_eq!(call_request.modulo, X25Modulo::Normal);
        assert_eq!(call_request.channel, 1);

        assert_eq!(
            call_request.called_addr,
            X121Addr::from_str("1234").unwrap()
        );

        assert_eq!(
            call_request.calling_addr,
            X121Addr::from_str("567").unwrap()
        );

        assert!(call_request.facilities.is_empty());
        assert!(call_request.call_user_data.is_empty());
    }

    #[test]
    fn decode_call_request_with_facilities() {
        let buf =
            Bytes::from_static(b"\x10\x01\x0b\x34\x12\x34\x56\x70\x06\x42\x07\x07\x43\x02\x02");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallRequest);

        let X25Packet::CallRequest(call_request) = packet else { unreachable!() };

        assert_eq!(call_request.modulo, X25Modulo::Normal);
        assert_eq!(call_request.channel, 1);

        assert_eq!(
            call_request.called_addr,
            X121Addr::from_str("1234").unwrap()
        );

        assert_eq!(
            call_request.calling_addr,
            X121Addr::from_str("567").unwrap()
        );

        let expected_facilities = [
            X25Facility::PacketSize {
                from_called: 128,
                from_calling: 128,
            },
            X25Facility::WindowSize {
                from_called: 2,
                from_calling: 2,
            },
        ];

        assert_eq!(call_request.facilities, expected_facilities);
        assert!(call_request.call_user_data.is_empty());
    }

    #[test]
    fn decode_call_request_with_call_user_data() {
        let buf = Bytes::from_static(b"\x10\x01\x0b\x34\x12\x34\x56\x70\x00\x01\x00\x00\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallRequest);

        let X25Packet::CallRequest(call_request) = packet else { unreachable!() };

        assert_eq!(call_request.modulo, X25Modulo::Normal);
        assert_eq!(call_request.channel, 1);

        assert_eq!(
            call_request.called_addr,
            X121Addr::from_str("1234").unwrap()
        );

        assert_eq!(
            call_request.calling_addr,
            X121Addr::from_str("567").unwrap()
        );

        assert!(call_request.facilities.is_empty());
        assert_eq!(&call_request.call_user_data[..], b"\x01\x00\x00\x00");
    }

    #[test]
    fn encode_clear_request() {
        let clear_request = X25ClearRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 1,
            diagnostic_code: 0,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            clear_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_request.encode(&mut buf), Ok(4));

        assert_eq!(&buf[..], b"\x10\x01\x13\x01");
    }

    #[test]
    fn encode_clear_request_with_diagnostic_code() {
        let clear_request = X25ClearRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 1,
            diagnostic_code: 1,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            clear_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_request.encode(&mut buf), Ok(5));

        assert_eq!(&buf[..], b"\x10\x01\x13\x01\x01");
    }

    #[test]
    fn encode_clear_request_with_addrs() {
        let clear_request = X25ClearRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 1,
            diagnostic_code: 0,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: Vec::new(),
            clear_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_request.encode(&mut buf), Ok(11));

        assert_eq!(&buf[..], b"\x10\x01\x13\x01\x00\x34\x12\x34\x56\x70\x00");
    }

    #[test]
    fn encode_clear_request_with_facilities() {
        let clear_request = X25ClearRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 1,
            diagnostic_code: 0,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: vec![
                X25Facility::PacketSize {
                    from_called: 128,
                    from_calling: 128,
                },
                X25Facility::WindowSize {
                    from_called: 2,
                    from_calling: 2,
                },
            ],
            clear_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_request.encode(&mut buf), Ok(13));

        assert_eq!(
            &buf[..],
            b"\x10\x01\x13\x01\x00\x00\x06\x42\x07\x07\x43\x02\x02"
        );
    }

    #[test]
    fn encode_clear_request_with_clear_user_data() {
        let clear_request = X25ClearRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 1,
            diagnostic_code: 0,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            clear_user_data: Bytes::from_static(b"\x01\x00\x00\x00"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_request.encode(&mut buf), Ok(11));

        assert_eq!(&buf[..], b"\x10\x01\x13\x01\x00\x00\x00\x01\x00\x00\x00");
    }

    #[test]
    fn decode_clear_request() {
        let buf = Bytes::from_static(b"\x10\x01\x13\x01");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearRequest);

        let X25Packet::ClearRequest(clear_request) = packet else { unreachable!() };

        assert_eq!(clear_request.modulo, X25Modulo::Normal);
        assert_eq!(clear_request.channel, 1);
        assert_eq!(clear_request.cause, 1);
        assert_eq!(clear_request.diagnostic_code, 0);
        assert!(clear_request.called_addr.is_null());
        assert!(clear_request.calling_addr.is_null());
        assert!(clear_request.facilities.is_empty());
        assert!(clear_request.clear_user_data.is_empty());
    }

    #[test]
    fn decode_clear_request_with_diagnostic_code() {
        let buf = Bytes::from_static(b"\x10\x01\x13\x01\x01");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearRequest);

        let X25Packet::ClearRequest(clear_request) = packet else { unreachable!() };

        assert_eq!(clear_request.modulo, X25Modulo::Normal);
        assert_eq!(clear_request.channel, 1);
        assert_eq!(clear_request.cause, 1);
        assert_eq!(clear_request.diagnostic_code, 1);
        assert!(clear_request.called_addr.is_null());
        assert!(clear_request.calling_addr.is_null());
        assert!(clear_request.facilities.is_empty());
        assert!(clear_request.clear_user_data.is_empty());
    }

    #[test]
    fn decode_clear_request_with_addrs() {
        let buf = Bytes::from_static(b"\x10\x01\x13\x01\x00\x34\x12\x34\x56\x70\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearRequest);

        let X25Packet::ClearRequest(clear_request) = packet else { unreachable!() };

        assert_eq!(clear_request.modulo, X25Modulo::Normal);
        assert_eq!(clear_request.channel, 1);
        assert_eq!(clear_request.cause, 1);
        assert_eq!(clear_request.diagnostic_code, 0);

        assert_eq!(
            clear_request.called_addr,
            X121Addr::from_str("1234").unwrap()
        );

        assert_eq!(
            clear_request.calling_addr,
            X121Addr::from_str("567").unwrap()
        );

        assert!(clear_request.facilities.is_empty());
        assert!(clear_request.clear_user_data.is_empty());
    }

    #[test]
    fn decode_clear_request_with_facilities() {
        let buf = Bytes::from_static(b"\x10\x01\x13\x01\x00\x00\x06\x42\x07\x07\x43\x02\x02");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearRequest);

        let X25Packet::ClearRequest(clear_request) = packet else { unreachable!() };

        assert_eq!(clear_request.modulo, X25Modulo::Normal);
        assert_eq!(clear_request.channel, 1);
        assert_eq!(clear_request.cause, 1);
        assert_eq!(clear_request.diagnostic_code, 0);
        assert!(clear_request.called_addr.is_null());
        assert!(clear_request.calling_addr.is_null());

        let expected_facilities = [
            X25Facility::PacketSize {
                from_called: 128,
                from_calling: 128,
            },
            X25Facility::WindowSize {
                from_called: 2,
                from_calling: 2,
            },
        ];

        assert_eq!(clear_request.facilities, expected_facilities);
        assert!(clear_request.clear_user_data.is_empty());
    }

    #[test]
    fn decode_clear_request_with_clear_user_data() {
        let buf = Bytes::from_static(b"\x10\x01\x13\x01\x00\x00\x00\x01\x00\x00\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearRequest);

        let X25Packet::ClearRequest(clear_request) = packet else { unreachable!() };

        assert_eq!(clear_request.modulo, X25Modulo::Normal);
        assert_eq!(clear_request.channel, 1);
        assert_eq!(clear_request.cause, 1);
        assert_eq!(clear_request.diagnostic_code, 0);
        assert!(clear_request.called_addr.is_null());
        assert!(clear_request.calling_addr.is_null());
        assert!(clear_request.facilities.is_empty());
        assert_eq!(&clear_request.clear_user_data[..], b"\x01\x00\x00\x00");
    }
}
