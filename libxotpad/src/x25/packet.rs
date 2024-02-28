//! X.25 packets.
//!
//! This module provides functionality for encoding and decoding X.25 packets.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::x121::X121Addr;
use crate::x25::facility::{decode_facilities, encode_facilities, X25Facility};
use crate::x25::seq::X25Modulo;

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
    CallAccept(X25CallAccept),
    ClearRequest(X25ClearRequest),
    ClearConfirm(X25ClearConfirm),
    Data(X25Data),
    // TODO: Interrupt
    // TODO: InterruptConfirm
    ReceiveReady(X25ReceiveReady),
    ReceiveNotReady(X25ReceiveNotReady),
    // TODO: Reject
    ResetRequest(X25ResetRequest),
    ResetConfirm(X25ResetConfirm),
    // TODO: RestartRequest
    // TODO: RestartConfirm
    // TODO: Diagnostic
}

/// X.25 packet type.
#[derive(PartialEq, Debug)]
pub enum X25PacketType {
    CallRequest,
    CallAccept,
    ClearRequest,
    ClearConfirm,
    Data,
    // TODO: Interrupt
    // TODO: InterruptConfirm
    ReceiveReady,
    ReceiveNotReady,
    // TODO: Reject
    ResetRequest,
    ResetConfirm,
    // TODO: RestartRequest
    // TODO: RestartConfirm
    // TODO: Diagnostic
}

impl X25Packet {
    /// Returns the type of this `X25Packet`.
    pub fn packet_type(&self) -> X25PacketType {
        match self {
            X25Packet::CallRequest(_) => X25PacketType::CallRequest,
            X25Packet::CallAccept(_) => X25PacketType::CallAccept,
            X25Packet::ClearRequest(_) => X25PacketType::ClearRequest,
            X25Packet::ClearConfirm(_) => X25PacketType::ClearConfirm,
            X25Packet::Data(_) => X25PacketType::Data,
            X25Packet::ReceiveReady(_) => X25PacketType::ReceiveReady,
            X25Packet::ReceiveNotReady(_) => X25PacketType::ReceiveNotReady,
            X25Packet::ResetRequest(_) => X25PacketType::ResetRequest,
            X25Packet::ResetConfirm(_) => X25PacketType::ResetConfirm,
        }
    }

    /// Returns the sequence numbering scheme of this `X25Packet`.
    pub fn modulo(&self) -> X25Modulo {
        match self {
            X25Packet::CallRequest(call_request) => call_request.modulo,
            X25Packet::CallAccept(call_accepted) => call_accepted.modulo,
            X25Packet::ClearRequest(clear_request) => clear_request.modulo,
            X25Packet::ClearConfirm(clear_confirm) => clear_confirm.modulo,
            X25Packet::Data(data) => data.modulo,
            X25Packet::ReceiveReady(receive_ready) => receive_ready.modulo,
            X25Packet::ReceiveNotReady(receive_not_ready) => receive_not_ready.modulo,
            X25Packet::ResetRequest(reset_request) => reset_request.modulo,
            X25Packet::ResetConfirm(reset_confirm) => reset_confirm.modulo,
        }
    }

    /// Returns the channel number of this `X25Packet`.
    pub fn channel(&self) -> Option<u16> {
        match self {
            X25Packet::CallRequest(call_request) => Some(call_request.channel),
            X25Packet::CallAccept(call_accepted) => Some(call_accepted.channel),
            X25Packet::ClearRequest(clear_request) => Some(clear_request.channel),
            X25Packet::ClearConfirm(clear_confirm) => Some(clear_confirm.channel),
            X25Packet::Data(data) => Some(data.channel),
            X25Packet::ReceiveReady(receive_ready) => Some(receive_ready.channel),
            X25Packet::ReceiveNotReady(receive_not_ready) => Some(receive_not_ready.channel),
            X25Packet::ResetRequest(reset_request) => Some(reset_request.channel),
            X25Packet::ResetConfirm(reset_confirm) => Some(reset_confirm.channel),
        }
    }

    /// Encodes this `X25Packet` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        match self {
            X25Packet::CallRequest(call_request) => call_request.encode(buf),
            X25Packet::CallAccept(call_accepted) => call_accepted.encode(buf),
            X25Packet::ClearRequest(clear_request) => clear_request.encode(buf),
            X25Packet::ClearConfirm(clear_confirm) => clear_confirm.encode(buf),
            X25Packet::Data(data) => data.encode(buf),
            X25Packet::ReceiveReady(receive_ready) => receive_ready.encode(buf),
            X25Packet::ReceiveNotReady(receive_not_ready) => receive_not_ready.encode(buf),
            X25Packet::ResetRequest(reset_request) => reset_request.encode(buf),
            X25Packet::ResetConfirm(reset_confirm) => reset_confirm.encode(buf),
        }
    }

    /// Decodes an `X25Packet` from the buffer provided.
    pub fn decode(buf: Bytes) -> Result<Self, String> {
        if buf.len() < MIN_PACKET_LEN {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > MAX_PACKET_LEN {
            return Err(format!("packet too long: {}", buf.len()));
        }

        let (modulo, gfi, channel, type_) = decode_packet_header(&buf)?;

        if type_ == 0x0b {
            let call_request = X25CallRequest::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::CallRequest(call_request))
        } else if type_ == 0x0f {
            let call_accepted = X25CallAccept::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::CallAccept(call_accepted))
        } else if type_ == 0x13 {
            let clear_request = X25ClearRequest::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::ClearRequest(clear_request))
        } else if type_ == 0x17 {
            let clear_confirm = X25ClearConfirm::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::ClearConfirm(clear_confirm))
        } else if type_ & 0x01 == 0x00 {
            let data = X25Data::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::Data(data))
        } else if type_ & 0x1f == 0x01 {
            let receive_ready = X25ReceiveReady::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::ReceiveReady(receive_ready))
        } else if type_ & 0x1f == 0x05 {
            let receive_not_ready = X25ReceiveNotReady::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::ReceiveNotReady(receive_not_ready))
        } else if type_ == 0x1b {
            let reset_request = X25ResetRequest::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::ResetRequest(reset_request))
        } else if type_ == 0x1f {
            let reset_confirm = X25ResetConfirm::decode(buf, modulo, gfi, channel, type_)?;

            Ok(X25Packet::ResetConfirm(reset_confirm))
        } else {
            Err(format!("unsupported packet type: {type_}"))
        }
    }
}

/// X.25 _call request_ packet.
#[derive(Clone, Debug)]
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
            return Err(format!("packet too long: {len}"));
        }

        Ok(len)
    }

    fn decode(
        mut buf: Bytes,
        modulo: X25Modulo,
        _gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_, 0x0b);

        if buf.len() < 5 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > 259 {
            return Err(format!("packet too long: {}", buf.len()));
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

/// X.25 _call accepted_ packet.
#[derive(Debug)]
pub struct X25CallAccept {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub called_addr: X121Addr,
    pub calling_addr: X121Addr,
    pub facilities: Vec<X25Facility>,
    pub called_user_data: Bytes,
}

impl X25CallAccept {
    /// Encodes this `X25CallAccept` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x0f, buf)?;

        let has_addr = !self.called_addr.is_null() || !self.calling_addr.is_null();
        let has_facilities = !self.facilities.is_empty();
        let has_called_user_data = !self.called_user_data.is_empty();

        // When the extended format is used, the address block and the facilities
        // block must be present.
        if has_addr || has_facilities || has_called_user_data {
            len += encode_addr_block(&self.called_addr, &self.calling_addr, buf);
            len += encode_facilities_block(&self.facilities, buf)?;
        }

        if has_called_user_data {
            buf.put_slice(&self.called_user_data);
            len += self.called_user_data.len();
        }

        if len > 259 {
            return Err(format!("packet too long: {len}"));
        }

        Ok(len)
    }

    fn decode(
        mut buf: Bytes,
        modulo: X25Modulo,
        _gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_, 0x0f);

        if buf.len() < 3 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > 259 {
            return Err(format!("packet too long: {}", buf.len()));
        }

        buf.advance(3);

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

        let called_user_data = if buf.has_remaining() {
            buf
        } else {
            Bytes::new()
        };

        Ok(X25CallAccept {
            modulo,
            channel,
            called_addr,
            calling_addr,
            facilities,
            called_user_data,
        })
    }
}

impl From<X25CallAccept> for X25Packet {
    fn from(call_accept: X25CallAccept) -> X25Packet {
        X25Packet::CallAccept(call_accept)
    }
}

/// X.25 _clear request_ packet.
#[derive(Clone, Debug)]
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
            return Err(format!("packet too long: {len}"));
        }

        Ok(len)
    }

    fn decode(
        mut buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_, 0x13);

        if buf.len() < 4 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > 259 {
            return Err(format!("packet too long: {}", buf.len()));
        }

        if (gfi & 0x04) != 0x00 {
            return Err(format!("invalid GFI: {gfi}"));
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

/// X.25 _clear confirmation_ packet.
#[derive(Debug)]
pub struct X25ClearConfirm {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub called_addr: X121Addr,
    pub calling_addr: X121Addr,
    pub facilities: Vec<X25Facility>,
}

impl X25ClearConfirm {
    /// Encodes this `X25ClearConfirm` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x17, buf)?;

        let has_addr = !self.called_addr.is_null() || !self.calling_addr.is_null();
        let has_facilities = !self.facilities.is_empty();

        if has_addr || has_facilities {
            len += encode_addr_block(&self.called_addr, &self.calling_addr, buf);
        }

        if has_facilities {
            len += encode_facilities_block(&self.facilities, buf)?;
        }

        if len > 259 {
            return Err(format!("packet too long: {len}"));
        }

        Ok(len)
    }

    fn decode(
        mut buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_, 0x17);

        if buf.len() < 3 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > 259 {
            return Err(format!("packet too long: {}", buf.len()));
        }

        if (gfi & 0x04) != 0x00 {
            return Err(format!("invalid GFI: {gfi}"));
        }

        buf.advance(3);

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

        Ok(X25ClearConfirm {
            modulo,
            channel,
            called_addr,
            calling_addr,
            facilities,
        })
    }
}

impl From<X25ClearConfirm> for X25Packet {
    fn from(clear_confirm: X25ClearConfirm) -> X25Packet {
        X25Packet::ClearConfirm(clear_confirm)
    }
}

/// X.25 _data_ packet.
#[derive(Debug)]
pub struct X25Data {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub send_seq: u8,
    pub recv_seq: u8,
    pub qualifier: bool,
    pub delivery: bool,
    pub more: bool,
    pub user_data: Bytes,
}

impl X25Data {
    /// Encodes this `X25Data` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        match self.modulo {
            X25Modulo::Normal => self.encode_normal(buf),
            X25Modulo::Extended => self.encode_extended(buf),
        }
    }

    fn encode_normal(&self, buf: &mut BytesMut) -> Result<usize, String> {
        if self.send_seq > 7 {
            return Err(format!("send sequence out of range: {}", self.send_seq));
        }

        if self.recv_seq > 7 {
            return Err(format!("receive sequence out of range: {}", self.recv_seq));
        }

        let mut len = 0;

        let gfi_overlay = u8::from(self.qualifier) << 3 | u8::from(self.delivery) << 2;
        let type_ = self.recv_seq << 5 | u8::from(self.more) << 4 | self.send_seq << 1;

        len += encode_packet_header(self.modulo, gfi_overlay, self.channel, type_, buf)?;

        buf.put_slice(&self.user_data);
        len += self.user_data.len();

        Ok(len)
    }

    fn encode_extended(&self, buf: &mut BytesMut) -> Result<usize, String> {
        if self.send_seq > 127 {
            return Err(format!("send sequence out of range: {}", self.send_seq));
        }

        if self.recv_seq > 127 {
            return Err(format!("receive sequence out of range: {}", self.recv_seq));
        }

        let mut len = 0;

        let gfi_overlay = u8::from(self.qualifier) << 3 | u8::from(self.delivery) << 2;
        let type_ = self.send_seq << 1;

        len += encode_packet_header(self.modulo, gfi_overlay, self.channel, type_, buf)?;

        buf.put_u8(self.recv_seq << 1 | u8::from(self.more));
        len += 1;

        buf.put_slice(&self.user_data);
        len += self.user_data.len();

        Ok(len)
    }

    fn decode(
        buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_ & 0x01, 0x00);

        match modulo {
            X25Modulo::Normal => X25Data::decode_normal(buf, gfi, channel),
            X25Modulo::Extended => X25Data::decode_extended(buf, gfi, channel),
        }
    }

    fn decode_normal(mut buf: Bytes, gfi: u8, channel: u16) -> Result<Self, String> {
        if buf.len() < 3 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        let qualifier = (gfi & 0x08) >> 3 == 1;
        let delivery = (gfi & 0x04) >> 2 == 1;
        let send_seq = (buf[2] & 0x0e) >> 1;
        let recv_seq = (buf[2] & 0xe0) >> 5;
        let more = (buf[2] & 0x10) >> 4 == 1;

        buf.advance(3);

        Ok(X25Data {
            modulo: X25Modulo::Normal,
            channel,
            send_seq,
            recv_seq,
            qualifier,
            delivery,
            more,
            user_data: buf,
        })
    }

    fn decode_extended(mut buf: Bytes, gfi: u8, channel: u16) -> Result<Self, String> {
        if buf.len() < 4 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        let qualifier = (gfi & 0x08) >> 3 == 1;
        let delivery = (gfi & 0x04) >> 2 == 1;
        let send_seq = (buf[2] & 0xfe) >> 1;
        let recv_seq = (buf[3] & 0xfe) >> 1;
        let more = (buf[3] & 0x01) == 1;

        buf.advance(4);

        Ok(X25Data {
            modulo: X25Modulo::Extended,
            channel,
            send_seq,
            recv_seq,
            qualifier,
            delivery,
            more,
            user_data: buf,
        })
    }
}

impl From<X25Data> for X25Packet {
    fn from(data: X25Data) -> X25Packet {
        X25Packet::Data(data)
    }
}

/// X.25 _receive ready_ packet.
#[derive(Debug)]
pub struct X25ReceiveReady {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub recv_seq: u8,
}

impl X25ReceiveReady {
    /// Encodes this `X25ReceiveReady` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        match self.modulo {
            X25Modulo::Normal => self.encode_normal(buf),
            X25Modulo::Extended => self.encode_extended(buf),
        }
    }

    fn encode_normal(&self, buf: &mut BytesMut) -> Result<usize, String> {
        if self.recv_seq > 7 {
            return Err(format!("receive sequence out of range: {}", self.recv_seq));
        }

        let mut len = 0;

        let type_ = self.recv_seq << 5 | 0x01;

        len += encode_packet_header(self.modulo, 0, self.channel, type_, buf)?;

        Ok(len)
    }

    fn encode_extended(&self, buf: &mut BytesMut) -> Result<usize, String> {
        if self.recv_seq > 127 {
            return Err(format!("receive sequence out of range: {}", self.recv_seq));
        }

        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x01, buf)?;

        buf.put_u8(self.recv_seq << 1);
        len += 1;

        Ok(len)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn decode(
        buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_ & 0x1f, 0x01);

        let expected_len = match modulo {
            X25Modulo::Normal => 3,
            X25Modulo::Extended => 4,
        };

        if buf.len() < expected_len {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > expected_len {
            return Err(format!("packet too long: {}", buf.len()));
        }

        if (gfi & 0x0c) != 0x00 {
            return Err(format!("invalid GFI: {gfi}"));
        }

        if modulo == X25Modulo::Extended && (type_ != 0x01 || (buf[3] & 0x01) != 0x00) {
            return Err("unidentifiable packet".into());
        }

        let recv_seq = match modulo {
            X25Modulo::Normal => (buf[2] & 0xe0) >> 5,
            X25Modulo::Extended => (buf[3] & 0xfe) >> 1,
        };

        Ok(X25ReceiveReady {
            modulo,
            channel,
            recv_seq,
        })
    }
}

impl From<X25ReceiveReady> for X25Packet {
    fn from(receive_ready: X25ReceiveReady) -> X25Packet {
        X25Packet::ReceiveReady(receive_ready)
    }
}

/// X.25 _receive not ready_ packet.
#[derive(Debug)]
pub struct X25ReceiveNotReady {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub recv_seq: u8,
}

impl X25ReceiveNotReady {
    /// Encodes this `X25ReceiveNotReady` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        match self.modulo {
            X25Modulo::Normal => self.encode_normal(buf),
            X25Modulo::Extended => self.encode_extended(buf),
        }
    }

    fn encode_normal(&self, buf: &mut BytesMut) -> Result<usize, String> {
        if self.recv_seq > 7 {
            return Err(format!("receive sequence out of range: {}", self.recv_seq));
        }

        let mut len = 0;

        let type_ = self.recv_seq << 5 | 0x05;

        len += encode_packet_header(self.modulo, 0, self.channel, type_, buf)?;

        Ok(len)
    }

    fn encode_extended(&self, buf: &mut BytesMut) -> Result<usize, String> {
        if self.recv_seq > 127 {
            return Err(format!("receive sequence out of range: {}", self.recv_seq));
        }

        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x05, buf)?;

        buf.put_u8(self.recv_seq << 1);
        len += 1;

        Ok(len)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn decode(
        buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_ & 0x1f, 0x05);

        let expected_len = match modulo {
            X25Modulo::Normal => 3,
            X25Modulo::Extended => 4,
        };

        if buf.len() < expected_len {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > expected_len {
            return Err(format!("packet too long: {}", buf.len()));
        }

        if (gfi & 0x0c) != 0x00 {
            return Err(format!("invalid GFI: {gfi}"));
        }

        if modulo == X25Modulo::Extended && (type_ != 0x05 || (buf[3] & 0x01) != 0x00) {
            return Err("unidentifiable packet".into());
        }

        let recv_seq = match modulo {
            X25Modulo::Normal => (buf[2] & 0xe0) >> 5,
            X25Modulo::Extended => (buf[3] & 0xfe) >> 1,
        };

        Ok(X25ReceiveNotReady {
            modulo,
            channel,
            recv_seq,
        })
    }
}

impl From<X25ReceiveNotReady> for X25Packet {
    fn from(receive_not_ready: X25ReceiveNotReady) -> X25Packet {
        X25Packet::ReceiveNotReady(receive_not_ready)
    }
}

/// X.25 _reset request_ packet.
#[derive(Debug)]
pub struct X25ResetRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub cause: u8,
    pub diagnostic_code: u8,
}

impl X25ResetRequest {
    /// Encodes this `X25ResetRequest` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        let mut len = 0;

        len += encode_packet_header(self.modulo, 0, self.channel, 0x1b, buf)?;

        buf.put_u8(self.cause);
        len += 1;

        if self.diagnostic_code > 0 {
            buf.put_u8(self.diagnostic_code);
            len += 1;
        }

        Ok(len)
    }

    fn decode(
        mut buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_, 0x1b);

        if buf.len() < 4 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > 5 {
            return Err(format!("packet too long: {}", buf.len()));
        }

        if (gfi & 0x0c) != 0x00 {
            return Err(format!("invalid GFI: {gfi}"));
        }

        buf.advance(3);

        let cause = buf.get_u8();

        let diagnostic_code = if buf.has_remaining() { buf.get_u8() } else { 0 };

        Ok(X25ResetRequest {
            modulo,
            channel,
            cause,
            diagnostic_code,
        })
    }
}

impl From<X25ResetRequest> for X25Packet {
    fn from(reset_request: X25ResetRequest) -> X25Packet {
        X25Packet::ResetRequest(reset_request)
    }
}

/// X.25 _reset confirmation_ packet.
#[derive(Debug)]
pub struct X25ResetConfirm {
    pub modulo: X25Modulo,
    pub channel: u16,
}

impl X25ResetConfirm {
    /// Encodes this `X25ResetConfirm` into the buffer provided.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, String> {
        encode_packet_header(self.modulo, 0, self.channel, 0x1f, buf)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn decode(
        buf: Bytes,
        modulo: X25Modulo,
        gfi: u8,
        channel: u16,
        type_: u8,
    ) -> Result<Self, String> {
        assert_eq!(type_, 0x1f);

        if buf.len() < 3 {
            return Err(format!("packet too short: {}", buf.len()));
        }

        if buf.len() > 3 {
            return Err(format!("packet too long: {}", buf.len()));
        }

        if (gfi & 0x0c) != 0x00 {
            return Err(format!("invalid GFI: {gfi}"));
        }

        Ok(X25ResetConfirm { modulo, channel })
    }
}

impl From<X25ResetConfirm> for X25Packet {
    fn from(reset_confirm: X25ResetConfirm) -> X25Packet {
        X25Packet::ResetConfirm(reset_confirm)
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
        return Err(format!("channel out of range: {channel}"));
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
        return Err(format!("packet too short: {}", buf.len()));
    }

    let gfi = (buf[0] & 0xf0) >> 4;
    let channel = ((u16::from(buf[0]) & 0x0f) << 8) | u16::from(buf[1]);
    let type_ = buf[2];

    let modulo = match gfi & 0x03 {
        0b01 => X25Modulo::Normal,
        0b10 => X25Modulo::Extended,
        _ => return Err("unsupported modulo".into()),
    };

    Ok((modulo, gfi, channel, type_))
}

fn encode_addr_block(called: &X121Addr, calling: &X121Addr, buf: &mut BytesMut) -> usize {
    buf.put_u8(u8::try_from(calling.len()).unwrap() << 4 | u8::try_from(called.len()).unwrap());

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
    #[allow(clippy::len_zero)]
    if buf.len() < 1 {
        return Err(format!("addr block too short: {}", buf.len()));
    }

    let len = buf.get_u8();

    let calling_len = ((len & 0xf0) >> 4) as usize;
    let called_len = (len & 0x0f) as usize;

    // Convert the length in digits to the length in packed bytes.
    let len = called_len + calling_len;
    let len = (len / 2) + (len % 2);

    if buf.len() < len {
        return Err(format!("addr block incomplete: {}", buf.len()));
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
        return Err(format!("facilities too long: {len}"));
    }

    buf.put_u8(u8::try_from(len).unwrap());
    buf.put(facilities_buf);

    Ok(1 + len)
}

fn decode_facilities_block(buf: &mut Bytes) -> Result<Vec<X25Facility>, String> {
    #[allow(clippy::len_zero)]
    if buf.len() < 1 {
        return Err(format!("facilities block too short: {}", buf.len()));
    }

    let len = buf.get_u8() as usize;

    if buf.len() < len {
        return Err(format!("facilities block incomplete: {}", buf.len()));
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

        let X25Packet::CallRequest(call_request) = packet else {
            unreachable!()
        };

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

        let X25Packet::CallRequest(call_request) = packet else {
            unreachable!()
        };

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

        let X25Packet::CallRequest(call_request) = packet else {
            unreachable!()
        };

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
    fn encode_call_accept() {
        let call_accept = X25CallAccept {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            called_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_accept.encode(&mut buf), Ok(3));

        assert_eq!(&buf[..], b"\x10\x01\x0f");
    }

    #[test]
    fn encode_call_accept_with_addr() {
        let call_accept = X25CallAccept {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: Vec::new(),
            called_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_accept.encode(&mut buf), Ok(9));

        assert_eq!(&buf[..], b"\x10\x01\x0f\x34\x12\x34\x56\x70\x00");
    }

    #[test]
    fn encode_call_accept_with_facilities() {
        let call_accept = X25CallAccept {
            modulo: X25Modulo::Normal,
            channel: 1,
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
            called_user_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_accept.encode(&mut buf), Ok(11));

        assert_eq!(&buf[..], b"\x10\x01\x0f\x00\x06\x42\x07\x07\x43\x02\x02");
    }

    #[test]
    fn encode_call_accept_with_called_user_data() {
        let call_accept = X25CallAccept {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            called_user_data: Bytes::from_static(b"\x01\x00\x00\x00"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(call_accept.encode(&mut buf), Ok(9));

        assert_eq!(&buf[..], b"\x10\x01\x0f\x00\x00\x01\x00\x00\x00");
    }

    #[test]
    fn decode_call_accept() {
        let buf = Bytes::from_static(b"\x10\x01\x0f");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallAccept);

        let X25Packet::CallAccept(call_accept) = packet else {
            unreachable!()
        };

        assert_eq!(call_accept.modulo, X25Modulo::Normal);
        assert_eq!(call_accept.channel, 1);
        assert!(call_accept.called_addr.is_null());
        assert!(call_accept.calling_addr.is_null());
        assert!(call_accept.facilities.is_empty());
        assert!(call_accept.called_user_data.is_empty());
    }

    #[test]
    fn decode_call_accept_with_addr() {
        let buf = Bytes::from_static(b"\x10\x01\x0f\x34\x12\x34\x56\x70\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallAccept);

        let X25Packet::CallAccept(call_accept) = packet else {
            unreachable!()
        };

        assert_eq!(call_accept.modulo, X25Modulo::Normal);
        assert_eq!(call_accept.channel, 1);

        assert_eq!(call_accept.called_addr, X121Addr::from_str("1234").unwrap());

        assert_eq!(call_accept.calling_addr, X121Addr::from_str("567").unwrap());

        assert!(call_accept.facilities.is_empty());
        assert!(call_accept.called_user_data.is_empty());
    }

    #[test]
    fn decode_call_accept_with_facilities() {
        let buf = Bytes::from_static(b"\x10\x01\x0f\x00\x06\x42\x07\x07\x43\x02\x02");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallAccept);

        let X25Packet::CallAccept(call_accept) = packet else {
            unreachable!()
        };

        assert_eq!(call_accept.modulo, X25Modulo::Normal);
        assert_eq!(call_accept.channel, 1);
        assert!(call_accept.called_addr.is_null());
        assert!(call_accept.calling_addr.is_null());

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

        assert_eq!(call_accept.facilities, expected_facilities);
        assert!(call_accept.called_user_data.is_empty());
    }

    #[test]
    fn decode_call_accept_with_called_user_data() {
        let buf = Bytes::from_static(b"\x10\x01\x0f\x00\x00\x01\x00\x00\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::CallAccept);

        let X25Packet::CallAccept(call_accept) = packet else {
            unreachable!()
        };

        assert_eq!(call_accept.modulo, X25Modulo::Normal);
        assert_eq!(call_accept.channel, 1);
        assert!(call_accept.called_addr.is_null());
        assert!(call_accept.calling_addr.is_null());
        assert!(call_accept.facilities.is_empty());
        assert_eq!(&call_accept.called_user_data[..], b"\x01\x00\x00\x00");
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
    fn encode_clear_request_with_addr() {
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

        let X25Packet::ClearRequest(clear_request) = packet else {
            unreachable!()
        };

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

        let X25Packet::ClearRequest(clear_request) = packet else {
            unreachable!()
        };

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
    fn decode_clear_request_with_addr() {
        let buf = Bytes::from_static(b"\x10\x01\x13\x01\x00\x34\x12\x34\x56\x70\x00");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearRequest);

        let X25Packet::ClearRequest(clear_request) = packet else {
            unreachable!()
        };

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

        let X25Packet::ClearRequest(clear_request) = packet else {
            unreachable!()
        };

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

        let X25Packet::ClearRequest(clear_request) = packet else {
            unreachable!()
        };

        assert_eq!(clear_request.modulo, X25Modulo::Normal);
        assert_eq!(clear_request.channel, 1);
        assert_eq!(clear_request.cause, 1);
        assert_eq!(clear_request.diagnostic_code, 0);
        assert!(clear_request.called_addr.is_null());
        assert!(clear_request.calling_addr.is_null());
        assert!(clear_request.facilities.is_empty());
        assert_eq!(&clear_request.clear_user_data[..], b"\x01\x00\x00\x00");
    }

    #[test]
    fn encode_clear_confirm() {
        let clear_confirm = X25ClearConfirm {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_confirm.encode(&mut buf), Ok(3));

        assert_eq!(&buf[..], b"\x10\x01\x17");
    }

    #[test]
    fn encode_clear_confirm_with_addr() {
        let clear_confirm = X25ClearConfirm {
            modulo: X25Modulo::Normal,
            channel: 1,
            called_addr: X121Addr::from_str("1234").unwrap(),
            calling_addr: X121Addr::from_str("567").unwrap(),
            facilities: Vec::new(),
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_confirm.encode(&mut buf), Ok(8));

        assert_eq!(&buf[..], b"\x10\x01\x17\x34\x12\x34\x56\x70");
    }

    #[test]
    fn encode_clear_confirm_with_facilities() {
        let clear_confirm = X25ClearConfirm {
            modulo: X25Modulo::Normal,
            channel: 1,
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
        };

        let mut buf = BytesMut::new();

        assert_eq!(clear_confirm.encode(&mut buf), Ok(11));

        assert_eq!(&buf[..], b"\x10\x01\x17\x00\x06\x42\x07\x07\x43\x02\x02");
    }

    #[test]
    fn decode_clear_confirm() {
        let buf = Bytes::from_static(b"\x10\x01\x17");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearConfirm);

        let X25Packet::ClearConfirm(clear_confirm) = packet else {
            unreachable!()
        };

        assert_eq!(clear_confirm.modulo, X25Modulo::Normal);
        assert_eq!(clear_confirm.channel, 1);
        assert!(clear_confirm.called_addr.is_null());
        assert!(clear_confirm.calling_addr.is_null());
        assert!(clear_confirm.facilities.is_empty());
    }

    #[test]
    fn decode_clear_confirm_with_addr() {
        let buf = Bytes::from_static(b"\x10\x01\x17\x34\x12\x34\x56\x70");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearConfirm);

        let X25Packet::ClearConfirm(clear_confirm) = packet else {
            unreachable!()
        };

        assert_eq!(clear_confirm.modulo, X25Modulo::Normal);
        assert_eq!(clear_confirm.channel, 1);

        assert_eq!(
            clear_confirm.called_addr,
            X121Addr::from_str("1234").unwrap()
        );

        assert_eq!(
            clear_confirm.calling_addr,
            X121Addr::from_str("567").unwrap()
        );

        assert!(clear_confirm.facilities.is_empty());
    }

    #[test]
    fn decode_clear_confirm_with_facilities() {
        let buf = Bytes::from_static(b"\x10\x01\x17\x00\x06\x42\x07\x07\x43\x02\x02");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ClearConfirm);

        let X25Packet::ClearConfirm(clear_confirm) = packet else {
            unreachable!()
        };

        assert_eq!(clear_confirm.modulo, X25Modulo::Normal);
        assert_eq!(clear_confirm.channel, 1);
        assert!(clear_confirm.called_addr.is_null());
        assert!(clear_confirm.calling_addr.is_null());

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

        assert_eq!(clear_confirm.facilities, expected_facilities);
    }

    #[test]
    fn encode_normal_data() {
        let data = X25Data {
            modulo: X25Modulo::Normal,
            channel: 1,
            send_seq: 5,
            recv_seq: 7,
            qualifier: false,
            delivery: false,
            more: false,
            user_data: Bytes::from_static(b"testing"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(data.encode(&mut buf), Ok(10));

        assert_eq!(&buf[..], b"\x10\x01\xeatesting");
    }

    #[test]
    fn encode_normal_data_with_flags() {
        let data = X25Data {
            modulo: X25Modulo::Normal,
            channel: 1,
            send_seq: 5,
            recv_seq: 7,
            qualifier: true,
            delivery: true,
            more: true,
            user_data: Bytes::from_static(b"testing"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(data.encode(&mut buf), Ok(10));

        assert_eq!(&buf[..], b"\xd0\x01\xfatesting");
    }

    #[test]
    fn encode_extended_data() {
        let data = X25Data {
            modulo: X25Modulo::Extended,
            channel: 1,
            send_seq: 65,
            recv_seq: 99,
            qualifier: false,
            delivery: false,
            more: false,
            user_data: Bytes::from_static(b"testing"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(data.encode(&mut buf), Ok(11));

        assert_eq!(&buf[..], b"\x20\x01\x82\xc6testing");
    }

    #[test]
    fn encode_extended_data_with_flags() {
        let data = X25Data {
            modulo: X25Modulo::Extended,
            channel: 1,
            send_seq: 65,
            recv_seq: 99,
            qualifier: true,
            delivery: true,
            more: true,
            user_data: Bytes::from_static(b"testing"),
        };

        let mut buf = BytesMut::new();

        assert_eq!(data.encode(&mut buf), Ok(11));

        assert_eq!(&buf[..], b"\xe0\x01\x82\xc7testing");
    }

    #[test]
    fn decode_normal_data() {
        let buf = Bytes::from_static(b"\x10\x01\xeatesting");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::Data);

        let X25Packet::Data(data) = packet else {
            unreachable!()
        };

        assert_eq!(data.modulo, X25Modulo::Normal);
        assert_eq!(data.channel, 1);
        assert_eq!(data.send_seq, 5);
        assert_eq!(data.recv_seq, 7);
        assert!(!data.qualifier);
        assert!(!data.delivery);
        assert!(!data.more);
        assert_eq!(&data.user_data[..], b"testing");
    }

    #[test]
    fn decode_normal_data_with_flags() {
        let buf = Bytes::from_static(b"\xd0\x01\xfatesting");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::Data);

        let X25Packet::Data(data) = packet else {
            unreachable!()
        };

        assert_eq!(data.modulo, X25Modulo::Normal);
        assert_eq!(data.channel, 1);
        assert_eq!(data.send_seq, 5);
        assert_eq!(data.recv_seq, 7);
        assert!(data.qualifier);
        assert!(data.delivery);
        assert!(data.more);
        assert_eq!(&data.user_data[..], b"testing");
    }

    #[test]
    fn decode_extended_data() {
        let buf = Bytes::from_static(b"\x20\x01\x82\xc6testing");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::Data);

        let X25Packet::Data(data) = packet else {
            unreachable!()
        };

        assert_eq!(data.modulo, X25Modulo::Extended);
        assert_eq!(data.channel, 1);
        assert_eq!(data.send_seq, 65);
        assert_eq!(data.recv_seq, 99);
        assert!(!data.qualifier);
        assert!(!data.delivery);
        assert!(!data.more);
        assert_eq!(&data.user_data[..], b"testing");
    }

    #[test]
    fn decode_extended_data_with_flags() {
        let buf = Bytes::from_static(b"\xe0\x01\x82\xc7testing");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::Data);

        let X25Packet::Data(data) = packet else {
            unreachable!()
        };

        assert_eq!(data.modulo, X25Modulo::Extended);
        assert_eq!(data.channel, 1);
        assert_eq!(data.send_seq, 65);
        assert_eq!(data.recv_seq, 99);
        assert!(data.qualifier);
        assert!(data.delivery);
        assert!(data.more);
        assert_eq!(&data.user_data[..], b"testing");
    }

    #[test]
    fn encode_normal_receive_ready() {
        let receive_ready = X25ReceiveReady {
            modulo: X25Modulo::Normal,
            channel: 1,
            recv_seq: 7,
        };

        let mut buf = BytesMut::new();

        assert_eq!(receive_ready.encode(&mut buf), Ok(3));

        assert_eq!(&buf[..], b"\x10\x01\xe1");
    }

    #[test]
    fn encode_extended_receive_ready() {
        let receive_ready = X25ReceiveReady {
            modulo: X25Modulo::Extended,
            channel: 1,
            recv_seq: 99,
        };

        let mut buf = BytesMut::new();

        assert_eq!(receive_ready.encode(&mut buf), Ok(4));

        assert_eq!(&buf[..], b"\x20\x01\x01\xc6");
    }

    #[test]
    fn decode_normal_receive_ready() {
        let buf = Bytes::from_static(b"\x10\x01\xe1");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ReceiveReady);

        let X25Packet::ReceiveReady(receive_ready) = packet else {
            unreachable!()
        };

        assert_eq!(receive_ready.modulo, X25Modulo::Normal);
        assert_eq!(receive_ready.channel, 1);
        assert_eq!(receive_ready.recv_seq, 7);
    }

    #[test]
    fn decode_extended_receive_ready() {
        let buf = Bytes::from_static(b"\x20\x01\x01\xc6");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ReceiveReady);

        let X25Packet::ReceiveReady(receive_ready) = packet else {
            unreachable!()
        };

        assert_eq!(receive_ready.modulo, X25Modulo::Extended);
        assert_eq!(receive_ready.channel, 1);
        assert_eq!(receive_ready.recv_seq, 99);
    }

    #[test]
    fn encode_normal_receive_not_ready() {
        let receive_not_ready = X25ReceiveNotReady {
            modulo: X25Modulo::Normal,
            channel: 1,
            recv_seq: 7,
        };

        let mut buf = BytesMut::new();

        assert_eq!(receive_not_ready.encode(&mut buf), Ok(3));

        assert_eq!(&buf[..], b"\x10\x01\xe5");
    }

    #[test]
    fn encode_extended_receive_not_ready() {
        let receive_not_ready = X25ReceiveNotReady {
            modulo: X25Modulo::Extended,
            channel: 1,
            recv_seq: 99,
        };

        let mut buf = BytesMut::new();

        assert_eq!(receive_not_ready.encode(&mut buf), Ok(4));

        assert_eq!(&buf[..], b"\x20\x01\x05\xc6");
    }

    #[test]
    fn decode_normal_receive_not_ready() {
        let buf = Bytes::from_static(b"\x10\x01\xe5");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ReceiveNotReady);

        let X25Packet::ReceiveNotReady(receive_not_ready) = packet else {
            unreachable!()
        };

        assert_eq!(receive_not_ready.modulo, X25Modulo::Normal);
        assert_eq!(receive_not_ready.channel, 1);
        assert_eq!(receive_not_ready.recv_seq, 7);
    }

    #[test]
    fn decode_extended_receive_not_ready() {
        let buf = Bytes::from_static(b"\x20\x01\x05\xc6");

        let packet = X25Packet::decode(buf);

        dbg!(&packet);
        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ReceiveNotReady);

        let X25Packet::ReceiveNotReady(receive_not_ready) = packet else {
            unreachable!()
        };

        assert_eq!(receive_not_ready.modulo, X25Modulo::Extended);
        assert_eq!(receive_not_ready.channel, 1);
        assert_eq!(receive_not_ready.recv_seq, 99);
    }

    #[test]
    fn encode_reset_request() {
        let reset_request = X25ResetRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 5,
            diagnostic_code: 0,
        };

        let mut buf = BytesMut::new();

        assert_eq!(reset_request.encode(&mut buf), Ok(4));

        assert_eq!(&buf[..], b"\x10\x01\x1b\x05");
    }

    #[test]
    fn encode_reset_request_with_diagnostic_code() {
        let reset_request = X25ResetRequest {
            modulo: X25Modulo::Normal,
            channel: 1,
            cause: 5,
            diagnostic_code: 1,
        };

        let mut buf = BytesMut::new();

        assert_eq!(reset_request.encode(&mut buf), Ok(5));

        assert_eq!(&buf[..], b"\x10\x01\x1b\x05\x01");
    }

    #[test]
    fn decode_reset_request() {
        let buf = Bytes::from_static(b"\x10\x01\x1b\x05");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ResetRequest);

        let X25Packet::ResetRequest(reset_request) = packet else {
            unreachable!()
        };

        assert_eq!(reset_request.modulo, X25Modulo::Normal);
        assert_eq!(reset_request.channel, 1);
        assert_eq!(reset_request.cause, 5);
        assert_eq!(reset_request.diagnostic_code, 0);
    }

    #[test]
    fn decode_reset_request_with_diagnostic_code() {
        let buf = Bytes::from_static(b"\x10\x01\x1b\x05\x01");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ResetRequest);

        let X25Packet::ResetRequest(reset_request) = packet else {
            unreachable!()
        };

        assert_eq!(reset_request.modulo, X25Modulo::Normal);
        assert_eq!(reset_request.channel, 1);
        assert_eq!(reset_request.cause, 5);
        assert_eq!(reset_request.diagnostic_code, 1);
    }

    #[test]
    fn encode_reset_confirm() {
        let reset_confirm = X25ResetConfirm {
            modulo: X25Modulo::Normal,
            channel: 1,
        };

        let mut buf = BytesMut::new();

        assert_eq!(reset_confirm.encode(&mut buf), Ok(3));

        assert_eq!(&buf[..], b"\x10\x01\x1f");
    }

    #[test]
    fn decode_reset_confirm() {
        let buf = Bytes::from_static(b"\x10\x01\x1f");

        let packet = X25Packet::decode(buf);

        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(packet.packet_type(), X25PacketType::ResetConfirm);

        let X25Packet::ResetConfirm(reset_confirm) = packet else {
            unreachable!()
        };

        assert_eq!(reset_confirm.modulo, X25Modulo::Normal);
        assert_eq!(reset_confirm.channel, 1);
    }
}
