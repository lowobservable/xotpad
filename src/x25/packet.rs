use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::x121::X121Address;

pub const MIN_PACKET_LENGTH: usize = 3;

// Maximum packet length based on a super extended header (7 bytes) and maximum
// data field length (4096 bytes).
pub const MAX_PACKET_LENGTH: usize = 7 + 4096;

pub const MAX_CHANNEL: u16 = 4095;

#[derive(Debug)]
pub enum X25Packet {
    CallRequest(X25CallRequest),
    CallAccepted(X25CallAccepted),
    ClearRequest(X25ClearRequest),
    ClearConfirmation(X25ClearConfirmation),
    Data(X25Data),
    // TODO: Interrupt
    // TODO: InterruptConfirmation
    ReceiveReady(X25ReceiveReady),
    ReceiveNotReady(X25ReceiveNotReady),
    // TODO: Reject
    ResetRequest(X25ResetRequest),
    ResetConfirmation(X25ResetConfirmation),
    // TODO: RestartRequest
    // TODO: RestartConfirmation
    Diagnostic(X25Diagnostic),
}

#[derive(Debug, PartialEq)]
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum X25Modulo {
    Normal = 8,
    Extended = 128,
}

impl X25Packet {
    pub fn modulo(&self) -> X25Modulo {
        match self {
            X25Packet::CallRequest(call_request) => call_request.modulo,
            X25Packet::CallAccepted(call_accepted) => call_accepted.modulo,
            X25Packet::ClearRequest(clear_request) => clear_request.modulo,
            X25Packet::ClearConfirmation(clear_confirmation) => clear_confirmation.modulo,
            X25Packet::Data(data) => data.modulo,
            X25Packet::ReceiveReady(receive_ready) => receive_ready.modulo,
            X25Packet::ReceiveNotReady(receive_not_ready) => receive_not_ready.modulo,
            X25Packet::ResetRequest(reset_request) => reset_request.modulo,
            X25Packet::ResetConfirmation(reset_confirmation) => reset_confirmation.modulo,
            X25Packet::Diagnostic(diagnostic) => diagnostic.modulo,
        }
    }

    pub fn packet_type(&self) -> X25PacketType {
        match self {
            X25Packet::CallRequest(_) => X25PacketType::CallRequest,
            X25Packet::CallAccepted(_) => X25PacketType::CallAccepted,
            X25Packet::ClearRequest(_) => X25PacketType::ClearRequest,
            X25Packet::ClearConfirmation(_) => X25PacketType::ClearConfirmation,
            X25Packet::Data(_) => X25PacketType::Data,
            X25Packet::ReceiveReady(_) => X25PacketType::ReceiveReady,
            X25Packet::ReceiveNotReady(_) => X25PacketType::ReceiveNotReady,
            X25Packet::ResetRequest(_) => X25PacketType::ResetRequest,
            X25Packet::ResetConfirmation(_) => X25PacketType::ResetConfirmation,
            X25Packet::Diagnostic(_) => X25PacketType::Diagnostic,
        }
    }
}

#[derive(Debug)]
pub struct X25CallRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub called_address: X121Address,
    pub calling_address: X121Address,
    pub facilities: Option<Bytes>,
    pub call_user_data: Option<Bytes>,
}

impl X25CallRequest {
    fn parse(mut buffer: Bytes, modulo: X25Modulo, channel: u16) -> Result<X25CallRequest, String> {
        let (called_address, calling_address) = parse_address_block(&mut buffer)?;

        let facilities = if buffer.has_remaining() {
            let facilities_length = buffer.get_u8() as usize;

            if buffer.remaining() < facilities_length {
                return Err("Packet too short".into());
            }

            Some(buffer.split_to(facilities_length))
        } else {
            None
        };

        let call_user_data = if buffer.has_remaining() {
            Some(buffer)
        } else {
            None
        };

        Ok(X25CallRequest {
            modulo,
            channel,
            called_address,
            calling_address,
            facilities,
            call_user_data,
        })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(32);

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, 0x0b)?;

        put_address_block(&mut buffer, &self.called_address, &self.calling_address);

        if let Some(facilities) = &self.facilities {
            buffer.put_u8(facilities.len() as u8);
            buffer.put_slice(facilities);
        }

        if let Some(call_user_data) = &self.call_user_data {
            buffer.put_slice(call_user_data);
        }

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25CallAccepted {
    pub modulo: X25Modulo,
    pub channel: u16,
    // TODO: called_address, calling_address etc.
}

impl X25CallAccepted {
    fn parse(_buffer: Bytes, modulo: X25Modulo, channel: u16) -> Result<X25CallAccepted, String> {
        // TODO: additional optional address fields
        Ok(X25CallAccepted { modulo, channel })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(3);

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, 0x0f)?;

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25ClearRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub cause: u8,
    pub diagnostic_code: Option<u8>,
    // TODO: called_address, calling_address etc.
}

impl X25ClearRequest {
    fn parse(
        mut buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
    ) -> Result<X25ClearRequest, String> {
        if buffer.remaining() < 1 {
            return Err("Packet too short".into());
        }

        let cause = buffer.get_u8();

        let diagnostic_code = if buffer.has_remaining() {
            Some(buffer.get_u8())
        } else {
            None
        };

        // TODO: additional optional address fields
        Ok(X25ClearRequest {
            modulo,
            channel,
            cause,
            diagnostic_code,
        })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(5);

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, 0x13)?;

        buffer.put_u8(self.cause);

        if let Some(diagnostic_code) = self.diagnostic_code {
            buffer.put_u8(diagnostic_code);
        }

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25ClearConfirmation {
    pub modulo: X25Modulo,
    pub channel: u16,
    // TODO: optional called address calling address etc.
}

impl X25ClearConfirmation {
    fn parse(
        _buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
    ) -> Result<X25ClearConfirmation, String> {
        // TODO: additional optional address fields
        Ok(X25ClearConfirmation { modulo, channel })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(3);

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, 0x17)?;

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25Data {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub send_sequence: u16,
    pub receive_sequence: u16,
    pub qualifier: bool,
    pub delivery_confirmation: bool,
    pub more_data: bool,
    pub buffer: Bytes,
}

impl X25Data {
    fn parse(
        buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        gfi: u8,
        type_: u8,
    ) -> Result<X25Data, String> {
        match modulo {
            X25Modulo::Normal => X25Data::parse_normal(buffer, modulo, channel, gfi, type_),
            X25Modulo::Extended => X25Data::parse_extended(buffer, modulo, channel, gfi, type_),
        }
    }

    fn format(&self) -> Result<Bytes, String> {
        match self.modulo {
            X25Modulo::Normal => self.format_normal(),
            X25Modulo::Extended => self.format_extended(),
        }
    }

    fn parse_normal(
        buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        gfi: u8,
        type_: u8,
    ) -> Result<X25Data, String> {
        let qualifier = (gfi & 0x80) >> 4 == 1;
        let delivery_confirmation = (gfi & 0x40) >> 3 == 1;

        let send_sequence = ((type_ & 0x0e) >> 1) as u16;
        let receive_sequence = ((type_ & 0xe0) >> 5) as u16;
        let more_data = (type_ & 0x10) >> 4 == 1;

        Ok(X25Data {
            modulo,
            channel,
            send_sequence,
            receive_sequence,
            qualifier,
            delivery_confirmation,
            more_data,
            buffer,
        })
    }

    fn parse_extended(
        mut buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        gfi: u8,
        type_: u8,
    ) -> Result<X25Data, String> {
        if buffer.remaining() < 1 {
            return Err("Packet too short".into());
        }

        let qualifier = (gfi & 0x80) >> 4 == 1;
        let delivery_confirmation = (gfi & 0x40) >> 3 == 1;

        let send_sequence = ((type_ & 0xfe) >> 1) as u16;

        let byte = buffer.get_u8();

        let receive_sequence = ((byte & 0xfe) >> 1) as u16;
        let more_data = (byte & 0x01) == 1;

        Ok(X25Data {
            modulo,
            channel,
            send_sequence,
            receive_sequence,
            qualifier,
            delivery_confirmation,
            more_data,
            buffer,
        })
    }

    fn format_normal(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(3 + self.buffer.len());

        let gfi_overlay = ((self.qualifier as u8) << 4) | ((self.delivery_confirmation as u8) << 3);

        let type_ = ((self.receive_sequence as u8) << 5)
            | ((self.more_data as u8) << 4)
            | ((self.send_sequence as u8) << 1);

        put_packet_header(&mut buffer, self.modulo, gfi_overlay, self.channel, type_)?;

        buffer.put_slice(&self.buffer);

        Ok(buffer.freeze())
    }

    fn format_extended(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(4 + self.buffer.len());

        let gfi_overlay = ((self.qualifier as u8) << 4) | ((self.delivery_confirmation as u8) << 3);

        let type_ = (self.send_sequence as u8) << 1;

        put_packet_header(&mut buffer, self.modulo, gfi_overlay, self.channel, type_)?;

        buffer.put_u8(((self.receive_sequence as u8) << 1) | (self.more_data as u8));

        buffer.put_slice(&self.buffer);

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25ReceiveReady {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub receive_sequence: u16,
}

impl X25ReceiveReady {
    fn parse(
        buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        type_: u8,
    ) -> Result<X25ReceiveReady, String> {
        match modulo {
            X25Modulo::Normal => X25ReceiveReady::parse_normal(buffer, modulo, channel, type_),
            X25Modulo::Extended => X25ReceiveReady::parse_extended(buffer, modulo, channel, type_),
        }
    }

    fn format(&self) -> Result<Bytes, String> {
        match self.modulo {
            X25Modulo::Normal => self.format_normal(),
            X25Modulo::Extended => self.format_extended(),
        }
    }

    fn parse_normal(
        _buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        type_: u8,
    ) -> Result<X25ReceiveReady, String> {
        let receive_sequence = ((type_ & 0xe0) >> 5) as u16;

        Ok(X25ReceiveReady {
            modulo,
            channel,
            receive_sequence,
        })
    }

    fn parse_extended(
        mut buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        type_: u8,
    ) -> Result<X25ReceiveReady, String> {
        if type_ & 0xe0 != 0 {
            return Err("Unidentifiable packet".into());
        }

        if buffer.remaining() < 1 {
            return Err("Packet too short".into());
        }

        let receive_sequence = ((buffer.get_u8() & 0xfe) >> 1) as u16;

        Ok(X25ReceiveReady {
            modulo,
            channel,
            receive_sequence,
        })
    }

    fn format_normal(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(3);

        let type_ = ((self.receive_sequence as u8) << 5) | 0x01;

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, type_)?;

        Ok(buffer.freeze())
    }

    fn format_extended(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(4);

        let type_ = 0x01;

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, type_)?;

        buffer.put_u8((self.receive_sequence as u8) << 1);

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25ReceiveNotReady {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub receive_sequence: u16,
}

impl X25ReceiveNotReady {
    fn parse(
        buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        type_: u8,
    ) -> Result<X25ReceiveNotReady, String> {
        match modulo {
            X25Modulo::Normal => X25ReceiveNotReady::parse_normal(buffer, modulo, channel, type_),
            X25Modulo::Extended => {
                X25ReceiveNotReady::parse_extended(buffer, modulo, channel, type_)
            }
        }
    }

    fn format(&self) -> Result<Bytes, String> {
        match self.modulo {
            X25Modulo::Normal => self.format_normal(),
            X25Modulo::Extended => self.format_extended(),
        }
    }

    fn parse_normal(
        _buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        type_: u8,
    ) -> Result<X25ReceiveNotReady, String> {
        let receive_sequence = ((type_ & 0xe0) >> 5) as u16;

        Ok(X25ReceiveNotReady {
            modulo,
            channel,
            receive_sequence,
        })
    }

    fn parse_extended(
        mut buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
        type_: u8,
    ) -> Result<X25ReceiveNotReady, String> {
        if type_ & 0xe0 != 0 {
            return Err("Unidentifiable packet".into());
        }

        if buffer.remaining() < 1 {
            return Err("Packet too short".into());
        }

        let receive_sequence = ((buffer.get_u8() & 0xfe) >> 1) as u16;

        Ok(X25ReceiveNotReady {
            modulo,
            channel,
            receive_sequence,
        })
    }

    fn format_normal(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(3);

        let type_ = ((self.receive_sequence as u8) << 5) | 0x05;

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, type_)?;

        Ok(buffer.freeze())
    }

    fn format_extended(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(4);

        let type_ = 0x05;

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, type_)?;

        buffer.put_u8((self.receive_sequence as u8) << 1);

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25ResetRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub cause: u8,
    pub diagnostic_code: Option<u8>,
}

impl X25ResetRequest {
    fn parse(
        mut buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
    ) -> Result<X25ResetRequest, String> {
        if buffer.remaining() < 1 {
            return Err("Packet too short".into());
        }

        let cause = buffer.get_u8();

        let diagnostic_code = if buffer.has_remaining() {
            Some(buffer.get_u8())
        } else {
            None
        };

        Ok(X25ResetRequest {
            modulo,
            channel,
            cause,
            diagnostic_code,
        })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(5);

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, 0x1b)?;

        buffer.put_u8(self.cause);

        if let Some(diagnostic_code) = self.diagnostic_code {
            buffer.put_u8(diagnostic_code);
        }

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25ResetConfirmation {
    pub modulo: X25Modulo,
    pub channel: u16,
}

impl X25ResetConfirmation {
    fn parse(
        _buffer: Bytes,
        modulo: X25Modulo,
        channel: u16,
    ) -> Result<X25ResetConfirmation, String> {
        // TODO: check length again... this has no additional fields!

        Ok(X25ResetConfirmation { modulo, channel })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(3);

        put_packet_header(&mut buffer, self.modulo, 0, self.channel, 0x1f)?;

        Ok(buffer.freeze())
    }
}

#[derive(Debug)]
pub struct X25Diagnostic {
    pub modulo: X25Modulo,
    pub code: u8,
    // TODO: diagnostic explanation
}

impl X25Diagnostic {
    fn parse(mut buffer: Bytes, modulo: X25Modulo, channel: u16) -> Result<X25Diagnostic, String> {
        if channel != 0 {
            // TODO: expected channel to be zero for diagnostic
        }

        if buffer.remaining() < 1 {
            return Err("Packet too short".into());
        }

        let code = buffer.get_u8();

        Ok(X25Diagnostic { modulo, code })
    }

    fn format(&self) -> Result<Bytes, String> {
        let mut buffer = BytesMut::with_capacity(4);

        put_packet_header(&mut buffer, self.modulo, 0, 0, 0x1f)?;

        buffer.put_u8(self.code);

        Ok(buffer.freeze())
    }
}

pub fn parse_packet(mut buffer: Bytes) -> Result<X25Packet, String> {
    if buffer.remaining() < MIN_PACKET_LENGTH {
        return Err("Packet too short".into());
    }

    let header = &buffer[..3];

    let gfi = (header[0] & 0xf0) >> 4;

    let modulo = match gfi & 0x03 {
        0b01 => X25Modulo::Normal,
        0b10 => X25Modulo::Extended,
        _ => return Err("Invalid general format identifier".into()),
    };

    let channel = (((header[0] & 0x0f) << 4) as u16) | (header[1] as u16);

    let type_ = header[2];

    buffer.advance(3);

    if type_ & 0x01 == 0x00 {
        let data = X25Data::parse(buffer, modulo, channel, gfi, type_)?;

        Ok(X25Packet::Data(data))
    } else if type_ == 0x0b {
        let call_request = X25CallRequest::parse(buffer, modulo, channel)?;

        Ok(X25Packet::CallRequest(call_request))
    } else if type_ == 0x0f {
        let call_accepted = X25CallAccepted::parse(buffer, modulo, channel)?;

        Ok(X25Packet::CallAccepted(call_accepted))
    } else if type_ == 0x13 {
        let clear_request = X25ClearRequest::parse(buffer, modulo, channel)?;

        Ok(X25Packet::ClearRequest(clear_request))
    } else if type_ == 0x17 {
        let clear_confirmation = X25ClearConfirmation::parse(buffer, modulo, channel)?;

        Ok(X25Packet::ClearConfirmation(clear_confirmation))
    } else if type_ & 0x1f == 0x01 {
        let receive_ready = X25ReceiveReady::parse(buffer, modulo, channel, type_)?;

        Ok(X25Packet::ReceiveReady(receive_ready))
    } else if type_ & 0x1f == 0x05 {
        let receive_not_ready = X25ReceiveNotReady::parse(buffer, modulo, channel, type_)?;

        Ok(X25Packet::ReceiveNotReady(receive_not_ready))
    } else if type_ == 0x1b {
        let reset_request = X25ResetRequest::parse(buffer, modulo, channel)?;

        Ok(X25Packet::ResetRequest(reset_request))
    } else if type_ == 0x1f {
        let reset_confirmation = X25ResetConfirmation::parse(buffer, modulo, channel)?;

        Ok(X25Packet::ResetConfirmation(reset_confirmation))
    } else if type_ == 0xf1 {
        let diagnostic = X25Diagnostic::parse(buffer, modulo, channel)?;

        Ok(X25Packet::Diagnostic(diagnostic))
    } else {
        println!("I cannot deal with 0x{:02x}", type_);

        Err("Unidentifiable packet".into())
    }
}

pub fn format_packet(packet: &X25Packet) -> Result<Bytes, String> {
    match packet {
        X25Packet::CallRequest(call_request) => call_request.format(),
        X25Packet::CallAccepted(call_accepted) => call_accepted.format(),
        X25Packet::ClearRequest(clear_request) => clear_request.format(),
        X25Packet::ClearConfirmation(clear_confirmation) => clear_confirmation.format(),
        X25Packet::Data(data) => data.format(),
        X25Packet::ReceiveReady(receive_ready) => receive_ready.format(),
        X25Packet::ReceiveNotReady(receive_not_ready) => receive_not_ready.format(),
        X25Packet::ResetRequest(reset_request) => reset_request.format(),
        X25Packet::ResetConfirmation(reset_confirmation) => reset_confirmation.format(),
        X25Packet::Diagnostic(diagnostic) => diagnostic.format(),
    }
}

// TODO: gfi -> gfi_overlay?
fn put_packet_header(
    buffer: &mut BytesMut,
    modulo: X25Modulo,
    gfi_overlay: u8,
    channel: u16,
    type_: u8,
) -> Result<(), String> {
    if channel > MAX_CHANNEL {
        return Err("Invalid channel".into());
    }

    let gfi: u8 = match modulo {
        X25Modulo::Normal => 0b01,
        X25Modulo::Extended => 0b10,
    };

    buffer.put_u8(((gfi | gfi_overlay) << 4) | (((channel & 0x0f00) >> 8) as u8));
    buffer.put_u8((channel & 0x00ff) as u8);
    buffer.put_u8(type_);

    Ok(())
}

// (non-TOA/NPI address
fn parse_address_block(buffer: &mut Bytes) -> Result<(X121Address, X121Address), String> {
    if buffer.remaining() < 1 {
        return Err("Packet too short".into());
    }

    let length = buffer.get_u8();

    let calling_length = ((length & 0xf0) >> 4) as usize;
    let called_length = (length & 0x0f) as usize;

    // Convert the length into packed bytes (from digits).
    let length = calling_length + called_length;
    let length = (length / 2) + (length % 2);

    if buffer.remaining() < length {
        return Err("Packet too short".into());
    }

    let address_buffer = buffer.split_to(length);

    // Unpack the digits.
    let mut digits = address_buffer
        .iter()
        .flat_map(|b| [(b & 0xf0) >> 4, b & 0x0f]);

    // Convert digits to addresses.
    let called = X121Address::from_digits(digits.by_ref().take(called_length))?;
    let calling = X121Address::from_digits(digits.take(calling_length))?;

    Ok((called, calling))
}

fn put_address_block(buffer: &mut BytesMut, called: &X121Address, calling: &X121Address) {
    buffer.put_u8(((calling.len() as u8) << 4) | (called.len() as u8));

    // Combine calling and called address digits.
    let digits: Vec<u8> = called.digits().chain(calling.digits()).collect();

    for pair in digits.chunks(2) {
        let high = pair[0];
        let low = if pair.len() > 1 { pair[1] } else { 0 };

        buffer.put_u8((high << 4) | low);
    }
}
