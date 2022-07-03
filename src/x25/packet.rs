use crate::x121::X121Address;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MIN_PACKET_LENGTH: usize = 3;

// Maximum packet length based on a super extended header (7 bytes) and maximum
// data field length (4096 bytes).
pub const MAX_PACKET_LENGTH: usize = 7 + 4096;

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

#[derive(Debug)]
pub struct X25CallRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub called_address: X121Address,
    pub calling_address: X121Address,
    pub facilities: Option<Bytes>,
    pub call_user_data: Option<Bytes>,
}

#[derive(Debug)]
pub struct X25CallAccepted {
    pub modulo: X25Modulo,
    pub channel: u16,
    // TODO: called_address, calling_address etc.
}

#[derive(Debug)]
pub struct X25ClearRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub cause: u8,
    pub diagnostic_code: Option<u8>,
    // TODO: called_address, calling_address etc.
}

#[derive(Debug)]
pub struct X25ClearConfirmation {
    pub modulo: X25Modulo,
    pub channel: u16,
    // TODO: optional called address calling address etc.
}

#[derive(Debug)]
pub struct X25Data {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub qualifier: bool,
    pub delivery_confirmation: bool,
    pub more_data: bool,
    pub receive_sequence: u16,
    pub send_sequence: u16,
    pub buffer: Bytes,
}

#[derive(Debug)]
pub struct X25ReceiveReady {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub receive_sequence: u16,
}

#[derive(Debug)]
pub struct X25ReceiveNotReady {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub receive_sequence: u16,
}

#[derive(Debug)]
pub struct X25ResetRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub cause: u8,
    pub diagnostic_code: Option<u8>,
}

#[derive(Debug)]
pub struct X25ResetConfirmation {
    pub modulo: X25Modulo,
    pub channel: u16,
}

#[derive(Debug)]
pub struct X25Diagnostic {
    pub modulo: X25Modulo,
    pub code: u8,
    // TODO: diagnostic explanation
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

pub fn parse_packet(mut buffer: Bytes) -> Result<X25Packet, String> {
    if buffer.remaining() < MIN_PACKET_LENGTH {
        return Err("Packet too short".into());
    }

    let gfi_group = buffer.get_u8();

    let gfi = (gfi_group & 0xf0) >> 4;

    let modulo = match gfi & 0x03 {
        0b01 => X25Modulo::Normal,
        0b10 => X25Modulo::Extended,
        _ => return Err("TODO".into()),
    };

    if modulo != X25Modulo::Normal {
        return Err("TODO".into());
    }

    let channel = (((gfi_group & 0x0f) << 4) as u16) | (buffer.get_u8() as u16);

    let type_ = buffer.get_u8();

    if type_ & 0x01 == 0 {
        let qualifier = (gfi & 0x80) >> 7 == 1;
        let delivery_confirmation = (gfi & 0x40) >> 6 == 1;

        let receive_sequence = ((type_ & 0xe0) >> 5) as u16;
        let more_data = (type_ & 0x10) >> 4 == 1;
        let send_sequence = ((type_ & 0x0e) >> 1) as u16;

        Ok(X25Packet::Data(X25Data {
            modulo,
            channel,
            qualifier,
            delivery_confirmation,
            more_data,
            receive_sequence,
            send_sequence,
            buffer,
        }))
    } else if type_ == 0b0000_1011 {
        if gfi != 0b0001 {
            return Err("Invalid general format identifier".into());
        }

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

        Ok(X25Packet::CallRequest(X25CallRequest {
            modulo,
            channel,
            called_address,
            calling_address,
            facilities,
            call_user_data,
        }))
    } else if type_ == 0b0000_1111 {
        // TODO: additional optional address fields
        Ok(X25Packet::CallAccepted(X25CallAccepted { modulo, channel }))
    } else if type_ == 0b0001_0011 {
        // TODO: check length again
        let cause = buffer.get_u8();

        let diagnostic_code = if buffer.has_remaining() {
            Some(buffer.get_u8())
        } else {
            None
        };

        // TODO: additional optional address fields
        Ok(X25Packet::ClearRequest(X25ClearRequest {
            modulo,
            channel,
            cause,
            diagnostic_code,
        }))
    } else if type_ == 0b0001_0111 {
        // TODO: additional optional address fields
        Ok(X25Packet::ClearConfirmation(X25ClearConfirmation {
            modulo,
            channel,
        }))
    } else if type_ & 0x1f == 0b0000_0001 {
        let receive_sequence = ((type_ & 0xe0) >> 5) as u16;

        Ok(X25Packet::ReceiveReady(X25ReceiveReady {
            modulo,
            channel,
            receive_sequence,
        }))
    } else if type_ & 0x1f == 0b0000_0101 {
        let receive_sequence = ((type_ & 0xe0) >> 5) as u16;

        Ok(X25Packet::ReceiveNotReady(X25ReceiveNotReady {
            modulo,
            channel,
            receive_sequence,
        }))
    } else if type_ == 0b0001_1011 {
        // TODO: check length again
        let cause = buffer.get_u8();

        let diagnostic_code = if buffer.has_remaining() {
            Some(buffer.get_u8())
        } else {
            None
        };

        Ok(X25Packet::ResetRequest(X25ResetRequest {
            modulo,
            channel,
            cause,
            diagnostic_code,
        }))
    } else if type_ == 0b0001_1111 {
        // TODO: check length again... this has no additional fields!

        Ok(X25Packet::ResetConfirmation(X25ResetConfirmation {
            modulo,
            channel,
        }))
    } else if type_ == 0b1111_0001 {
        if channel != 0 {
            // TODO: expected channel to be zero for diagnostic
        }

        // TODO: check length

        let code = buffer.get_u8();

        Ok(X25Packet::Diagnostic(X25Diagnostic { modulo, code }))
    } else {
        println!("I cannot deal with 0x{:02x}", type_);

        Err("Unidentifiable packet".into())
    }
}

pub fn format_packet(packet: &X25Packet) -> Bytes {
    let mut buffer = BytesMut::with_capacity(32);

    match packet {
        X25Packet::CallRequest(call_request) => {
            put_packet_header(
                &mut buffer,
                call_request.modulo,
                0,
                call_request.channel,
                0b0000_1011,
            );
            put_address_block(
                &mut buffer,
                &call_request.called_address,
                &call_request.calling_address,
            );

            if let Some(facilities) = &call_request.facilities {
                buffer.put_u8(facilities.len() as u8);
                buffer.put_slice(facilities);
            }

            if let Some(call_user_data) = &call_request.call_user_data {
                buffer.put_slice(call_user_data);
            }
        }

        X25Packet::CallAccepted(call_accepted) => {
            put_packet_header(
                &mut buffer,
                call_accepted.modulo,
                0,
                call_accepted.channel,
                0b0000_1111,
            );
        }

        X25Packet::ClearRequest(clear_request) => {
            put_packet_header(
                &mut buffer,
                clear_request.modulo,
                0,
                clear_request.channel,
                0b0001_0011,
            );

            buffer.put_u8(clear_request.cause);

            if let Some(diagnostic_code) = clear_request.diagnostic_code {
                buffer.put_u8(diagnostic_code);
            }
        }

        X25Packet::ClearConfirmation(clear_confirmation) => {
            put_packet_header(
                &mut buffer,
                clear_confirmation.modulo,
                0,
                clear_confirmation.channel,
                0b0001_0111,
            );
        }

        X25Packet::Data(data) => {
            // TODO: qualifier, delivery_confirmation
            let gfi = 0b0000;

            // TODO: more_data
            let type_ = ((data.receive_sequence as u8) << 5) | ((data.send_sequence as u8) << 1);

            put_packet_header(&mut buffer, data.modulo, gfi, data.channel, type_);

            buffer.put_slice(&data.buffer);
        }

        X25Packet::ReceiveReady(receive_ready) => {
            let type_ = ((receive_ready.receive_sequence as u8) << 5) | 0b0000_0001;

            put_packet_header(
                &mut buffer,
                receive_ready.modulo,
                0,
                receive_ready.channel,
                type_,
            );
        }

        X25Packet::ReceiveNotReady(receive_not_ready) => {
            let type_ = ((receive_not_ready.receive_sequence as u8) << 5) | 0b0000_0101;

            put_packet_header(
                &mut buffer,
                receive_not_ready.modulo,
                0,
                receive_not_ready.channel,
                type_,
            );
        }

        X25Packet::ResetRequest(reset_request) => {
            put_packet_header(
                &mut buffer,
                reset_request.modulo,
                0,
                reset_request.channel,
                0b0001_1011,
            );

            buffer.put_u8(reset_request.cause);

            if let Some(diagnostic_code) = reset_request.diagnostic_code {
                buffer.put_u8(diagnostic_code);
            }
        }

        X25Packet::ResetConfirmation(reset_confirmation) => {
            put_packet_header(
                &mut buffer,
                reset_confirmation.modulo,
                0,
                reset_confirmation.channel,
                0b0001_1111,
            );
        }

        X25Packet::Diagnostic(diagnostic) => {
            put_packet_header(&mut buffer, diagnostic.modulo, 0, 0, 0b1111_0001);

            buffer.put_u8(diagnostic.code);
        }
    }

    buffer.freeze()
}

// TODO: gfi -> gfi_overlay?
fn put_packet_header(buffer: &mut BytesMut, modulo: X25Modulo, gfi: u8, channel: u16, type_: u8) {
    if modulo != X25Modulo::Normal {
        todo!();
    }

    buffer.put_u8(((gfi | 0b0001) << 4) | (((channel & 0x0f00) >> 8) as u8));
    buffer.put_u8((channel & 0x00ff) as u8);
    buffer.put_u8(type_);
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
