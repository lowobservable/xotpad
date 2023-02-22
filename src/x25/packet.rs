//! X.25 packets.
//!
//! This module provides functionality for encoding and decoding X.25 packets.

use bytes::Bytes;

use crate::x121::X121Addr;

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
pub enum X25Packet {}

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
pub enum X25Modulo {
    /// Numbers cycle through the entire range 0 to 7.
    Normal = 8,

    /// Numbers cycle through the entire range 0 to 127.
    Extended = 128,
}

/// X.25 _call request_ packet.
pub struct X25CallRequest {
    pub modulo: X25Modulo,
    pub channel: u16,
    pub called_addr: X121Addr,
    pub calling_addr: X121Addr,
    //TODO: pub facilities: Vec<X25Facility>,
    pub call_user_data: Bytes,
}
