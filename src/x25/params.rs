//! X.25 parameters.
//!
//! This module provides functionalty for managing X.25 parameters.

use std::time::Duration;

use crate::x121::X121Addr;
use crate::x25::X25Modulo;

/// Common X.25 parameters.
#[derive(Clone, Debug)]
pub struct X25Params {
    /// The local X.121 address.
    pub addr: X121Addr,

    /// The packet sequence numbering scheme.
    pub modulo: X25Modulo,

    /// The maximum data field length of _data_ packets sent.
    pub send_packet_size: usize,

    /// The number of packets that can be sent before waiting for an acknowledgment.
    pub send_window_size: u8,

    /// The _call request_ timeout.
    pub t21: Duration,

    /// The _reset request_ timeout.
    pub t22: Duration,

    /// The _clear request_ timeout.
    pub t23: Duration,
}
