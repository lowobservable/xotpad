//! X.25 parameters.
//!
//! This module provides functionalty for managing X.25 parameters.

use std::time::Duration;

use crate::x121::X121Addr;

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

/// Common X.25 parameters.
#[derive(Clone, Debug)]
pub struct X25Params {
    /// The local X.121 address.
    pub addr: X121Addr,

    /// The packet sequence numbering scheme.
    pub modulo: X25Modulo,

    /// The _call request_ timeout.
    pub t21: Duration,

    /// The _reset request_ timeout.
    pub t22: Duration,

    /// The _clear request_ timeout.
    pub t23: Duration,
}
