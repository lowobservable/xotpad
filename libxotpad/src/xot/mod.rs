//! X.25 over TCP.
//!
//! This module provides functionality to transmit X.25 packets over TCP.
//!
//! The XOT protocol is specified in [IETF RFC 1613].
//!
//! [IETF RFC 1613]: https://tools.ietf.org/html/rfc1613

use std::io;
use std::net::TcpStream;

use crate::x121::X121Addr;

mod link;
mod resolver;

pub use self::link::XotLink;
pub use self::resolver::XotResolver;

/// Registered XOT TCP port number.
pub const TCP_PORT: u16 = 1998;

pub fn connect(addr: &X121Addr, resolver: &XotResolver) -> io::Result<XotLink> {
    let Some(xot_gateway) = resolver.lookup(addr) else {
        // TODO: HostUnreachable...
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no XOT gateway found".to_owned(),
        ));
    };

    let tcp_stream = TcpStream::connect((xot_gateway, TCP_PORT))?;

    let xot_link = XotLink::new(tcp_stream);

    Ok(xot_link)
}

#[cfg(fuzzing)]
pub mod fuzzing {
    use bytes::{Bytes, BytesMut};

    pub fn decode(buf: &mut BytesMut) -> Result<Option<Bytes>, String> {
        super::link::decode(buf)
    }
}
