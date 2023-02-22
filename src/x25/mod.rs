//! X.25 packet switched networking.
//!
//! The X.25 protocol is specified in [ITU-T Rec. X.25 (10/96)].
//!
//! [ITU-T Rec. X.25 (10/96)]: https://www.itu.int/rec/T-REC-X.25-199610-I

pub mod facility;
pub mod packet;

pub use self::facility::X25Facility;
pub use self::packet::{MAX_PACKET_LEN, MIN_PACKET_LEN};
