#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

extern crate xotpad;

use xotpad::x25::X25Packet;

fuzz_target!(|data: &[u8]| {
    let buf = Bytes::copy_from_slice(data);

    let _ = X25Packet::decode(buf);
});
