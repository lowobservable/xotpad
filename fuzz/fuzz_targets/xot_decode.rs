#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;

extern crate libxotpad;

use libxotpad::xot::fuzzing::decode;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);

    let _ = decode(&mut buf);
});
