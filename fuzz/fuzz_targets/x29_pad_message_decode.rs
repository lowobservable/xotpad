#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

extern crate libxotpad;

use libxotpad::x29::fuzzing::pad_message_decode;

fuzz_target!(|data: &[u8]| {
    let buf = Bytes::copy_from_slice(data);

    let _ = pad_message_decode(buf);
});
