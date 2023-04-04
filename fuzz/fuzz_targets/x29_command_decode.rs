#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

extern crate xotpad;

use xotpad::pad::x29::X29Command;

fuzz_target!(|data: &[u8]| {
    let buf = Bytes::copy_from_slice(data);

    let _ = X29Command::decode(buf);
});
