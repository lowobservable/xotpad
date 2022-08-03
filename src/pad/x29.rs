use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const PAD_PROTOCOL: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

pub const MAX_CALL_DATA_LENGTH: usize = 12;

pub struct X29CallUserData {
    protocol: [u8; 4],
    call_data: Vec<u8>,
}

impl X29CallUserData {
    pub fn new(call_data: &[u8]) -> Result<Self, String> {
        if call_data.len() > MAX_CALL_DATA_LENGTH {
            return Err("call data too long".into());
        }

        Ok(X29CallUserData {
            protocol: PAD_PROTOCOL,
            call_data: Vec::from(call_data),
        })
    }

    pub fn is_pad(&self) -> bool {
        self.protocol == PAD_PROTOCOL
    }

    pub fn call_data(&self) -> &[u8] {
        &self.call_data
    }
}

pub fn encode_call_user_data(call_user_data: &X29CallUserData) -> Bytes {
    let mut buffer = BytesMut::with_capacity(16);

    buffer.put_slice(&call_user_data.protocol);
    buffer.put_slice(&call_user_data.call_data);

    buffer.freeze()
}

pub fn decode_call_user_data(buffer: Bytes) -> Result<X29CallUserData, String> {
    if buffer.remaining() < 4 {
        return Err("call user data too short".into());
    }

    if buffer.remaining() > 16 {
        return Err("call user data too long".into());
    }

    let mut protocol: [u8; 4] = [0; 4];

    protocol.copy_from_slice(&buffer[..4]);

    let call_data = buffer[4..].to_vec();

    Ok(X29CallUserData {
        protocol,
        call_data,
    })
}
