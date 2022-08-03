use crate::x25::packet::X25Modulo;

const DEFAULT_MAX_PACKET_SIZE: usize = 128;
const DEFAULT_WINDOW_SIZE: u16 = 2;

#[derive(Clone, Debug)]
pub struct X25Parameters {
    modulo: X25Modulo,
    send_max_packet_size: usize,
    send_window_size: u16,
    receive_max_packet_size: usize,
    receive_window_size: u16,
}

impl X25Parameters {
    pub fn new(
        modulo: X25Modulo,
        send_max_packet_size: usize,
        send_window_size: u16,
        receive_max_packet_size: usize,
        receive_window_size: u16,
    ) -> Result<Self, String> {
        if !is_valid_packet_size(send_max_packet_size) {
            return Err("invalid send max packet size".into());
        }

        if !is_valid_window_size(send_window_size, modulo) {
            return Err("invalid send window size".into());
        }

        if !is_valid_packet_size(receive_max_packet_size) {
            return Err("invalid receive max packet size".into());
        }

        if !is_valid_window_size(receive_window_size, modulo) {
            return Err("invalid receive window size".into());
        }

        Ok(X25Parameters {
            modulo,
            send_max_packet_size,
            send_window_size,
            receive_max_packet_size,
            receive_window_size,
        })
    }

    pub fn default_with_modulo(modulo: X25Modulo) -> X25Parameters {
        X25Parameters::new(
            modulo,
            DEFAULT_MAX_PACKET_SIZE,
            DEFAULT_WINDOW_SIZE,
            DEFAULT_MAX_PACKET_SIZE,
            DEFAULT_WINDOW_SIZE,
        )
        .unwrap()
    }

    pub fn modulo(&self) -> X25Modulo {
        self.modulo
    }

    pub fn send_max_packet_size(&self) -> usize {
        self.send_max_packet_size
    }

    pub fn send_window_size(&self) -> u16 {
        self.send_window_size
    }

    pub fn receive_max_packet_size(&self) -> usize {
        self.receive_max_packet_size
    }

    pub fn receive_window_size(&self) -> u16 {
        self.receive_window_size
    }
}

impl Default for X25Parameters {
    fn default() -> Self {
        X25Parameters::default_with_modulo(X25Modulo::Normal)
    }
}

fn is_valid_packet_size(packet_size: usize) -> bool {
    let valid_packet_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

    valid_packet_sizes.contains(&packet_size)
}

fn is_valid_window_size(window_size: u16, modulo: X25Modulo) -> bool {
    window_size > 0 && window_size < (modulo as u16)
}
