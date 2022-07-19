use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;

#[derive(Debug)]
pub enum X25Facility {
    PacketSize {
        from_called: usize,
        from_calling: usize,
    },
    WindowSize {
        from_called: u8,
        from_calling: u8,
    },
    ClassA(u8, (u8,)),
    ClassB(u8, (u8, u8)),
    ClassC(u8, (u8, u8, u8)),
    ClassD(u8, Bytes),
}

pub fn parse_facilities(mut buffer: Bytes) -> Result<Vec<X25Facility>, String> {
    let mut facilities = Vec::new();

    let mut codes: HashSet<u8> = HashSet::new();

    while !buffer.is_empty() {
        let code = buffer.get_u8();

        if !codes.insert(code) {
            return Err("Facility code repeated".into());
        }

        let class = (code & 0xc0) >> 6;

        if code == 0x42 {
            let (from_called, from_calling) = parse_class_b_parameters(&mut buffer)?;

            facilities.push(X25Facility::PacketSize {
                from_called: decode_packet_size(from_called)?,
                from_calling: decode_packet_size(from_calling)?,
            });
        } else if code == 0x43 {
            let (from_called, from_calling) = parse_class_b_parameters(&mut buffer)?;

            facilities.push(X25Facility::WindowSize {
                from_called,
                from_calling,
            });
        } else if class == 0 {
            facilities.push(X25Facility::ClassA(
                code,
                parse_class_a_parameters(&mut buffer)?,
            ));
        } else if class == 1 {
            facilities.push(X25Facility::ClassB(
                code,
                parse_class_b_parameters(&mut buffer)?,
            ));
        } else if class == 2 {
            facilities.push(X25Facility::ClassC(
                code,
                parse_class_c_parameters(&mut buffer)?,
            ));
        } else if class == 3 {
            facilities.push(X25Facility::ClassD(
                code,
                parse_class_d_parameters(&mut buffer)?,
            ));
        }
    }

    Ok(facilities)
}

pub fn format_facilities(facilities: &Vec<X25Facility>) -> Result<Bytes, String> {
    let mut buffer = BytesMut::new();

    // TODO: ensure that outgoing facility codes are unique?

    for facility in facilities {
        match facility {
            X25Facility::PacketSize {
                from_called,
                from_calling,
            } => {
                let from_called = encode_packet_size(*from_called)?;
                let from_calling = encode_packet_size(*from_calling)?;

                buffer.put_u8(0x42);
                buffer.put(format_class_b_parameters(&(from_called, from_calling)));
            }
            X25Facility::WindowSize {
                from_called,
                from_calling,
            } => {
                buffer.put_u8(0x43);
                buffer.put(format_class_b_parameters(&(*from_called, *from_calling)));
            }
            X25Facility::ClassA(code, parameters) => {
                buffer.put_u8(*code);
                buffer.put(format_class_a_parameters(parameters));
            }
            X25Facility::ClassB(code, parameters) => {
                buffer.put_u8(*code);
                buffer.put(format_class_b_parameters(parameters));
            }
            X25Facility::ClassC(code, parameters) => {
                buffer.put_u8(*code);
                buffer.put(format_class_c_parameters(parameters));
            }
            X25Facility::ClassD(code, parameters) => {
                buffer.put_u8(*code);
                buffer.put(format_class_d_parameters(parameters));
            }
        }
    }

    Ok(buffer.freeze())
}

fn parse_class_a_parameters(buffer: &mut Bytes) -> Result<(u8,), String> {
    if buffer.remaining() < 1 {
        return Err("Class coding of the facility corresponding to a parameter field length larger than remainder of packet".into());
    }

    Ok((buffer.get_u8(),))
}

fn format_class_a_parameters(parameters: &(u8,)) -> Bytes {
    let mut buffer = BytesMut::with_capacity(1);

    buffer.put_u8(parameters.0);

    buffer.freeze()
}

fn parse_class_b_parameters(buffer: &mut Bytes) -> Result<(u8, u8), String> {
    if buffer.remaining() < 2 {
        return Err("Class coding of the facility corresponding to a parameter field length larger than remainder of packet".into());
    }

    Ok((buffer.get_u8(), buffer.get_u8()))
}

fn format_class_b_parameters(parameters: &(u8, u8)) -> Bytes {
    let mut buffer = BytesMut::with_capacity(2);

    buffer.put_u8(parameters.0);
    buffer.put_u8(parameters.1);

    buffer.freeze()
}

fn parse_class_c_parameters(buffer: &mut Bytes) -> Result<(u8, u8, u8), String> {
    if buffer.remaining() < 3 {
        return Err("Class coding of the facility corresponding to a parameter field length larger than remainder of packet".into());
    }

    Ok((buffer.get_u8(), buffer.get_u8(), buffer.get_u8()))
}

fn format_class_c_parameters(parameters: &(u8, u8, u8)) -> Bytes {
    let mut buffer = BytesMut::with_capacity(3);

    buffer.put_u8(parameters.0);
    buffer.put_u8(parameters.1);
    buffer.put_u8(parameters.2);

    buffer.freeze()
}

fn parse_class_d_parameters(buffer: &mut Bytes) -> Result<Bytes, String> {
    if buffer.remaining() < 1 {
        return Err("Class coding of the facility corresponding to a parameter field length larger than remainder of packet".into());
    }

    let length = buffer.get_u8() as usize;

    if buffer.remaining() < length {
        return Err("Class coding of the facility corresponding to a parameter field length larger than remainder of packet".into());
    }

    Ok(buffer.split_to(length))
}

fn format_class_d_parameters(parameters: &Bytes) -> Bytes {
    if parameters.len() > 255 {
        panic!("TODO");
    }

    let mut buffer = BytesMut::with_capacity(1 + parameters.len());

    buffer.put_u8(parameters.len() as u8);
    buffer.put_slice(parameters);

    buffer.freeze()
}

fn encode_packet_size(size: usize) -> Result<u8, String> {
    // TODO: This could be replaced with log2 when available...
    match size {
        16 => Ok(4),
        32 => Ok(5),
        64 => Ok(6),
        128 => Ok(7),
        256 => Ok(8),
        512 => Ok(9),
        1024 => Ok(10),
        2048 => Ok(11),
        4096 => Ok(12),
        _ => Err("Facility value not allowed or invalid".into()),
    }
}

fn decode_packet_size(value: u8) -> Result<usize, String> {
    match value {
        4 => Ok(16),
        5 => Ok(32),
        6 => Ok(64),
        7 => Ok(128),
        8 => Ok(256),
        9 => Ok(512),
        10 => Ok(1024),
        11 => Ok(2048),
        12 => Ok(4096),
        _ => Err("Facility value not allowed or invalid".into()),
    }
}
