use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug)]
pub enum X25Facility {
    PacketSize { from_called: u8, from_calling: u8 },
    WindowSize { from_called: u8, from_calling: u8 },
    ClassA(u8, (u8,)),
    ClassB(u8, (u8, u8)),
    ClassC(u8, (u8, u8, u8)),
    ClassD(u8, Bytes),
}

pub fn parse_facilities(mut buffer: Bytes) -> Result<Vec<X25Facility>, String> {
    let mut facilities = Vec::new();

    while !buffer.is_empty() {
        let code = buffer.get_u8();
        let class = (code & 0xc0) >> 6;

        if code == 0x42 {
            let (from_called, from_calling) = parse_class_b_parameters(&mut buffer)?;

            facilities.push(X25Facility::PacketSize {
                from_called,
                from_calling,
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

pub fn format_facilities(facilities: &Vec<X25Facility>) -> Bytes {
    let mut buffer = BytesMut::new();

    for facility in facilities {
        match facility {
            X25Facility::PacketSize {
                from_called,
                from_calling,
            } => {
                buffer.put_u8(0x42);
                buffer.put(format_class_b_parameters(&(*from_called, *from_calling)));
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

    buffer.freeze()
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
