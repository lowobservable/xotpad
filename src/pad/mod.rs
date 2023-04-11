use bytes::{BufMut, Bytes, BytesMut};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::io::{self, BufReader, Read, Write};
use std::net::TcpListener;
use std::ops::{Add, Sub};
use std::str::{self, FromStr};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing_mutex::stdsync::TracingMutex;

use crate::x121::X121Addr;
use crate::x25::{Svc, Vc, X25Params};
use crate::xot::{self, XotLink, XotResolver};

use self::x28::X28Command;
use self::x29::X29PadMessage;

mod x28;
mod x29;
mod x3;

pub use self::x3::X3Params;

pub fn call(addr: &X121Addr, x25_params: &X25Params, resolver: &XotResolver) -> io::Result<Svc> {
    let xot_link = xot::connect(addr, resolver)?;

    let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

    Svc::call(xot_link, 1, addr, &call_user_data, x25_params)
}

#[derive(Copy, Clone, PartialEq)]
enum PadUserState {
    Command,
    Data,
}

#[derive(Debug)]
enum PadInput {
    Call,
    Network(io::Result<Option<(Bytes, bool)>>),
    User(io::Result<Option<(u8, Instant)>>),
    TimeOut,
}

pub fn run(
    x25_params: &X25Params,
    resolver: &XotResolver,
    tcp_listener: Option<TcpListener>,
    svc: Option<Svc>,
    x3_params: &X3Params,
) -> io::Result<()> {
    let (tx, rx) = channel();

    enable_raw_mode()?;

    // Start the user input thread.
    thread::spawn({
        let tx = tx.clone();

        move || {
            let reader = BufReader::new(io::stdin());

            for byte in reader.bytes() {
                let should_continue = byte.is_ok();

                let input = byte.map(|b| Some((b, Instant::now())));

                if tx.send(PadInput::User(input)).is_err() {
                    break;
                }

                if !should_continue {
                    break;
                }
            }

            let _ = tx.send(PadInput::User(Ok(None)));

            println!("done with user input thread");
        }
    });

    let current_call = Arc::new(TracingMutex::new(Option::<(Svc, X25Params)>::None));

    let mut user_state = PadUserState::Command;
    let mut is_one_shot = false;

    if let Some(svc) = svc {
        let x25_params = svc.params();

        current_call.lock().unwrap().replace((svc, x25_params));

        user_state = PadUserState::Data;
        is_one_shot = true;

        {
            let current_call = current_call.lock().unwrap();

            let (svc, _) = current_call.as_ref().unwrap();

            spawn_network_thread(svc, tx.clone());
        }
    }

    if let Some(tcp_listener) = tcp_listener {
        let x25_params = x25_params.clone();
        let current_call = Arc::clone(&current_call);
        let tx = tx.clone();

        thread::spawn(move || {
            for tcp_stream in tcp_listener.incoming() {
                if tcp_stream.is_err() {
                    continue;
                }

                let xot_link = XotLink::new(tcp_stream.unwrap());

                let incoming_call = Svc::listen(
                    xot_link,
                    1, /* this "channel" needs to be removed! */
                    &x25_params,
                );

                if incoming_call.is_err() {
                    continue;
                }

                let incoming_call = incoming_call.unwrap();

                let mut current_call = current_call.lock().unwrap();

                if current_call.is_some() {
                    let _ = incoming_call.clear(1, 0); // Number busy
                    continue;
                }

                let svc = incoming_call.accept().unwrap();

                let x25_params = svc.params();

                current_call.replace((svc, x25_params));

                if tx.send(PadInput::Call).is_err() {
                    break;
                }
            }

            println!("done with listener thread");
        });
    }

    let mut command_buf = BytesMut::with_capacity(128);
    let mut data_buf = BytesMut::with_capacity(128);
    let mut last_data_time = None;

    let user_x3_params = x3_params.clone();
    let mut current_x3_params = x3_params.clone();

    if user_state == PadUserState::Command {
        print!("*");
        io::stdout().flush()?;
    }

    let mut timeout = None;

    loop {
        let input = match recv_input(&rx, timeout) {
            Some(input) => input,
            None => break,
        };

        let mut current_call = current_call.lock().unwrap();

        match input {
            PadInput::Call => {
                println!("\r\nyou got a call!\r\n");

                user_state = PadUserState::Data;

                let (svc, _) = current_call.as_ref().unwrap();

                spawn_network_thread(svc, tx.clone());
            }
            PadInput::Network(Ok(Some((buf, true)))) => {
                let message = X29PadMessage::decode(buf);

                match message {
                    Ok(X29PadMessage::Set(ref params)) => {
                        let (svc, _) = current_call.as_ref().unwrap();

                        x29_set(svc, &mut current_x3_params, params, &user_x3_params)?;
                    }
                    Ok(X29PadMessage::Read(ref params)) => {
                        let (svc, _) = current_call.as_ref().unwrap();

                        x29_read(svc, &current_x3_params, params)?;
                    }
                    Ok(X29PadMessage::SetRead(ref params)) => {
                        let (svc, _) = current_call.as_ref().unwrap();

                        x29_set_read(svc, &mut current_x3_params, params, &user_x3_params)?;
                    }
                    Ok(X29PadMessage::Indicate(_)) => todo!("XXX"),
                    Ok(X29PadMessage::ClearInvitation) => {
                        // TODO: we should attempt to send all that we have before
                        // clearing...

                        current_call.take().unwrap().0.clear(0, 0)?;

                        if is_one_shot {
                            break;
                        }

                        ensure_command(&mut user_state);
                    }
                    Err(err) => println!("unrecognized or invalid X.29 PAD message"),
                }
            }
            PadInput::Network(Ok(Some((buf, false)))) => {
                let mut out = io::stdout().lock();

                out.write_all(&buf)?;
                out.flush()?;
            }
            PadInput::Network(Ok(None)) => {
                // XXX: we can tell whether we should show anything or not, based
                // on whether the SVC still "exists" otherwise we would have shown
                // the important info before...
                if current_call.is_some() {
                    let (svc, _) = current_call.take().unwrap();

                    let (cause, diagnostic_code) = svc.cleared().unwrap_or((0, 0));

                    println!("CLR xxx C:{cause} D:{diagnostic_code}");
                }

                if is_one_shot {
                    break;
                }

                ensure_command(&mut user_state);
            }
            PadInput::Network(Err(err)) => {
                println!("network error: {err:?}");

                current_call.take();

                if is_one_shot {
                    break;
                }

                ensure_command(&mut user_state);
            }
            PadInput::User(Ok(None) | Err(_)) => {
                println!("here");

                if current_call.is_none() {
                    break;
                }

                println!("not really sure what to do here yet...");
                println!("we probably need to wait for all data to be sent...");
                println!("then shut down cleanly.");
            }
            PadInput::User(Ok(Some((byte, input_time)))) => match (user_state, byte) {
                (PadUserState::Command, /* Enter */ 0x0d) => {
                    let buf = command_buf.split();

                    let line = str::from_utf8(&buf[..]).unwrap().trim();

                    print!("\r\n");

                    if !line.is_empty() {
                        let command = X28Command::from_str(line);

                        match command {
                            Ok(X28Command::Call(ref addr)) => {
                                if current_call.is_some() {
                                    print!("ERROR... ENGAGED!\r\n");
                                } else {
                                    match call(addr, x25_params, resolver) {
                                        Ok(svc) => {
                                            let x25_params = svc.params();

                                            current_call.replace((svc, x25_params));

                                            user_state = PadUserState::Data;

                                            let (svc, _) = current_call.as_ref().unwrap();

                                            spawn_network_thread(svc, tx.clone());
                                        }
                                        Err(xxx) => print!("SOMETHING WENT WRONG: {xxx}\r\n"),
                                    }
                                }
                            }
                            Ok(X28Command::Clear) => {
                                if current_call.is_some() {
                                    current_call.take().unwrap().0.clear(0, 0)?;
                                } else {
                                    print!("ERROR... NOT CONNECTED!\r\n");
                                }

                                if is_one_shot {
                                    break;
                                }
                            }
                            Ok(X28Command::Status) => {
                                if current_call.is_some() {
                                    print!("ENGAGED\r\n");
                                } else {
                                    print!("FREE\r\n");
                                }
                            }
                            Ok(X28Command::Exit) => {
                                if current_call.is_some() {
                                    current_call.take().unwrap().0.clear(0, 0)?;
                                }

                                break;
                            }
                            Err(err) => {
                                print!("{err}\r\n");
                            }
                        }
                    }

                    if current_call.is_some() {
                        user_state = PadUserState::Data;
                    } else {
                        print!("*");
                        io::stdout().flush()?;
                    }
                }
                (PadUserState::Command, /* Ctrl+C */ 0x03) => {
                    if command_buf.is_empty() {
                        if current_call.is_some() {
                            current_call.take().unwrap().0.clear(0, 0)?;
                        }

                        break;
                    }

                    command_buf.clear();
                }
                (PadUserState::Command, /* Ctrl+P */ 0x10) => {
                    if command_buf.is_empty() && current_call.is_some() {
                        let (svc, x25_params) = current_call.as_ref().unwrap();

                        last_data_time = Some(input_time);

                        queue_and_send_data_if_ready(
                            svc,
                            x25_params,
                            &current_x3_params,
                            &mut data_buf,
                            0x10,
                        )?;

                        print!("\r\n");
                        user_state = PadUserState::Data;
                    }
                }
                (PadUserState::Command, byte) => {
                    command_buf.put_u8(byte);

                    io::stdout().write_all(&[byte])?;
                }
                (PadUserState::Data, /* Ctrl+P */ 0x10) => {
                    ensure_command(&mut user_state);
                }
                (PadUserState::Data, byte) => {
                    if current_x3_params.echo {
                        io::stdout().write_all(&[byte])?;
                    }

                    let (svc, x25_params) = current_call.as_ref().unwrap();

                    last_data_time = Some(input_time);

                    queue_and_send_data_if_ready(
                        svc,
                        x25_params,
                        &current_x3_params,
                        &mut data_buf,
                        byte,
                    )?;
                }
            },
            PadInput::TimeOut => {
                // Idle input timeout will be handled below.
            }
        }

        // Send data if the idle timeout has expired, otherwise set the input
        // timeout.
        timeout = None;

        if let Some(delay) = get_idle_delay(&current_x3_params) {
            if !data_buf.is_empty() {
                let now = Instant::now();
                let deadline = last_data_time.unwrap().add(delay);

                if now >= deadline {
                    let (svc, _) = current_call.as_ref().unwrap();

                    send_data(svc, &mut data_buf)?;
                } else {
                    timeout = Some(deadline.sub(now));
                }
            }
        }

        if data_buf.is_empty() {
            last_data_time = None;
        }

        io::stdout().flush()?;
    }

    io::stdout().flush()?;

    disable_raw_mode()?;

    Ok(())
}

fn get_idle_delay(x3_params: &X3Params) -> Option<Duration> {
    if x3_params.idle == 0 {
        return None;
    }

    let delay = Duration::from_millis(u64::from(x3_params.idle) * 50);

    Some(delay)
}

fn queue_and_send_data_if_ready(
    svc: &Svc,
    x25_params: &X25Params,
    x3_params: &X3Params,
    buf: &mut BytesMut,
    byte: u8,
) -> io::Result<()> {
    buf.put_u8(byte);

    if !should_send_data(buf, x25_params, x3_params) {
        return Ok(());
    }

    send_data(svc, buf)
}

fn send_data(svc: &Svc, buf: &mut BytesMut) -> io::Result<()> {
    assert!(!buf.is_empty());

    let user_data = buf.split();

    svc.send(user_data.into(), false)
}

fn should_send_data(buf: &BytesMut, x25_params: &X25Params, x3_params: &X3Params) -> bool {
    if buf.is_empty() {
        return false;
    }

    if buf.len() == x25_params.send_packet_size {
        return true;
    }

    let forward = x3_params.forward;
    let last_byte = *buf.last().unwrap();

    if forward & 1 == 1 && last_byte.is_ascii_alphanumeric() {
        return true;
    }

    // CR (0x0d)
    if forward & 2 == 2 && last_byte == 0x0d {
        return true;
    }

    // ESC (0x1b) BEL (0x07) ENQ (0x05) ACK (0x06)
    if forward & 4 == 4 && [0x1b, 0x07, 0x05, 0x06].contains(&last_byte) {
        return true;
    }

    // DEL (0x7f), CAN (0x18), DC2 (0x12)
    if forward & 8 == 8 && [0x7f, 0x18, 0x12].contains(&last_byte) {
        return true;
    }

    // EOT (0x04), ETX (0x03)
    if forward & 16 == 16 && [0x04, 0x03].contains(&last_byte) {
        return true;
    }

    // HT (0x09), LF (0x0a), VT (0x0b), FF (0x0c)
    if forward & 32 == 32 && [0x09, 0x0a, 0x0b, 0x0c].contains(&last_byte) {
        return true;
    }

    // Everything else from IA5 columns 0 and 1...
    if forward & 64 == 64
        && [
            0x00, 0x01, 0x02, 0x08, 0x0e, 0x0f, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19,
            0x1a, 0x1c, 0x1d, 0x1e, 0x1f,
        ]
        .contains(&last_byte)
    {
        return true;
    }

    false
}

fn ensure_command(state: &mut PadUserState) {
    if *state == PadUserState::Command {
        return;
    }

    print!("\r\n*");

    *state = PadUserState::Command;
}

fn spawn_network_thread(svc: &Svc, channel: Sender<PadInput>) -> JoinHandle<()> {
    let svc = svc.clone();

    thread::spawn(move || {
        loop {
            let result = svc.recv();

            let should_continue = matches!(result, Ok(Some(_)));

            if channel.send(PadInput::Network(result)).is_err() {
                break;
            }

            if !should_continue {
                break;
            }
        }

        println!("done with network input thread");
    })
}

fn x29_read(svc: &Svc, current_params: &X3Params, requested: &[u8]) -> io::Result<()> {
    let requested = if requested.is_empty() {
        &x3::PARAMS
    } else {
        requested
    };

    let params = requested
        .iter()
        .map(|&p| (p, current_params.get(p).unwrap_or(0x81)))
        .collect();

    let message = X29PadMessage::Indicate(params);

    let mut buf = BytesMut::new();

    message.encode(&mut buf);

    svc.send(buf.into(), true)
}

fn x29_set(
    svc: &Svc,
    current_params: &mut X3Params,
    requested: &[(u8, u8)],
    user_params: &X3Params,
) -> io::Result<()> {
    if requested.is_empty() {
        *current_params = user_params.clone();
        return Ok(());
    }

    let errors: Vec<(u8, u8)> = requested
        .iter()
        .map(|&p| (p.0, current_params.set(p.0, p.1)))
        .filter_map(|(p, r)| {
            // TODO: improve this, so we can return a correct error code!
            if r.is_err() {
                Some((p, 0x80))
            } else {
                None
            }
        })
        .collect();

    if errors.is_empty() {
        return Ok(());
    }

    let message = X29PadMessage::Indicate(errors);

    let mut buf = BytesMut::new();

    message.encode(&mut buf);

    svc.send(buf.into(), true)
}

fn x29_set_read(
    svc: &Svc,
    current_params: &mut X3Params,
    requested: &[(u8, u8)],
    user_params: &X3Params,
) -> io::Result<()> {
    if requested.is_empty() {
        *current_params = user_params.clone();

        let requested: Vec<u8> = requested.iter().map(|&p| p.0).collect();

        return x29_read(svc, current_params, &requested);
    }

    let params: Vec<(u8, u8)> = requested
        .iter()
        .map(|&p| {
            // TODO: improve this, so we can return a correct error code!
            if current_params.set(p.0, p.1).is_err() {
                return (p.0, 0x80);
            }

            (p.0, current_params.get(p.0).unwrap_or(0x81))
        })
        .collect();

    let message = X29PadMessage::Indicate(params);

    let mut buf = BytesMut::new();

    message.encode(&mut buf);

    svc.send(buf.into(), true)
}

fn recv_input(channel: &Receiver<PadInput>, timeout: Option<Duration>) -> Option<PadInput> {
    if let Some(timeout) = timeout {
        return match channel.recv_timeout(timeout) {
            Ok(input) => Some(input),
            Err(RecvTimeoutError::Timeout) => Some(PadInput::TimeOut),
            Err(RecvTimeoutError::Disconnected) => None,
        };
    }

    match channel.recv() {
        Ok(input) => Some(input),
        Err(_) => None,
    }
}

#[cfg(fuzzing)]
pub mod fuzzing {
    pub use super::x29::X29PadMessage;
}
