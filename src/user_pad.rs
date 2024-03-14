use bytes::{BufMut, Bytes, BytesMut};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use either::Either::{self, Left, Right};
use libxotpad::x121::X121Addr;
use libxotpad::x25::{Svc, Vc, X25Params};
use libxotpad::x29::{X29Pad, X29PadSignal};
use libxotpad::x3::X3Params as _;
use libxotpad::xot::{self, XotLink, XotResolver};
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Stdout, Write};
use std::net::TcpListener;
use std::ops::{Add, Sub};
use std::str::{self, FromStr};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing_mutex::stdsync::{TracingMutex, TracingRwLock};

use crate::x28::{format_params, X28Command};
use crate::x3::X3Params;

pub fn call(addr: &X121Addr, x25_params: &X25Params, resolver: &XotResolver) -> io::Result<Svc> {
    let xot_link = xot::connect(addr, resolver)?;

    let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

    Svc::call(xot_link, 1, addr, &call_user_data, x25_params)
}

#[derive(Copy, Clone, PartialEq)]
enum PadLocalState {
    Command,
    Data,
}

enum PadInput {
    Call,
    Local(io::Result<Option<(u8, Instant)>>),
    Remote(io::Result<Option<Either<Bytes, X29PadSignal>>>),
    TimeOut,
}

pub fn run(
    x25_params: &X25Params,
    x3_profiles: &HashMap<&str, X3Params>,
    resolver: &XotResolver,
    x3_profile: &str,
    tcp_listener: Option<TcpListener>,
    svc: Option<Svc>,
) -> io::Result<()> {
    let (tx, rx) = channel();

    enable_raw_mode()?;

    // Start the local input thread.
    thread::Builder::new()
        .name("user_input".to_string())
        .spawn({
            let tx = tx.clone();

            move || {
                let reader = BufReader::new(io::stdin());

                for byte in reader.bytes() {
                    let should_continue = byte.is_ok();

                    let input = byte.map(|b| Some((b, Instant::now())));

                    if tx.send(PadInput::Local(input)).is_err() {
                        break;
                    }

                    if !should_continue {
                        break;
                    }
                }

                let _ = tx.send(PadInput::Local(Ok(None)));
            }
        });

    let mut local_state = PadLocalState::Command;
    let mut is_one_shot = false;

    let x3_params = Arc::new(TracingRwLock::new(
        x3_profiles
            .get(x3_profile)
            .expect("unknown X.3 profile")
            .clone(),
    ));

    let current_call = Arc::new(TracingMutex::new(Option::<(X29Pad, X25Params)>::None));

    if let Some(svc) = svc {
        let x25_params = svc.params();

        let x29_pad = X29Pad::new(svc, Arc::clone(&x3_params));

        current_call.lock().unwrap().replace((x29_pad, x25_params));

        local_state = PadLocalState::Data;
        is_one_shot = true;

        {
            let current_call = current_call.lock().unwrap();

            let (x29_pad, _) = current_call.as_ref().unwrap();

            spawn_remote_thread(x29_pad, tx.clone());
        }
    }

    if let Some(tcp_listener) = tcp_listener {
        let x25_params = x25_params.clone();
        let x3_params = Arc::clone(&x3_params);
        let current_call = Arc::clone(&current_call);
        let tx = tx.clone();

        thread::Builder::new()
            .name("user_pad_1".to_string())
            .spawn(move || {
                for tcp_stream in tcp_listener.incoming() {
                    if tcp_stream.is_err() {
                        continue;
                    }

                    let xot_link = XotLink::new(tcp_stream.unwrap());

                    let incoming_call = Svc::listen_timeout(
                        xot_link,
                        1, /* this "channel" needs to be removed! */
                        &x25_params,
                        Duration::from_secs(200),
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

                    // TODO: should we "reset" the X.3 parameters here, for a new
                    // call?

                    let x29_pad = X29Pad::new(svc, Arc::clone(&x3_params));

                    current_call.replace((x29_pad, x25_params));

                    if tx.send(PadInput::Call).is_err() {
                        break;
                    }
                }
            });
    }

    let mut command_buf = BytesMut::with_capacity(128);
    let mut data_buf = BytesMut::with_capacity(128);
    let mut last_data_time = None;

    if local_state == PadLocalState::Command {
        print!("*");
        io::stdout().flush()?;
    }

    let mut timeout = None;

    loop {
        let Some(input) = recv_input(&rx, timeout) else {
            break;
        };

        let mut current_call = current_call.lock().unwrap();

        match input {
            PadInput::Call => {
                println!("\r\nyou got a call!\r\n");

                local_state = PadLocalState::Data;

                let (x29_pad, _) = current_call.as_ref().unwrap();

                spawn_remote_thread(x29_pad, tx.clone());
            }
            PadInput::Remote(Ok(Some(Left(buf)))) => {
                write_recv_data(io::stdout(), &buf, &x3_params.read().unwrap())?;
            }
            PadInput::Remote(Ok(Some(Right(X29PadSignal::ClearInvitation)))) => {
                let (x29_pad, _) = current_call.take().unwrap();

                x29_pad.flush()?;

                x29_pad.into_svc().clear(0, 0)?;

                print!("\r\nCLR CONF\r\n");

                if is_one_shot {
                    break;
                }

                ensure_command(&mut local_state);
            }
            PadInput::Remote(Ok(None)) => {
                // XXX: we can tell whether we should show anything or not, based
                // on whether the call still "exists" otherwise we would have shown
                // the important info before...
                if current_call.is_some() {
                    let (x29_pad, _) = current_call.take().unwrap();

                    let (cause, diagnostic_code) = x29_pad.into_svc().cleared().unwrap_or((0, 0));

                    println!("CLR xxx C:{cause} D:{diagnostic_code}");
                }

                if is_one_shot {
                    break;
                }

                ensure_command(&mut local_state);
            }
            PadInput::Remote(Err(err)) => {
                println!("remote error: {err:?}");

                current_call.take();

                if is_one_shot {
                    break;
                }

                ensure_command(&mut local_state);
            }
            PadInput::Local(Ok(None) | Err(_)) => {
                if let Some((x29_pad, _)) = current_call.take() {
                    x29_pad.flush()?;
                    x29_pad.into_svc().clear(0, 0)?; // TODO
                }
            }
            PadInput::Local(Ok(Some((byte, input_time)))) => match (local_state, byte) {
                (PadLocalState::Command, /* CR */ 0x0d) => {
                    let buf = command_buf.split();

                    let line = str::from_utf8(&buf[..]).unwrap().trim();

                    print!("\r\n");

                    if !line.is_empty() {
                        let command = X28Command::from_str(line);

                        match command {
                            Ok(X28Command::Selection(ref addr)) => {
                                if current_call.is_some() {
                                    print!("ERROR... ENGAGED!\r\n");
                                } else {
                                    match call(addr, x25_params, resolver) {
                                        Ok(svc) => {
                                            let x25_params = svc.params();

                                            let x29_pad = X29Pad::new(svc, Arc::clone(&x3_params));

                                            current_call.replace((x29_pad, x25_params));

                                            local_state = PadLocalState::Data;

                                            let (x29_pad, _) = current_call.as_ref().unwrap();

                                            spawn_remote_thread(x29_pad, tx.clone());
                                        }
                                        Err(xxx) => print!("SOMETHING WENT WRONG: {xxx}\r\n"),
                                    }
                                }
                            }
                            Ok(X28Command::ClearRequest) => {
                                if let Some((x29_pad, _)) = current_call.take() {
                                    x29_pad.into_svc().clear(0, 0)?;
                                } else {
                                    print!("ERROR... NOT CONNECTED!\r\n");
                                }

                                if is_one_shot {
                                    break;
                                }
                            }
                            Ok(X28Command::Read(ref request)) => {
                                read_params(&x3_params.read().unwrap(), request);
                            }
                            Ok(X28Command::Set(ref request)) => {
                                set_params(&mut x3_params.write().unwrap(), request);
                            }
                            Ok(X28Command::SetRead(ref request)) => {
                                set_read_params(&mut x3_params.write().unwrap(), request);
                            }
                            Ok(X28Command::Status) => {
                                if current_call.is_some() {
                                    print!("ENGAGED\r\n");
                                } else {
                                    print!("FREE\r\n");
                                }
                            }
                            Ok(X28Command::ClearInvitation) => {
                                if let Some((x29_pad, _)) = current_call.as_ref() {
                                    x29_pad.send_clear_invitation()?;

                                    // TODO: we need to add a timeout...
                                } else {
                                    print!("ERROR... NOT CONNECTED!\r\n");
                                }
                            }
                            Ok(X28Command::Exit) => {
                                if let Some((x29_pad, _)) = current_call.take() {
                                    x29_pad.into_svc().clear(0, 0)?;
                                }

                                break;
                            }
                            Err(err) => {
                                print!("{err}\r\n");
                            }
                        }
                    }

                    if current_call.is_some() {
                        local_state = PadLocalState::Data;
                    } else {
                        print!("*");
                    }
                }
                (PadLocalState::Command, /* Ctrl+C */ 0x03) => {
                    if command_buf.is_empty() {
                        if let Some((x29_pad, _)) = current_call.take() {
                            x29_pad.into_svc().clear(0, 0)?;
                        }

                        break;
                    }

                    command_buf.clear();

                    print!("\r\n*");
                }
                (PadLocalState::Command, /* Ctrl+P */ 0x10) => {
                    if command_buf.is_empty() && current_call.is_some() {
                        let (x29_pad, x25_params) = current_call.as_ref().unwrap();

                        last_data_time = Some(input_time);

                        queue_and_send_data_if_ready(
                            x29_pad,
                            x25_params,
                            &x3_params.read().unwrap(),
                            &mut data_buf,
                            0x10,
                        )?;

                        print!("\r\n");
                        local_state = PadLocalState::Data;
                    }
                }
                (PadLocalState::Command, byte) => {
                    command_buf.put_u8(byte);

                    io::stdout().write_all(&[byte])?;
                }
                (PadLocalState::Data, /* Ctrl+P */ 0x10) => {
                    ensure_command(&mut local_state);
                }
                (PadLocalState::Data, byte) => 'input: {
                    let x3_params = x3_params.read().unwrap();

                    let editing: bool = x3_params.editing.into();

                    if editing {
                        if x3_params.char_delete.is_match(byte) {
                            handle_char_delete(&mut data_buf)?;
                            break 'input;
                        } else if x3_params.line_delete.is_match(byte) {
                            handle_line_delete(&mut data_buf)?;
                            break 'input;
                        } else if x3_params.line_display.is_match(byte) {
                            handle_line_display(&data_buf)?;
                            break 'input;
                        }
                    }

                    if x3_params.echo.into() {
                        io::stdout().write_all(&[byte])?;

                        // TODO: it is not obvious if this also depends on ECHO (param 2)...
                        // i.e should this be inside this IF block?
                        if x3_params.lf_insert.after_echo(byte) {
                            io::stdout().write_all(&[/* LF */ 0x0a])?;
                        }
                    }

                    let (x29_pad, x25_params) = current_call.as_ref().unwrap();

                    last_data_time = Some(input_time);

                    queue_and_send_data_if_ready(
                        x29_pad,
                        x25_params,
                        &x3_params,
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

        let x3_params = x3_params.read().unwrap();

        if let Some(delay) = x3_params.idle.into() {
            let editing: bool = x3_params.editing.into();

            // The idle timeout does not apply when editing....
            if !data_buf.is_empty() && !editing {
                let now = Instant::now();
                let deadline = last_data_time.unwrap().add(delay);

                if now >= deadline {
                    let (x29_pad, _) = current_call.as_ref().unwrap();

                    send_data(x29_pad, &mut data_buf)?;
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

fn queue_and_send_data_if_ready(
    x29_pad: &X29Pad,
    x25_params: &X25Params,
    x3_params: &X3Params,
    buf: &mut BytesMut,
    byte: u8,
) -> io::Result<()> {
    buf.put_u8(byte);

    if x3_params.lf_insert.after_send(byte) {
        buf.put_u8(/* LF */ 0x0a);
    }

    if !should_send_data(buf, byte, x25_params, x3_params) {
        return Ok(());
    }

    send_data(x29_pad, buf)
}

fn should_send_data(
    buf: &BytesMut,
    last_byte: u8,
    x25_params: &X25Params,
    x3_params: &X3Params,
) -> bool {
    if buf.is_empty() {
        return false;
    }

    let editing: bool = x3_params.editing.into();

    // NOTE: >= because of the possible insertion of a LF, after CR
    // this does not apply if editing... kinda makes sense I guess :)
    if buf.len() >= x25_params.send_packet_size && !editing {
        return true;
    }

    x3_params.forward.is_match(last_byte)
}

fn send_data(x29_pad: &X29Pad, buf: &mut BytesMut) -> io::Result<()> {
    assert!(!buf.is_empty());

    let user_data = buf.split();

    x29_pad.send_data(user_data.into())
}

fn ensure_command(state: &mut PadLocalState) {
    if *state == PadLocalState::Command {
        return;
    }

    print!("\r\n*");

    *state = PadLocalState::Command;
}

fn spawn_remote_thread(x29_pad: &X29Pad, channel: Sender<PadInput>) -> JoinHandle<()> {
    let x29_pad = x29_pad.clone();

    thread::Builder::new()
        .name("user_pad_2".to_string())
        .spawn(move || loop {
            let result = x29_pad.recv();

            let should_continue = matches!(result, Ok(Some(_)));

            if channel.send(PadInput::Remote(result)).is_err() {
                break;
            }

            if !should_continue {
                break;
            }
        })
        .unwrap()
}

fn read_params(params: &X3Params, request: &[u8]) {
    let response: Vec<(u8, Option<u8>)> = if request.is_empty() {
        params.all().iter().map(|&(p, v)| (p, Some(v))).collect()
    } else {
        request.iter().map(|&p| (p, params.get(p))).collect()
    };

    print!("PAR {}\r\n", format_params(&response));
}

fn set_params(params: &mut X3Params, request: &[(u8, u8)]) {
    for &(param, value) in request {
        // TODO: should we just ignore errors?
        let _ = params.set(param, value);
    }
}

fn set_read_params(params: &mut X3Params, request: &[(u8, u8)]) {
    let response: Vec<(u8, Option<u8>)> = request
        .iter()
        .map(|&(p, v)| {
            if params.set(p, v).is_err() {
                return (p, None);
            }

            (p, params.get(p))
        })
        .collect();

    print!("PAR {}\r\n", format_params(&response));
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

fn write_recv_data(mut stdout: Stdout, buf: &[u8], params: &X3Params) -> io::Result<()> {
    // TODO: this can be improved to avoid writing individual characters...
    for &byte in buf {
        stdout.write_all(&[byte])?;

        if params.lf_insert.after_recv(byte) {
            stdout.write_all(&[/* LF */ 0x0a])?;
        }
    }

    Ok(())
}

fn handle_char_delete(buf: &mut BytesMut) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    buf.truncate(buf.len() - 1);

    // TODO: Now do some terminal thing...
    io::stdout().write_all(&[0x08, 0x20, 0x08])
}

fn handle_line_delete(buf: &mut BytesMut) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    // TODO: it's not clear if this should clear the whole buffer, or just a "LINE"... I think
    // the Cisco X.28 command will just show XXX and then, er, it doesn't really work tho...
    buf.clear();

    io::stdout().write_all(b"XXX\r\n")
}

fn handle_line_display(buf: &BytesMut) -> io::Result<()> {
    io::stdout().write_all(b"\r\n")?;
    io::stdout().write_all(buf)
}
