use bytes::{BufMut, Bytes, BytesMut};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing_mutex::stdsync::TracingMutex;

use crate::resolver::Resolver;
use crate::x121::X121Addr;
use crate::x25::{Svc, Vc, X25Params};
use crate::xot::{self, XotLink};

use self::x28::X28Command;
use self::x29::X29Command;

pub mod x28;
pub mod x29;

#[derive(Copy, Clone, PartialEq)]
enum PadUserState {
    Command,
    Data,
}

#[derive(Debug)]
enum PadInput {
    Call,
    Network(io::Result<Option<(Bytes, bool)>>),
    User(u8),
}

pub fn run(
    x25_params: &X25Params,
    resolver: &Resolver,
    tcp_listener: Option<TcpListener>,
    svc: Option<Svc>,
) -> io::Result<()> {
    let (tx, rx) = channel();

    enable_raw_mode()?;

    // Start the user input thread.
    thread::spawn({
        let tx = tx.clone();

        move || {
            let mut reader = BufReader::new(io::stdin());

            loop {
                let mut buf = [0; 1];

                if reader.read_exact(&mut buf).is_err() {
                    break;
                }

                if tx.send(PadInput::User(buf[0])).is_err() {
                    break;
                }
            }

            println!("done with user input thread");
        }
    });

    let xxx = Arc::new(TracingMutex::new(Option::<(Svc, X25Params)>::None));

    let mut user_state = PadUserState::Command;
    let mut is_one_shot = false;

    if let Some(svc) = svc {
        let zzz = svc.clone();
        let x25_params = svc.params();

        xxx.lock().unwrap().replace((svc, x25_params));

        user_state = PadUserState::Data;
        is_one_shot = true;

        spawn_network_thread(zzz, tx.clone());
    }

    if let Some(tcp_listener) = tcp_listener {
        let x25_params = x25_params.clone();
        let xxx = Arc::clone(&xxx);
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

                let mut xxx = xxx.lock().unwrap();

                if xxx.is_some() {
                    let _ = incoming_call.clear(1, 0); // Number busy
                    continue;
                }

                let svc = incoming_call.accept().unwrap();

                let x25_params = svc.params();

                xxx.replace((svc, x25_params));

                if tx.send(PadInput::Call).is_err() {
                    break;
                }
            }

            println!("done with listener thread");
        });
    }

    let mut command_buf = BytesMut::with_capacity(128);
    let mut data_buf = BytesMut::with_capacity(128);

    if user_state == PadUserState::Command {
        print!("*");
        io::stdout().flush()?;
    }

    for input in rx {
        let mut xxx = xxx.lock().unwrap();

        match input {
            PadInput::Call => {
                println!("\r\nyou got a call!\r\n");

                user_state = PadUserState::Data;

                spawn_network_thread(xxx.as_ref().unwrap().0.clone(), tx.clone());
            }
            PadInput::Network(Ok(Some((buf, true)))) => match X29Command::decode(buf) {
                Ok(X29Command::ClearInvitation) => {
                    println!("X.29 command: invitation to clear...");

                    xxx.take().unwrap().0.clear(0, 0)?;

                    if is_one_shot {
                        break;
                    }

                    ensure_command(&mut user_state);
                }
                Err(err) => println!("unrecognized or invalid X.29 command"),
            },
            PadInput::Network(Ok(Some((buf, false)))) => {
                let mut out = io::stdout().lock();

                out.write_all(&buf)?;
                out.flush()?;
            }
            PadInput::Network(Ok(None)) => {
                // XXX: we can tell whether we should show anything or not, based
                // on whether the SVC still "exists" otherwise we would have shown
                // the important info before...
                if xxx.is_some() {
                    let (cause, diagnostic_code) =
                        xxx.take().unwrap().0.cleared().unwrap_or((0, 0));

                    println!("CLR xxx C:{cause} D:{diagnostic_code}");
                }

                if is_one_shot {
                    break;
                }

                ensure_command(&mut user_state);
            }
            PadInput::Network(Err(err)) => {
                println!("network error: {err:?}");

                xxx.take();

                if is_one_shot {
                    break;
                }

                ensure_command(&mut user_state);
            }
            PadInput::User(byte) => match (user_state, byte) {
                (PadUserState::Command, /* Enter */ 0x0d) => {
                    let buf = command_buf.split();

                    let line = str::from_utf8(&buf[..]).unwrap().trim();

                    print!("\r\n");

                    if !line.is_empty() {
                        match X28Command::parse(line) {
                            Ok(X28Command::Call(addr)) => {
                                if xxx.is_some() {
                                    print!("ERROR... ENGAGED!\r\n");
                                } else {
                                    match call(addr, resolver, x25_params) {
                                        Ok(svc) => {
                                            let zzz = svc.clone();
                                            let x25_params = svc.params();

                                            xxx.replace((svc, x25_params));

                                            user_state = PadUserState::Data;

                                            spawn_network_thread(zzz, tx.clone());
                                        }
                                        Err(xxx) => print!("SOMETHING WENT WRONG: {xxx}\r\n"),
                                    }
                                }
                            }
                            Ok(X28Command::Clear) => {
                                if xxx.is_some() {
                                    xxx.take().unwrap().0.clear(0, 0)?;
                                } else {
                                    print!("ERROR... NOT CONNECTED!\r\n");
                                }

                                if is_one_shot {
                                    break;
                                }
                            }
                            Ok(X28Command::Status) => {
                                if xxx.is_some() {
                                    print!("ENGAGED\r\n");
                                } else {
                                    print!("FREE\r\n");
                                }
                            }
                            Ok(X28Command::Exit) => {
                                if xxx.is_some() {
                                    xxx.take().unwrap().0.clear(0, 0)?;
                                }

                                break;
                            }
                            Err(err) => {
                                print!("{err}\r\n");
                            }
                        }
                    }

                    if xxx.is_some() {
                        user_state = PadUserState::Data;
                    } else {
                        print!("*");
                        io::stdout().flush()?;
                    }
                }
                (PadUserState::Command, /* Ctrl+C */ 0x03) => {
                    if command_buf.is_empty() {
                        if xxx.is_some() {
                            xxx.take().unwrap().0.clear(0, 0)?;
                        }

                        break;
                    }

                    command_buf.clear();
                }
                (PadUserState::Command, /* Ctrl+P */ 0x10) => {
                    if command_buf.is_empty() && xxx.is_some() {
                        let (svc, x25_params) = xxx.as_ref().unwrap();

                        queue_and_send_data_if_ready(svc, x25_params, &mut data_buf, 0x10)?;
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
                    let (svc, x25_params) = xxx.as_ref().unwrap();

                    queue_and_send_data_if_ready(svc, x25_params, &mut data_buf, byte)?;
                }
            },
        }

        io::stdout().flush()?;
    }

    io::stdout().flush()?;

    disable_raw_mode()?;

    Ok(())
}

fn queue_and_send_data_if_ready(
    svc: &Svc,
    x25_params: &X25Params,
    buf: &mut BytesMut,
    byte: u8,
) -> io::Result<()> {
    buf.put_u8(byte);

    if is_data_ready_to_send(buf, x25_params) {
        let user_data = buf.split();

        return svc.send(user_data.into(), false);
    }

    Ok(())
}

// TODO: add x3_params to determine when to send!
fn is_data_ready_to_send(buf: &BytesMut, x25_params: &X25Params) -> bool {
    if buf.is_empty() {
        return false;
    }

    if buf.len() == x25_params.send_packet_size {
        return true;
    }

    let last_byte = buf.last().unwrap();

    // ...

    true
}

fn ensure_command(state: &mut PadUserState) {
    if *state == PadUserState::Command {
        return;
    }

    print!("\r\n*");

    *state = PadUserState::Command;
}

pub fn call(addr: X121Addr, resolver: &Resolver, x25_params: &X25Params) -> Result<Svc, String> {
    let Some(xot_gateway) = resolver.lookup(&addr) else {
        return Err("no XOT gateway found".into());
    };

    let tcp_stream = match TcpStream::connect((xot_gateway, xot::TCP_PORT)) {
        Ok(stream) => stream,
        Err(err) => return Err("unable to connect to XOT gateway".into()),
    };

    let xot_link = XotLink::new(tcp_stream);

    let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

    let svc = match Svc::call(xot_link, 1, &addr, &call_user_data, x25_params) {
        Ok(svc) => svc,
        Err(err) => return Err("something went wrong with the call".into()),
    };

    Ok(svc)
}

fn spawn_network_thread(svc: Svc, channel: Sender<PadInput>) -> JoinHandle<()> {
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
