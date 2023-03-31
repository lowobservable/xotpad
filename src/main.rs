use bytes::{BufMut, Bytes, BytesMut};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::env;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use xotpad::x121::X121Addr;
use xotpad::x25::packet::X25CallRequest;
use xotpad::x25::{Svc, Vc, X25Modulo, X25Params};
use xotpad::xot::{self, XotLink};

#[derive(Copy, Clone, PartialEq)]
enum PadUserState {
    Command,
    Data,
}

#[derive(Debug)]
enum PadInput {
    Network(io::Result<Option<(Bytes, bool)>>),
    User(u8),
}

enum PadCommand {
    Clear,
    Exit,
}

fn very_simple_pad(svc: Svc) -> io::Result<()> {
    let (tx, rx) = channel();

    enable_raw_mode();

    // The network input thread...
    thread::spawn({
        let svc = svc.clone();
        let tx = tx.clone();

        move || {
            loop {
                let result = svc.recv();

                if tx.send(PadInput::Network(result)).is_err() {
                    break;
                }
            }

            println!("done with network input thread");
        }
    });

    // The user input thread...
    thread::spawn(move || {
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
    });

    // The main loop...
    let mut user_state = PadUserState::Data; // <- for the "very simple PAD"

    let mut command_buf = BytesMut::with_capacity(128);
    let mut data_buf = BytesMut::with_capacity(128);

    for input in rx {
        match input {
            PadInput::Network(Ok(Some((buf, true)))) => match &buf[..] {
                b"\x01" => {
                    println!("X.29 command: invitation to clear...");

                    svc.clear(0, 0)?;
                    break;
                }
                _ => println!("X.29 command: {buf:?}"),
            },
            PadInput::Network(Ok(Some((buf, false)))) => {
                let mut out = io::stdout().lock();

                out.write_all(&buf)?;
                out.flush()?;
            }
            PadInput::Network(Ok(None)) => {
                let (cause, diagnostic_code) = svc.cleared().unwrap_or((0, 0));

                println!("CLR xxx C:{cause} D:{diagnostic_code}");
                break;
            }
            PadInput::Network(Err(err)) => {
                println!("network error: {err:?}");
                break;
            }
            PadInput::User(byte) => match (user_state, byte) {
                (PadUserState::Command, /* Ctrl+C */ 0x03) => {
                    if command_buf.is_empty() {
                        println!("\rGot a CTRL+C with empty buffer...\r\n");
                        svc.clear(0, 0)?;
                        break;
                    }

                    command_buf.clear();
                }
                (PadUserState::Command, /* Enter */ 0x0d) => {
                    let buf = command_buf.split();

                    let line = str::from_utf8(&buf[..]).unwrap();

                    print!("\r\n");

                    match parse_pad_command(line) {
                        Some(PadCommand::Clear | PadCommand::Exit) => {
                            svc.clear(0, 0)?;
                            break;
                        }
                        None => {
                            print!("{line} is an unrecognized command!\r\n");
                        }
                    }

                    user_state = PadUserState::Data;
                }
                (PadUserState::Command, byte) => {
                    command_buf.put_u8(byte);

                    io::stdout().write(&[byte]);
                }
                (PadUserState::Data, /* Ctrl+P */ 0x10) => {
                    print!("\r\n*");

                    user_state = PadUserState::Command;
                }
                (PadUserState::Data, byte) => {
                    data_buf.put_u8(byte);

                    if is_data_ready_to_send(&data_buf) {
                        let buf = data_buf.split();

                        svc.send(buf.into(), false)?;
                    }
                }
            },
        }

        io::stdout().flush();
    }

    disable_raw_mode();

    io::stdout().flush();

    Ok(())
}

fn is_data_ready_to_send(buf: &BytesMut) -> bool {
    true
}

fn parse_pad_command(line: &str) -> Option<PadCommand> {
    match line {
        "clear" => Some(PadCommand::Clear),
        "exit" => Some(PadCommand::Exit),
        _ => None,
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let config = load_config();

    if args[1] == "call" {
        let tcp_stream = TcpStream::connect((config.xot_gateway, xot::TCP_PORT))?;

        let xot_link = XotLink::new(tcp_stream);

        let addr = X121Addr::from_str(&args[2]).unwrap();
        let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

        let svc = Svc::call(xot_link, 1, &addr, &call_user_data, &config.x25_params)?;

        println!("CONNECTED!");

        very_simple_pad(svc)?;
    } else if args[1] == "listen" {
        let tcp_listener = TcpListener::bind(("0.0.0.0", xot::TCP_PORT))?;

        for tcp_stream in tcp_listener.incoming() {
            let xot_link = XotLink::new(tcp_stream?);

            let incoming_call = Svc::listen(
                xot_link,
                1, /* this "channel" needs to be removed! */
                &config.x25_params,
            )?;

            if let Some((cause, diagnostic_code)) = should_accept_call(incoming_call.request()) {
                incoming_call.clear(cause, diagnostic_code)?;
                continue;
            }

            let svc = incoming_call.accept()?;

            println!("ACCEPTED!");

            very_simple_pad(svc)?;
        }
    }

    Ok(())
}

fn should_accept_call(call_request: &X25CallRequest) -> Option<(u8, u8)> {
    dbg!(call_request);

    //Some((1, 0))
    None
}

struct Config {
    x25_params: X25Params,
    xot_gateway: String,
}

fn load_config() -> Config {
    let x25_params = X25Params {
        addr: X121Addr::from_str("73720201").unwrap(),
        modulo: X25Modulo::Normal,
        send_packet_size: 128,
        send_window_size: 2,
        recv_packet_size: 128,
        recv_window_size: 2,
        t21: Duration::from_secs(5),
        t22: Duration::from_secs(5),
        t23: Duration::from_secs(5),
    };

    let xot_gateway = env::var("XOT_GATEWAY").unwrap_or("localhost".into());

    Config {
        x25_params,
        xot_gateway,
    }
}
