use bytes::{BufMut, Bytes, BytesMut};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::env;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing_mutex::stdsync::TracingMutex;

use xotpad::x121::X121Addr;
use xotpad::x25::packet::X25CallRequest;
use xotpad::x25::{Svc, Vc, X25Modulo, X25Params};
use xotpad::xot::{self, XotLink};

struct Resolver {
    xot_gateway: String,
}

impl Resolver {
    pub fn new(xot_gateway: &str) -> Self {
        Resolver {
            xot_gateway: xot_gateway.to_owned(),
        }
    }

    pub fn lookup(&self, x25_addr: &X121Addr) -> Option<String> {
        Some(self.xot_gateway.clone())
    }
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
    User(u8),
}

enum PadCommand {
    Call(X121Addr),
    Clear,
    Status,
    Exit,
}

fn pad(
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
                    incoming_call.clear(1, 0); // Number busy
                    continue;
                }

                let svc = incoming_call.accept().unwrap();

                let x25_params = svc.params();

                xxx.replace((svc, x25_params));

                tx.send(PadInput::Call);
            }
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
            PadInput::Network(Ok(Some((buf, true)))) => match &buf[..] {
                b"\x01" => {
                    println!("X.29 command: invitation to clear...");

                    xxx.take().unwrap().0.clear(0, 0)?;

                    if is_one_shot {
                        break;
                    }

                    ensure_command(&mut user_state);
                }
                _ => println!("X.29 command: {buf:?}"),
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

                    let line = str::from_utf8(&buf[..]).unwrap();

                    print!("\r\n");

                    match parse_pad_command(line) {
                        Ok(Some(PadCommand::Call(addr))) => {
                            if xxx.is_some() {
                                print!("ERROR... ENGAGED!\r\n");
                            } else {
                                match call(addr, x25_params, resolver) {
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
                        Ok(Some(PadCommand::Clear)) => {
                            if xxx.is_some() {
                                xxx.take().unwrap().0.clear(0, 0)?;
                            } else {
                                print!("ERROR... NOT CONNECTED!\r\n");
                            }

                            if is_one_shot {
                                break;
                            }
                        }
                        Ok(Some(PadCommand::Status)) => {
                            if xxx.is_some() {
                                print!("ENGAGED\r\n");
                            } else {
                                print!("FREE\r\n");
                            }
                        }
                        Ok(Some(PadCommand::Exit)) => {
                            if xxx.is_some() {
                                xxx.take().unwrap().0.clear(0, 0)?;
                            }

                            break;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            print!("{err}\r\n");
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

fn call(addr: X121Addr, x25_params: &X25Params, resolver: &Resolver) -> Result<Svc, String> {
    let Some(xot_gateway) = resolver.lookup(&addr) else {
        return Err("no XOT gateway found".into());
    };

    let tcp_stream = match TcpStream::connect((xot_gateway, xot::TCP_PORT)) {
        Ok(stream) => stream,
        Err(err) => return Err("unable to connect to XOT gateway".into()),
    };

    let xot_link = XotLink::new(tcp_stream);

    let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

    let svc = match Svc::call(xot_link, 1, &addr, &call_user_data, &x25_params) {
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

fn parse_pad_command(line: &str) -> Result<Option<PadCommand>, String> {
    let line = line.trim();

    if line.is_empty() {
        return Ok(None);
    }

    let pair: Vec<&str> = line.splitn(2, ' ').collect();

    let command = pair[0].to_uppercase();
    let rest = if pair.len() > 1 { Some(pair[1]) } else { None };

    match &command[..] {
        "CALL" => {
            let addr = rest.unwrap_or("").trim();

            if addr.is_empty() {
                return Err("addr required, dude!".into());
            }

            match X121Addr::from_str(addr) {
                Ok(addr) => Ok(Some(PadCommand::Call(addr))),
                Err(_) => Err("invalid addr".into()),
            }
        }
        "CLR" | "CLEAR" => Ok(Some(PadCommand::Clear)),
        "STAT" | "STATUS" => Ok(Some(PadCommand::Status)),
        "EXIT" => Ok(Some(PadCommand::Exit)),
        _ => Err("unrecognized command".into()),
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let config = load_config();

    let resolver = Resolver::new(&config.xot_gateway);

    let listener = if args.len() == 1 {
        Some(TcpListener::bind(("0.0.0.0", xot::TCP_PORT))?)
    } else {
        None
    };

    let svc = if args.len() > 1 {
        let addr = X121Addr::from_str(&args[1]).expect("TODO");

        match call(addr, &config.x25_params, &resolver) {
            Ok(svc) => Some(svc),
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err));
            }
        }
    } else {
        None
    };

    pad(&config.x25_params, &resolver, listener, svc)?;

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
