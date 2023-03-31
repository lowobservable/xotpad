use bytes::{BufMut, Bytes, BytesMut};
use std::env;
use std::io::{self, BufRead, Write};
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

#[derive(Debug)]
enum Input {
    Network(io::Result<Option<(Bytes, bool)>>),
    User(Bytes),
}

fn very_simple_pad(svc: Svc) -> io::Result<()> {
    let (tx, rx) = channel();

    // The network input thread...
    thread::spawn({
        let svc = svc.clone();
        let tx = tx.clone();

        move || {
            loop {
                let result = svc.recv();

                if tx.send(Input::Network(result)).is_err() {
                    break;
                }
            }

            println!("done with network input thread");
        }
    });

    // The user input thread...
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if line.is_err() {
                break;
            }

            let line = line.unwrap();

            // Reheat in the microwave...
            let mut buf = BytesMut::with_capacity(line.len() + 1);

            buf.put(line.as_bytes());
            buf.put_u8(b'\r');

            if tx.send(Input::User(buf.into())).is_err() {
                break;
            }
        }

        println!("done with user input thread");
    });

    // The main loop...
    for input in rx {
        match input {
            Input::Network(Ok(Some((buf, true)))) => match &buf[..] {
                b"\x01" => {
                    println!("X.29 command: invitation to clear...");

                    svc.clear(0, 0)?;
                    break;
                }
                _ => println!("X.29 command: {buf:?}"),
            },
            Input::Network(Ok(Some((buf, false)))) => {
                let mut out = io::stdout().lock();

                out.write_all(&buf)?;
                out.flush()?;
            }
            Input::Network(Ok(None)) => {
                let (cause, diagnostic_code) = svc.cleared().unwrap_or((0, 0));

                println!("CLR xxx C:{cause} D:{diagnostic_code}");
                break;
            }
            Input::Network(Err(err)) => {
                println!("network error: {err:?}");
                break;
            }
            Input::User(buf) => {
                if buf.starts_with(b"!") && buf.ends_with(b"\r") {
                    let end = buf.len() - 1;
                    let cmd = str::from_utf8(&buf[1..end]).unwrap();

                    match cmd {
                        "clear" => {
                            svc.clear(0, 0)?;
                            break;
                        }
                        _ => println!("unrecognized command: {cmd}"),
                    }
                } else {
                    svc.send(buf, false)?;
                }
            }
        }
    }

    Ok(())
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
