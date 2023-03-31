use bytes::Bytes;
use std::env;
use std::io::{self, BufRead};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use xotpad::x121::X121Addr;
use xotpad::x25::packet::X25CallRequest;
use xotpad::x25::{Svc, Vc, X25Modulo, X25Params};
use xotpad::xot::{self, XotLink};

fn very_simple_pad(svc: Svc) {
    thread::spawn({
        let svc = svc.clone();

        move || loop {
            let (user_data, qualifier) = match svc.recv() {
                Ok(Some(data)) => data,
                Ok(None) => {
                    if let Some((cause, diagnostic_code)) = svc.cleared() {
                        println!("CLR C:{cause} D:{diagnostic_code}");
                    }

                    break;
                }
                Err(err) => {
                    dbg!(err);
                    break;
                }
            };

            dbg!(user_data, qualifier);
        }
    });

    for line in io::stdin().lock().lines() {
        let line = line.unwrap();

        if line == "!clear" {
            if let Err(err) = svc.clear(0, 0) {
                dbg!(err);
            }

            break;
        }

        if let Err(err) = svc.send(line.into(), false) {
            dbg!(err);
            break;
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let config = load_config();

    if args[1] == "call" {
        let tcp_stream = TcpStream::connect((config.xot_gateway, xot::TCP_PORT))?;

        let xot_link = XotLink::new(tcp_stream);

        let addr = X121Addr::from_str("737101").unwrap();
        let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

        let svc = Svc::call(xot_link, 1, &addr, &call_user_data, &config.x25_params)?;

        println!("CONNECTED!");

        very_simple_pad(svc);
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

            very_simple_pad(svc);
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
