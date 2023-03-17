use bytes::Bytes;
use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use xotpad::x121::X121Addr;
use xotpad::x25::{Svc, Vc, X25CallRequest, X25Modulo, X25Params};
use xotpad::xot::{self, XotLink};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let x25_params = X25Params {
        addr: X121Addr::from_str("73720201").unwrap(),
        modulo: X25Modulo::Normal,
        t21: Duration::from_secs(5),
        t23: Duration::from_secs(5),
    };

    if args[1] == "call" {
        let tcp_stream = TcpStream::connect(("localhost", xot::TCP_PORT))?;

        let xot_link = XotLink::new(tcp_stream);

        let addr = X121Addr::from_str("737101").unwrap();
        let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

        let svc = Svc::call(xot_link, 1, &addr, &call_user_data, &x25_params)?;

        while let Ok((data, qualifier)) = svc.recv() {
            println!("{:?}", data);

            if data.ends_with(b"Password: ") {
                break;
            }
        }

        svc.clear(0, 0)?;

        println!("all done!");
    } else if args[1] == "listen" {
        let tcp_listener = TcpListener::bind(("0.0.0.0", xot::TCP_PORT))?;

        for tcp_stream in tcp_listener.incoming() {
            let xot_link = XotLink::new(tcp_stream?);

            let incoming_call = Svc::listen(xot_link, &x25_params)?;

            if let Some((cause, diagnostic_code)) = should_accept_call(incoming_call.request()) {
                incoming_call.clear(cause, diagnostic_code)?;
                continue;
            }

            let svc = incoming_call.accept()?;

            svc.send(Bytes::from_static(b"hi there!"), false)?;

            thread::sleep(Duration::from_secs(5));

            svc.clear(0, 0)?;
        }
    }

    thread::sleep(Duration::from_secs(5));

    Ok(())
}

fn should_accept_call(call_request: &X25CallRequest) -> Option<(u8, u8)> {
    Some((0, 0))
}
