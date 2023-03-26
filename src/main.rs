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

    let config = load_config();

    if args[1] == "call" {
        let tcp_stream = TcpStream::connect((config.xot_gateway, xot::TCP_PORT))?;

        let xot_link = XotLink::new(tcp_stream);

        let addr = X121Addr::from_str("737101").unwrap();
        let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

        let svc = Svc::call(xot_link, 1, &addr, &call_user_data, &config.x25_params)?;

        println!("CONNECTED!");

        for _ in 0..10 {
            svc.reset(0, 0)?;
        }

        while let Ok((data, qualifier)) = svc.recv() {
            println!("{:?}", data);
        }

        // recv() will have returned an error when the link was cleared, we
        // cannot clear here...
        //
        // how should recv() do this, how can the "user" get at the clear
        // cause and diagnostic code?
        //svc.clear(0, 0)?;

        println!("all done!");
    } else if args[1] == "listen" {
        let tcp_listener = TcpListener::bind(("0.0.0.0", xot::TCP_PORT))?;

        for tcp_stream in tcp_listener.incoming() {
            let xot_link = XotLink::new(tcp_stream?);

            let incoming_call = Svc::listen(
                xot_link,
                1, /* this "channel" needs to be removed! */
                &config.x25_params,
            )?;

            thread::sleep(Duration::from_secs(30));

            if let Some((cause, diagnostic_code)) = should_accept_call(incoming_call.request()) {
                incoming_call.clear(cause, diagnostic_code)?;
                continue;
            }

            let svc = incoming_call.accept()?;

            println!("ACCEPTED!");

            thread::sleep(Duration::from_secs(5));

            println!("CLEARING...");

            svc.clear(0, 0)?;
        }
    }

    Ok(())
}

fn should_accept_call(call_request: &X25CallRequest) -> Option<(u8, u8)> {
    dbg!(call_request);

    //Some((0x39, 0))
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
