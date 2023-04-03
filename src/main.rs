use std::env;
use std::io;
use std::net::TcpListener;
use std::str::FromStr;
use std::time::Duration;

use xotpad::pad;
use xotpad::resolver::Resolver;
use xotpad::x121::X121Addr;
use xotpad::x25::{X25Modulo, X25Params};
use xotpad::xot;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let config = load_config();

    let listener = if true {
        match TcpListener::bind(("0.0.0.0", xot::TCP_PORT)) {
            Ok(listener) => Some(listener),
            Err(err) => {
                println!("unable to bind... will not listen!");
                None
            }
        }
    } else {
        None
    };

    let svc = if args.len() > 1 {
        let addr = X121Addr::from_str(&args[1]).expect("TODO");

        match pad::call(addr, &config.x25_params, &config.resolver) {
            Ok(svc) => Some(svc),
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err));
            }
        }
    } else {
        None
    };

    pad::run(&config.x25_params, &config.resolver, listener, svc)?;

    Ok(())
}

struct Config {
    x25_params: X25Params,
    resolver: Resolver,
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

    let resolver = Resolver::new(&xot_gateway);

    Config {
        x25_params,
        resolver,
    }
}
