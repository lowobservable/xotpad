use clap::Parser;
use std::io;
use std::net::TcpListener;
use std::time::Duration;

use xotpad::pad;
use xotpad::pad::x3::{X3Echo, X3Forward, X3Idle, X3Params};
use xotpad::x121::X121Addr;
use xotpad::x25::{X25Modulo, X25Params};
use xotpad::xot::{self, XotResolver};

fn main() -> io::Result<()> {
    let args = Args::parse();

    let (x25_params, resolver, x3_params) = load_config(&args);

    let listener = if args.should_listen {
        if let Ok(listener) = TcpListener::bind(("0.0.0.0", xot::TCP_PORT)) {
            Some(listener)
        } else {
            println!("unable to bind... will not listen!");
            None
        }
    } else {
        None
    };

    let svc = if let Some(addr) = args.call_addr {
        match pad::call(&addr, &x25_params, &resolver) {
            Ok(svc) => Some(svc),
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err));
            }
        }
    } else {
        None
    };

    pad::run(&x25_params, &resolver, listener, svc, &x3_params)?;

    Ok(())
}

// -a address
// -g gateway
// -G bind
// -P X.25 profile
// -p X.3 profile
#[derive(Parser, Debug)]
struct Args {
    #[arg(
        short = 'a',
        value_name = "ADDRESS",
        env = "X121_ADDRESS",
        help = "Local X.121 address"
    )]
    local_addr: Option<X121Addr>,

    #[arg(
        short = 'g',
        value_name = "GATEWAY",
        env = "XOT_GATEWAY",
        help = "XOT gateway"
    )]
    xot_gateway: Option<String>,

    #[arg(short = 'L', help = "Listen for incoming calls")]
    should_listen: bool,

    #[arg(
        conflicts_with = "should_listen",
        value_name = "ADDRESS",
        help = "X.121 address to call"
    )]
    call_addr: Option<X121Addr>,
}

fn load_config(args: &Args) -> (X25Params, XotResolver, X3Params) {
    let addr = match args.local_addr {
        Some(ref local_addr) => local_addr.clone(),
        None => X121Addr::null(),
    };

    let x25_params = X25Params {
        addr,
        modulo: X25Modulo::Normal,
        send_packet_size: 128,
        send_window_size: 2,
        recv_packet_size: 128,
        recv_window_size: 2,
        t21: Duration::from_secs(5),
        t22: Duration::from_secs(5),
        t23: Duration::from_secs(5),
    };

    let mut resolver = XotResolver::new();

    if let Some(ref xot_gateway) = args.xot_gateway {
        let _ = resolver.add(".*", xot_gateway);
    } else {
        let _ = resolver.add("^(...)(...)..", "\\2.\\1.x25.org");
    }

    let x3_params = X3Params {
        echo: X3Echo::try_from(0).unwrap(),
        forward: X3Forward::try_from(2).unwrap(),
        idle: X3Idle::from(0),
    };

    (x25_params, resolver, x3_params)
}
