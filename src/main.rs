use clap::Parser;
use std::io;
use std::net::TcpListener;
use std::time::Duration;

use xotpad::pad;
use xotpad::resolver::Resolver;
use xotpad::x121::X121Addr;
use xotpad::x25::{X25Modulo, X25Params};
use xotpad::xot;

fn main() -> io::Result<()> {
    let args = Args::parse();

    let config = load_config(&args);

    let listener = if args.should_listen {
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

    let svc = if let Some(addr) = args.call_addr {
        match pad::call(&addr, &config.x25_params, &config.resolver) {
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
    local_addr: X121Addr,

    #[arg(
        short = 'g',
        value_name = "GATEWAY",
        env = "XOT_GATEWAY",
        help = "XOT gateway"
    )]
    xot_gateway: String,

    #[arg(short = 'L', help = "Listen for incoming calls")]
    should_listen: bool,

    #[arg(
        conflicts_with = "should_listen",
        value_name = "ADDRESS",
        help = "X.121 address to call"
    )]
    call_addr: Option<X121Addr>,
}

#[derive(Debug)]
struct Config {
    x25_params: X25Params,
    resolver: Resolver,
}

fn load_config(args: &Args) -> Config {
    let x25_params = X25Params {
        addr: args.local_addr.clone(),
        modulo: X25Modulo::Normal,
        send_packet_size: 128,
        send_window_size: 2,
        recv_packet_size: 128,
        recv_window_size: 2,
        t21: Duration::from_secs(5),
        t22: Duration::from_secs(5),
        t23: Duration::from_secs(5),
    };

    let resolver = Resolver::new(&args.xot_gateway);

    Config {
        x25_params,
        resolver,
    }
}
