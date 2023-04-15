use clap::Parser;
use std::collections::HashMap;
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

    let (x25_params, resolver, x3_profiles, x3_profile) = load_config(&args);

    let listener = if args.should_listen {
        if let Ok(listener) = TcpListener::bind((args.xot_bind_addr.as_str(), xot::TCP_PORT)) {
            Some(listener)
        } else {
            println!("unable to bind... will not listen!");
            None
        }
    } else {
        None
    };

    let svc = if let Some(addr) = &args.call_addr {
        match pad::call(addr, &x25_params, &resolver) {
            Ok(svc) => Some(svc),
            Err(err) => {
                return Err(io::Error::new(io::ErrorKind::Other, err));
            }
        }
    } else {
        None
    };

    pad::run_user_pad(
        &x25_params,
        &x3_profiles,
        &resolver,
        listener,
        svc,
        x3_profile,
    )?;

    Ok(())
}

// -P X.25 profile
// -p X.3 profile
#[derive(Parser, Debug)]
struct Args {
    /// Local X.121 address.
    #[arg(short = 'a', value_name = "ADDRESS")]
    local_addr: Option<X121Addr>,

    /// XOT gateway.
    #[arg(short = 'g', value_name = "GATEWAY")]
    xot_gateway: Option<String>,

    /// Bind address for incoming XOT connections.
    #[arg(short = 'G', value_name = "ADDRESS", default_value = "0.0.0.0")]
    xot_bind_addr: String,

    /// Listen for incoming calls.
    #[arg(short = 'L')]
    should_listen: bool,

    /// X.3 profile.
    #[arg(short = 'p', value_name = "PROFILE", default_value = "default")]
    x3_profile: String,

    /// X.121 address to call.
    #[arg(value_name = "ADDRESS", conflicts_with = "should_listen")]
    call_addr: Option<X121Addr>,
}

fn load_config(args: &Args) -> (X25Params, XotResolver, HashMap<&str, X3Params>, &str) {
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

    let mut x3_profiles = HashMap::new();

    // TODO...
    x3_profiles.insert(
        "default",
        X3Params {
            echo: X3Echo::try_from(0).unwrap(),
            forward: X3Forward::try_from(2).unwrap(),
            idle: X3Idle::from(0),
        },
    );

    // TODO...
    let x3_profile = args.x3_profile.as_str();

    if !x3_profiles.contains_key(x3_profile) {
        panic!("uuuh that X.3 profile does not exist!");
    }

    (x25_params, resolver, x3_profiles, x3_profile)
}
