use bytes::{Bytes, BytesMut};
use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;

use xotpad::x121::X121Addr;
use xotpad::x25::{
    X25CallAccept, X25CallRequest, X25ClearRequest, X25Modulo, X25Packet, X25PacketType,
};
use xotpad::xot::{self, XotLink};

fn to_other_io_error(e: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

fn send(link: &mut XotLink, packet: &X25Packet) -> io::Result<()> {
    let mut buf = BytesMut::new();

    packet.encode(&mut buf).map_err(to_other_io_error)?;

    link.send(&buf)
}

fn call_request(link: &mut XotLink, addr: &X121Addr) -> io::Result<()> {
    let calling_addr = X121Addr::from_str("73720201").unwrap();

    let call_request = X25CallRequest {
        modulo: X25Modulo::Normal,
        channel: 1,
        called_addr: addr.clone(),
        calling_addr,
        facilities: Vec::new(),
        call_user_data: Bytes::new(),
    };

    send(link, &call_request.into())
}

fn call_accept(link: &mut XotLink) -> io::Result<()> {
    let call_accept = X25CallAccept {
        modulo: X25Modulo::Normal,
        channel: 1,
        called_addr: X121Addr::null(),
        calling_addr: X121Addr::null(),
        facilities: Vec::new(),
        called_user_data: Bytes::new(),
    };

    send(link, &call_accept.into())
}

fn clear_request(link: &mut XotLink, cause: u8, diagnostic_code: u8) -> io::Result<()> {
    let clear_request = X25ClearRequest {
        modulo: X25Modulo::Normal,
        channel: 1,
        cause,
        diagnostic_code,
        called_addr: X121Addr::null(),
        calling_addr: X121Addr::null(),
        facilities: Vec::new(),
        clear_user_data: Bytes::new(),
    };

    send(link, &clear_request.into())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args[1] == "call" {
        let tcp_stream = TcpStream::connect(("pac1", xot::TCP_PORT))?;

        let mut xot_link = XotLink::new(tcp_stream);

        call_request(&mut xot_link, &X121Addr::from_str("73710301").unwrap())?;

        loop {
            let x25_packet = xot_link.recv()?;

            println!("{:?}", x25_packet);

            let x25_packet = X25Packet::decode(x25_packet).map_err(to_other_io_error)?;

            println!("{:?}", x25_packet);

            clear_request(&mut xot_link, 0, 0)?;
        }
    } else if args[1] == "listen" {
        let tcp_listener = TcpListener::bind("0.0.0.0:1998")?;

        for tcp_stream in tcp_listener.incoming() {
            let mut xot_link = XotLink::new(tcp_stream.unwrap());

            loop {
                let x25_packet = xot_link.recv()?;

                println!("{:?}", x25_packet);

                let x25_packet = X25Packet::decode(x25_packet).map_err(to_other_io_error)?;

                println!("{:?}", x25_packet);

                match x25_packet {
                    X25Packet::CallRequest(call_request) => {
                        if call_request.called_addr == X121Addr::from_str("73720299").unwrap() {
                            call_accept(&mut xot_link)?;
                        } else {
                            clear_request(&mut xot_link, 0, 0)?;
                        }
                    }
                    X25Packet::ClearConfirm(_) => break,
                    _ => todo!(),
                }
            }

            println!("done with this link!");
        }
    }

    Ok(())
}

/*
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args[1] == "send" {
        let tcp_stream = TcpStream::connect(("127.0.0.1", xot::TCP_PORT))?;

        let mut xot_link = XotLink::new(tcp_stream);

        let packet = [0_u8; x25::MAX_PACKET_LEN];

        for len in x25::MIN_PACKET_LEN..=x25::MAX_PACKET_LEN {
            xot_link.send(&packet[..len])?;
        }
    } else if args[1] == "recv" {
        let tcp_listener = TcpListener::bind("127.0.0.1:1998")?;

        for tcp_stream in tcp_listener.incoming() {
            let mut xot_link = XotLink::new(tcp_stream.unwrap());

            loop {
                let x25_packet = xot_link.recv()?;

                println!("{}", x25_packet.len());
            }
        }
    }

    Ok(())
}
*/
