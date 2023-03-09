use bytes::{Bytes, BytesMut};
use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;

use xotpad::x121::X121Addr;
use xotpad::x25::{
    X25CallAccept, X25CallRequest, X25ClearConfirm, X25ClearRequest, X25Data, X25Modulo, X25Packet,
    X25ResetConfirm, X25ResetRequest,
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

fn send_call_request(link: &mut XotLink, addr: &X121Addr) -> io::Result<()> {
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

fn send_call_accept(link: &mut XotLink) -> io::Result<()> {
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

fn send_clear_request(link: &mut XotLink, cause: u8, diagnostic_code: u8) -> io::Result<()> {
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

fn send_clear_confirm(link: &mut XotLink) -> io::Result<()> {
    let clear_confirm = X25ClearConfirm {
        modulo: X25Modulo::Normal,
        channel: 1,
        called_addr: X121Addr::null(),
        calling_addr: X121Addr::null(),
        facilities: Vec::new(),
    };

    send(link, &clear_confirm.into())
}

fn send_data(link: &mut XotLink, send_seq: u8, recv_seq: u8, user_data: Bytes) -> io::Result<()> {
    let data = X25Data {
        modulo: X25Modulo::Normal,
        channel: 1,
        send_seq,
        recv_seq,
        qualifier: false,
        delivery: false,
        more: false,
        user_data,
    };

    send(link, &data.into())
}

fn send_reset_request(link: &mut XotLink, cause: u8, diagnostic_code: u8) -> io::Result<()> {
    let reset_request = X25ResetRequest {
        modulo: X25Modulo::Normal,
        channel: 1,
        cause,
        diagnostic_code,
    };

    send(link, &reset_request.into())
}

fn send_reset_confirm(link: &mut XotLink) -> io::Result<()> {
    let reset_confirm = X25ResetConfirm {
        modulo: X25Modulo::Normal,
        channel: 1,
    };

    send(link, &reset_confirm.into())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args[1] == "call" {
        let tcp_stream = TcpStream::connect(("pac1", xot::TCP_PORT))?;

        let mut xot_link = XotLink::new(tcp_stream);

        send_call_request(&mut xot_link, &X121Addr::from_str("73710301").unwrap())?;

        loop {
            let x25_packet = xot_link.recv()?;

            println!("{:?}", x25_packet);

            let x25_packet = X25Packet::decode(x25_packet).map_err(to_other_io_error)?;

            println!("{:?}", x25_packet);

            send_clear_request(&mut xot_link, 0, 0)?;
        }
    } else if args[1] == "listen" {
        let tcp_listener = TcpListener::bind("0.0.0.0:1998")?;

        for tcp_stream in tcp_listener.incoming() {
            let mut xot_link = XotLink::new(tcp_stream.unwrap());

            let mut send_seq = 0;

            loop {
                let x25_packet = xot_link.recv()?;

                println!("{:?}", x25_packet);

                let x25_packet = X25Packet::decode(x25_packet).map_err(to_other_io_error)?;

                println!("{:?}", x25_packet);

                match x25_packet {
                    X25Packet::CallRequest(call_request) => {
                        if call_request.called_addr == X121Addr::from_str("73720299").unwrap() {
                            send_call_accept(&mut xot_link)?;
                        } else {
                            send_clear_request(&mut xot_link, 0, 0)?;
                        }
                    }
                    X25Packet::ClearRequest(_) => {
                        send_clear_confirm(&mut xot_link)?;
                        break;
                    }
                    X25Packet::ClearConfirm(_) => break,
                    X25Packet::Data(data) => {
                        let recv_seq = next_seq(data.send_seq, data.modulo);

                        let user_data = generate_response(data.user_data);

                        send_data(&mut xot_link, 0, recv_seq, user_data)?;

                        send_seq = next_seq(send_seq, data.modulo);
                    }
                    X25Packet::ReceiveReady(_) => continue,
                    X25Packet::ResetRequest(_) => {
                        send_seq = 0;

                        send_reset_confirm(&mut xot_link)?;
                    }
                    X25Packet::ResetConfirm(_) => {
                        send_seq = 0;
                    }
                    _ => unimplemented!(),
                }
            }

            println!("done with this link!");
        }
    }

    Ok(())
}

fn next_seq(seq: u8, modulo: X25Modulo) -> u8 {
    (seq + 1) % (modulo as u8)
}

fn generate_response(user_data: Bytes) -> Bytes {
    user_data
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
