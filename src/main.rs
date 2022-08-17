use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};

mod x25;

mod xot;
use xot::XotLinkLayer;

fn main() -> io::Result<()> {
    let x: Vec<String> = env::args().collect();

    if x[1] == "call" {
        let tcp_stream = TcpStream::connect(("127.0.0.1", 1998))?;

        let mut xot_link_layer = XotLinkLayer::new(tcp_stream);

        let packet = [0_u8; x25::MAX_PACKET_LEN];

        for len in x25::MIN_PACKET_LEN..=x25::MAX_PACKET_LEN {
            xot_link_layer.send(&packet[..len])?;
        }
    } else if x[1] == "listen" {
        let tcp_listener = TcpListener::bind("127.0.0.1:1998")?;

        for tcp_stream in tcp_listener.incoming() {
            let mut xot_link_layer = XotLinkLayer::new(tcp_stream.unwrap());

            loop {
                let x25_packet = xot_link_layer.recv()?;

                println!("{}", x25_packet.len());
            }
        }
    }

    Ok(())
}
