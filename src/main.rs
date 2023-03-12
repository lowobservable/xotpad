use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use xotpad::x121::X121Addr;
use xotpad::x25::{
    X25CallAccept, X25CallRequest, X25ClearConfirm, X25ClearRequest, X25Data, X25Facility,
    X25Modulo, X25Packet, X25ReceiveNotReady, X25ReceiveReady, X25ResetConfirm, X25ResetRequest,
};
use xotpad::xot::{self, XotLink};

#[derive(Clone)]
struct X25Params {
    addr: X121Addr,
    modulo: X25Modulo,
    t21: Duration,
    t23: Duration,
}

impl From<&X25Params> for Vec<X25Facility> {
    fn from(params: &X25Params) -> Vec<X25Facility> {
        vec![
            X25Facility::PacketSize {
                from_called: 128,  // TODO
                from_calling: 128, // TODO
            },
            X25Facility::WindowSize {
                from_called: 2,  // TODO
                from_calling: 2, // TODO
            },
        ]
    }
}

trait Vc {
    //fn send(&self, user_data: &Bytes, qualifier: bool) -> io::Result<()>;

    fn recv(&self) -> io::Result<(Bytes, bool)>;

    //fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()>;
}

/*
impl Svc {
    pub fn call(...) -> io::Result<Svc>

    pub fn listen(link: XotLink, params: &X25Params) -> io::Result<SvcIncomingCall>
}

struct SvcIncomingCall(X25CallRequest);

impl SvcIncomingCall {
    pub fn accept(self) -> Svc

    pub fn clear(self)
}
*/

#[derive(Copy, Clone, PartialEq, Debug)]
enum SvcState {
    Ready,
    WaitCallAccept,
    DataTransfer,
    //WaitResetConfirm,
    WaitClearConfirm,
}

struct Svc {
    send_link: Arc<Mutex<XotLink>>, // does this really need to have a lock?
    params: X25Params,
    channel: u16,
    state: Arc<(Mutex<SvcState>, Condvar)>,
    modulo: X25Modulo, // TODO: this is "real" modulo...
    // ...
    recv_data: Arc<(Mutex<VecDeque<X25Data>>, Condvar)>,
}

impl Svc {
    pub fn call(
        link: XotLink,
        params: &X25Params,
        channel: u16,
        addr: &X121Addr,
        call_user_data: &Bytes,
    ) -> io::Result<Self> {
        let mut svc = Svc::start(link, params.clone(), channel);

        svc.call_request(addr, call_user_data)?;

        Ok(svc)
    }

    // TODO: this will only be used on a active "svc" not an 'incoming call'
    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        let (state, condvar) = self.state.deref();

        // Send the clear request...
        {
            let mut state = state.lock().unwrap();

            if !(*state == SvcState::DataTransfer/*|| *state == SvcState::WaitResetConfirm)*/) {
                return Err(to_other_io_error("invalid state".into()));
            }

            let prev_state = *state;

            *state = SvcState::WaitClearConfirm;

            let clear_request = X25ClearRequest {
                modulo: self.modulo,
                channel: self.channel,
                cause,
                diagnostic_code,
                called_addr: X121Addr::null(),
                calling_addr: X121Addr::null(),
                facilities: Vec::new(),
                clear_user_data: Bytes::new(),
            };

            if let Err(err) = Svc::send_packet(&self.send_link, &clear_request.into()) {
                // uugh...
                *state = prev_state;
                return Err(err);
            }
        }

        // Okay, now we wait...
        let (state, timeout) = condvar
            .wait_timeout_while(state.lock().unwrap(), self.params.t23, |state| {
                *state == SvcState::WaitClearConfirm
            })
            .unwrap();

        match *state {
            SvcState::Ready => Ok(()),
            SvcState::WaitClearConfirm => Err(to_other_io_error("T23 timeout".into())),
            _ => unreachable!(),
        }
    }

    fn start(link: XotLink, params: X25Params, channel: u16) -> Self {
        let (send_link, mut recv_link) = split_xot_link(link);

        let send_link = Arc::new(Mutex::new(send_link));
        let state = Arc::new((Mutex::new(SvcState::Ready), Condvar::new()));

        let recv_data = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));

        // start the packet receiver thread...
        thread::spawn({
            let state = Arc::clone(&state);
            let recv_data = Arc::clone(&recv_data);

            move || {
                println!("recv thread starting...");

                while let Ok(packet) = recv_link.recv() {
                    let packet = match X25Packet::decode(packet) {
                        Ok(packet) => packet,
                        Err(err) => {
                            dbg!(err);
                            continue;
                        }
                    };

                    let (state, condvar) = state.deref();

                    let mut state = state.lock().unwrap();

                    match *state {
                        SvcState::Ready => {
                            // uggghh, we only expect an incoming call I guess?
                            // or reset... if this was a PVC
                            unimplemented!("state == ready");
                        }
                        SvcState::WaitCallAccept => {
                            match packet {
                                X25Packet::CallAccept(_) => {
                                    // TODO: we need to negotiate!
                                    *state = SvcState::DataTransfer;
                                }
                                X25Packet::ClearRequest(_) => {
                                    // TODO; how to communicate "last" cause?
                                    *state = SvcState::Ready;
                                }
                                X25Packet::CallRequest(_) => {
                                    // TODO: how to communicate collision?
                                    *state = SvcState::Ready;
                                }
                                _ => {
                                    todo!("ignore?");
                                }
                            }
                        }
                        SvcState::DataTransfer => match packet {
                            X25Packet::Data(data) => {
                                // validate it...

                                // queue it...
                                Svc::queue_recv_data(&recv_data, data);

                                // update window...

                                // release anything from the send queue...

                                // or, send receive ready
                            }
                            _ => {
                                todo!("ignore?");
                            }
                        },
                        SvcState::WaitClearConfirm => {
                            match packet {
                                X25Packet::ClearConfirm(_) => {
                                    *state = SvcState::Ready;
                                }
                                X25Packet::ClearRequest(_) => {
                                    // TODO: how to communicate collision?
                                    *state = SvcState::Ready;
                                }
                                _ => {
                                    todo!("ignore?");
                                }
                            }
                        }
                    }

                    condvar.notify_all();
                }

                // TODO: tell the engine we quit?

                println!("recv thread finished");
            }
        });

        let modulo = params.modulo; // ???

        Svc {
            send_link,
            params,
            channel,
            state,
            modulo,
            // ...
            recv_data,
        }
    }

    fn call_request(&mut self, addr: &X121Addr, call_user_data: &Bytes) -> io::Result<()> {
        let (state, condvar) = self.state.deref();

        // Send the call request...
        {
            let mut state = state.lock().unwrap();

            if *state != SvcState::Ready {
                return Err(to_other_io_error("invalid state".into()));
            }

            *state = SvcState::WaitCallAccept;

            let call_request = X25CallRequest {
                modulo: self.params.modulo,
                channel: self.channel,
                called_addr: addr.clone(),
                calling_addr: self.params.addr.clone(),
                facilities: Vec::new(),
                call_user_data: call_user_data.clone(),
            };

            if let Err(err) = Svc::send_packet(&self.send_link, &call_request.into()) {
                // uugh...
                *state = SvcState::Ready;
                return Err(err);
            }
        }

        // Okay, now we wait...
        let (state, timeout) = condvar
            .wait_timeout_while(state.lock().unwrap(), self.params.t21, |state| {
                *state == SvcState::WaitCallAccept
            })
            .unwrap();

        match *state {
            SvcState::DataTransfer => Ok(()),
            SvcState::Ready => Err(to_other_io_error(
                "rejected but I don't know how to tell you why just yet".into(),
            )),
            SvcState::WaitCallAccept => Err(to_other_io_error("T21 timeout".into())),
            _ => unreachable!(),
        }
    }

    fn send_packet(link: &Mutex<XotLink>, packet: &X25Packet) -> io::Result<()> {
        let mut buf = BytesMut::new();

        packet.encode(&mut buf).map_err(to_other_io_error)?;

        let mut link = link.lock().unwrap();

        link.send(&buf)
    }

    fn queue_recv_data((queue, condvar): &(Mutex<VecDeque<X25Data>>, Condvar), data: X25Data) {
        let mut queue = queue.lock().unwrap();

        queue.push_back(data);

        condvar.notify_all();
    }
}

impl Vc for Svc {
    fn recv(&self) -> io::Result<(Bytes, bool)> {
        let (queue, condvar) = self.recv_data.deref();

        let mut queue = queue.lock().unwrap();

        loop {
            // TODO...
            //if queue.is_none() {
            //    return Err(io::Error::new(io::ErrorKind::ConnectionReset, "...".into()));
            //}

            if let Some(data) = queue.pop_front() {
                // TODO: there could be MORE!
                return Ok((data.user_data, data.qualifier));
            }

            queue = condvar.wait(queue).unwrap();
        }
    }
}

fn split_xot_link(link: XotLink) -> (XotLink, XotLink) {
    // crazy hack...
    let tcp_stream = link.into_stream();

    (
        XotLink::new(tcp_stream.try_clone().unwrap()),
        XotLink::new(tcp_stream),
    )
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "blah" {
        let tcp_listener = TcpListener::bind(("0.0.0.0", xot::TCP_PORT))?;

        for tcp_stream in tcp_listener.incoming() {
            println!("got a live one...");

            let mut xot_link = XotLink::new(tcp_stream.unwrap());

            thread::sleep(Duration::from_secs(2));

            let x25_packet = X25CallAccept {
                modulo: X25Modulo::Normal,
                channel: 1,
                called_addr: X121Addr::null(),
                calling_addr: X121Addr::null(),
                facilities: Vec::new(),
                called_user_data: Bytes::new(),
            };

            /*
            let x25_packet = X25ClearRequest {
                modulo: X25Modulo::Normal,
                channel: 1,
                cause: 0,
                diagnostic_code: 0,
                called_addr: X121Addr::null(),
                calling_addr: X121Addr::null(),
                facilities: Vec::new(),
                clear_user_data: Bytes::new(),
            };
            */

            let mut buf = BytesMut::new();

            x25_packet.encode(&mut buf).map_err(to_other_io_error)?;

            xot_link.send(&buf)?;

            println!("sent packet!");

            // wait around a bit
            thread::sleep(Duration::from_secs(20));
        }
    } else {
        let x25_params = X25Params {
            addr: X121Addr::from_str("73720201").unwrap(),
            modulo: X25Modulo::Normal,
            t21: Duration::from_secs(5),
            t23: Duration::from_secs(5),
        };

        let tcp_stream = TcpStream::connect(("pac1", xot::TCP_PORT))?;

        let xot_link = XotLink::new(tcp_stream);

        let addr = X121Addr::from_str("737101").unwrap();
        let call_user_data = Bytes::from_static(b"\x01\x00\x00\x00");

        let svc = Svc::call(xot_link, &x25_params, 1, &addr, &call_user_data)?;

        println!("COM!!!");

        loop {
            let (user_data, qualifier) = svc.recv()?;

            dbg!(user_data);
        }

        svc.clear(0, 0)?;

        println!("all done!");
    }

    Ok(())
}

fn to_other_io_error(e: String) -> io::Error {
    //io::Error::other(e)
    io::Error::new(io::ErrorKind::Other, e)
}

/*
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

fn send_receive_ready(link: &mut XotLink, recv_seq: u8) -> io::Result<()> {
    let receive_ready = X25ReceiveReady {
        modulo: X25Modulo::Normal,
        channel: 1,
        recv_seq,
    };

    send(link, &receive_ready.into())
}

fn send_receive_not_ready(link: &mut XotLink, recv_seq: u8) -> io::Result<()> {
    let receive_not_ready = X25ReceiveNotReady {
        modulo: X25Modulo::Normal,
        channel: 1,
        recv_seq,
    };

    send(link, &receive_not_ready.into())
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

            dbg!(&x25_packet);

            let x25_packet = X25Packet::decode(x25_packet).map_err(to_other_io_error)?;

            dbg!(&x25_packet);

            send_clear_request(&mut xot_link, 0, 0)?;
        }
    } else if args[1] == "listen" {
        let tcp_listener = TcpListener::bind("0.0.0.0:1998")?;

        for tcp_stream in tcp_listener.incoming() {
            let mut xot_link = XotLink::new(tcp_stream.unwrap());

            let mut send_seq = 0;
            let mut recv_seq = 0;

            loop {
                let x25_packet = xot_link.recv()?;

                dbg!(&x25_packet);

                let x25_packet = X25Packet::decode(x25_packet).map_err(to_other_io_error)?;

                dbg!(&x25_packet);

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
                        if data.send_seq != recv_seq {
                            // Local procedure error - invalid P(S)...
                            send_reset_request(&mut xot_link, 5, 1)?;
                            continue;
                        }

                        recv_seq = next_seq(recv_seq, data.modulo);

                        match &data.user_data[..] {
                            b"xrr\r" => {
                                send_receive_ready(&mut xot_link, recv_seq)?;
                            }
                            b"xrnr\r" => {
                                send_receive_not_ready(&mut xot_link, recv_seq)?;

                                println!("sleeping for 10 seconds...");
                                thread::sleep(Duration::from_secs(10));

                                send_receive_ready(&mut xot_link, recv_seq)?;
                            }
                            _ => {
                                let user_data = generate_response(data.user_data);

                                send_data(&mut xot_link, send_seq, recv_seq, user_data)?;

                                send_seq = next_seq(send_seq, data.modulo);
                            }
                        };
                    }
                    X25Packet::ReceiveReady(_) => continue,
                    X25Packet::ResetRequest(_) => {
                        send_seq = 0;
                        recv_seq = 0;

                        send_reset_confirm(&mut xot_link)?;
                    }
                    X25Packet::ResetConfirm(_) => {
                        send_seq = 0;
                        recv_seq = 0;
                    }
                    _ => unimplemented!(),
                }
            }

            println!("done with this link!");
        }
    }

    Ok(())
}
*/

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
