use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use xotpad::x121::X121Addr;
use xotpad::x25::{
    X25CallAccept, X25CallRequest, X25ClearRequest, X25Data, X25Facility, X25Modulo, X25Packet,
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
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()>;

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
        let (state, condvar) = &*self.state;

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
        let (state, _) = condvar
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

                    let (state, condvar) = &*state;

                    let mut state = state.lock().unwrap();

                    match *state {
                        SvcState::Ready => {
                            // uggghh, we only expect an incoming call I guess?
                            // or reset... if this was a PVC - actually PVC
                            // probably goes straight to DataTransfer?
                            unimplemented!("state == ready");
                        }
                        SvcState::WaitCallAccept => {
                            match packet {
                                X25Packet::CallAccept(_) => {
                                    // TODO: we need to negotiate!
                                    *state = SvcState::DataTransfer;
                                }
                                X25Packet::ClearRequest(clear_request) => {
                                    // TODO; how to communicate "last" cause?
                                    dbg!(clear_request);
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
        let (state, condvar) = &*self.state;

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
        let (state, _) = condvar
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
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        todo!()
    }

    fn recv(&self) -> io::Result<(Bytes, bool)> {
        let (queue, condvar) = &*self.recv_data;

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
        let data = svc.recv()?;

        dbg!(&data);

        if data.0.ends_with(b"Password: ") {
            println!("y0!");

            svc.send(Bytes::from_static(b"password"), false)?;
        }
    }

    svc.clear(0, 0)?;

    println!("all done!");

    Ok(())
}

fn next_seq(seq: u8, modulo: X25Modulo) -> u8 {
    (seq + 1) % (modulo as u8)
}

fn to_other_io_error(e: String) -> io::Error {
    //io::Error::other(e)
    io::Error::new(io::ErrorKind::Other, e)
}
