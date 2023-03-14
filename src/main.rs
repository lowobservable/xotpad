use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::io;
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, RwLock};
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
    // ...
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

// TODO: can we make this consume the inncombin params?
fn negotiate(call_accept: &X25CallAccept, params: &X25Params) -> X25Params {
    let params = params.clone();

    X25Params {
        addr: params.addr.clone(),
        modulo: call_accept.modulo,
        ..params
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
    DataTransfer(DataTransferState),
    //WaitResetConfirm,
    WaitClearConfirm,
    // TODO: LinkUnavail - i.e. socket closed ???
}

#[derive(Copy, Clone, PartialEq, Debug)]
struct DataTransferState {
    send_seq: u8,
    recv_seq: u8,
    // ...
}

impl Default for DataTransferState {
    fn default() -> Self {
        DataTransferState {
            send_seq: 0,
            recv_seq: 0,
            // ...
        }
    }
}

struct Svc {
    send_link: Arc<Mutex<XotLink>>, // does this really need to have a lock?
    channel: u16,
    // TODO: if call / listen handled the bootstrapping better, this would
    // not need a lock, right?
    params: Arc<RwLock<X25Params>>,
    state: Arc<(Mutex<SvcState>, Condvar)>,
    send_queue: Arc<(Mutex<VecDeque<(Bytes, bool)>>, Condvar)>,
    recv_queue: Arc<(Mutex<VecDeque<X25Data>>, Condvar)>,
}

impl Svc {
    pub fn call(
        link: XotLink,
        channel: u16,
        addr: &X121Addr,
        call_user_data: &Bytes,
        params: &X25Params,
    ) -> io::Result<Self> {
        let svc = Svc::new(link, channel, params);

        let state = {
            let (state, condvar) = &*svc.state;

            // Send the call request...
            {
                let mut state = state.lock().unwrap();

                if *state != SvcState::Ready {
                    return Err(to_other_io_error("invalid state".into()));
                }

                *state = SvcState::WaitCallAccept;

                let params = svc.params.read().unwrap();

                let call_request = X25CallRequest {
                    modulo: params.modulo,
                    channel: svc.channel,
                    called_addr: addr.clone(),
                    calling_addr: params.addr.clone(),
                    facilities: (&*params).into(),
                    call_user_data: call_user_data.clone(),
                };

                if let Err(err) = Svc::send_packet(&svc.send_link, &call_request.into()) {
                    // uugh...
                    *state = SvcState::Ready;
                    return Err(err);
                }
            }

            // Okay, now we wait...
            let timeout = svc.params.read().unwrap().t21;

            let (state, _) = condvar
                .wait_timeout_while(state.lock().unwrap(), timeout, |state| {
                    *state == SvcState::WaitCallAccept
                })
                .unwrap();

            *state
        };

        match state {
            SvcState::DataTransfer(_) => Ok(svc),
            SvcState::Ready => Err(to_other_io_error(
                "rejected but I don't know how to tell you why just yet".into(),
            )),
            SvcState::WaitCallAccept => Err(to_other_io_error("T21 timeout".into())),
            _ => unreachable!(),
        }
    }

    // TODO: this will only be used on a active "svc" not an 'incoming call'
    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        let (state, condvar) = &*self.state;

        // Send the clear request...
        {
            let mut state = state.lock().unwrap();

            if !(matches!(*state, SvcState::DataTransfer(_))/*|| *state == SvcState::WaitResetConfirm)*/)
            {
                return Err(to_other_io_error("invalid state".into()));
            }

            let prev_state = *state;

            *state = SvcState::WaitClearConfirm;

            let modulo = self.params.read().unwrap().modulo;

            let clear_request = X25ClearRequest {
                modulo,
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
        let timeout = self.params.read().unwrap().t23;

        let (state, _) = condvar
            .wait_timeout_while(state.lock().unwrap(), timeout, |state| {
                *state == SvcState::WaitClearConfirm
            })
            .unwrap();

        match *state {
            SvcState::Ready => Ok(()),
            SvcState::WaitClearConfirm => Err(to_other_io_error("T23 timeout".into())),
            _ => unreachable!(),
        }
    }

    fn new(link: XotLink, channel: u16, params: &X25Params) -> Self {
        let (send_link, recv_link) = split_xot_link(link);

        let send_link = Arc::new(Mutex::new(send_link));

        let params = Arc::new(RwLock::new(params.clone()));
        let state = Arc::new((Mutex::new(SvcState::Ready), Condvar::new()));
        let send_queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let recv_queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));

        // start the packet receiver thread...
        thread::spawn({
            let send_link = Arc::clone(&send_link);
            let params = Arc::clone(&params);
            let state = Arc::clone(&state);
            let send_queue = Arc::clone(&send_queue);
            let recv_queue = Arc::clone(&recv_queue);

            move || {
                Svc::run(
                    send_link, recv_link, channel, params, state, send_queue, recv_queue,
                )
            }
        });

        // TODO: wait on a "running" barrier?

        Svc {
            send_link,
            channel,
            params,
            state,
            send_queue,
            recv_queue,
        }
    }

    fn run(
        send_link: Arc<Mutex<XotLink>>,
        mut recv_link: XotLink,
        channel: u16,
        params: Arc<RwLock<X25Params>>,
        state: Arc<(Mutex<SvcState>, Condvar)>,
        send_queue: Arc<(Mutex<VecDeque<(Bytes, bool)>>, Condvar)>,
        recv_queue: Arc<(Mutex<VecDeque<X25Data>>, Condvar)>,
    ) {
        // release a "running" barrier?

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
                        X25Packet::CallAccept(call_accept) => {
                            let mut params = params.write().unwrap();

                            *params = negotiate(&call_accept, &params);
                            *state = SvcState::DataTransfer(DataTransferState::default());
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
                SvcState::DataTransfer(mut data_transfer_state) => match packet {
                    X25Packet::Data(data) => {
                        // validate it...

                        // queue it...
                        Svc::queue_recv_data(&recv_queue, data);

                        // update window...
                        data_transfer_state.recv_seq = 9; // TODO...

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

        println!("runner done running...");
    }

    fn send_queued_data() -> io::Result<(usize, usize)> {
        // returns (pkts sent, pkts remaining)...
        todo!()
    }

    fn queue_recv_data((queue, condvar): &(Mutex<VecDeque<X25Data>>, Condvar), data: X25Data) {
        let mut queue = queue.lock().unwrap();

        queue.push_back(data);

        condvar.notify_all();
    }

    fn send_packet(link: &Mutex<XotLink>, packet: &X25Packet) -> io::Result<()> {
        let mut buf = BytesMut::new();

        packet.encode(&mut buf).map_err(to_other_io_error)?;

        let mut link = link.lock().unwrap();

        link.send(&buf)
    }
}

impl Vc for Svc {
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        // TODO: check that things aren't dead... maybe?

        let (queue, condvar) = &*self.send_queue;

        let mut queue = queue.lock().unwrap();

        // TODO: split user_data into chunks based on max send packet size...
        queue.push_back((user_data, qualifier));

        condvar.notify_all();

        Ok(())
    }

    fn recv(&self) -> io::Result<(Bytes, bool)> {
        let (queue, condvar) = &*self.recv_queue;

        let mut queue = queue.lock().unwrap();

        // TODO: this should "reconstruct" MORE packets...

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

    let svc = Svc::call(xot_link, 1, &addr, &call_user_data, &x25_params)?;

    println!("COM!!!");

    loop {
        let data = svc.recv()?;

        dbg!(&data);

        if data.0.ends_with(b"Password: ") {
            /*
            println!("y0!");

            svc.send(Bytes::from_static(b"password\r"), false)?;
            */
            break;
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
