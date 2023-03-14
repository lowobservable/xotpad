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
    X25CallAccept, X25CallRequest, X25ClearConfirm, X25ClearRequest, X25Data, X25Facility,
    X25Modulo, X25Packet,
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
    pub fn call(...) -> io::Result<Self>

    pub fn listen(link: XotLink, params: &X25Params) -> io::Result<SvcIncomingCall>
}

struct SvcIncomingCall(X25CallRequest);

impl SvcIncomingCall {
    pub fn accept(self) -> Svc

    pub fn clear(self, cause: u8, diagnostic_code: u8)
}
*/

#[derive(Clone, Debug)]
enum SvcState {
    Ready,
    WaitCallAccept,
    DataTransfer(DataTransferState),
    //WaitResetConfirm,
    WaitClearConfirm,
    Clear(Option<(u8, u8)>),
    // TODO: LinkUnavail - i.e. socket closed ???
}

#[derive(Copy, Clone, Debug)]
struct DataTransferState {
    send_seq: u8,
    recv_seq: u8,
    // ...
}

#[allow(clippy::derivable_impls)]
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

                if !matches!(*state, SvcState::Ready) {
                    return Err(to_other_io_error("invalid state".into()));
                }

                let call_request =
                    send_call_request(&svc.send_link, channel, addr, call_user_data, &svc.params)?;

                *state = SvcState::WaitCallAccept; /*(Instant::now(), call_request)*/
            }

            // TODO: trigger the state condvar ourselves here!

            // Okay, now we wait...
            let timeout = svc.params.read().unwrap().t21;

            let (state, _) = condvar
                .wait_timeout_while(state.lock().unwrap(), timeout, |state| {
                    matches!(*state, SvcState::WaitCallAccept)
                })
                .unwrap();

            (*state).clone()
        };

        match state {
            SvcState::DataTransfer(_) => Ok(svc),
            SvcState::Clear(request) => {
                let (cause, diagnostic_code) = request.unwrap_or((0, 0));

                let message = format!("call cleared: {cause} - {diagnostic_code}");

                Err(to_other_io_error(message))
            }
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

            let clear_request = send_clear_request(
                &self.send_link,
                self.channel,
                cause,
                diagnostic_code,
                &self.params,
            )?;

            *state = SvcState::WaitClearConfirm;

            // TODO: notify listeners of the state change here!
        }

        // Okay, now we wait...
        let timeout = self.params.read().unwrap().t23;

        let (state, _) = condvar
            .wait_timeout_while(state.lock().unwrap(), timeout, |state| {
                matches!(*state, SvcState::WaitClearConfirm)
            })
            .unwrap();

        match *state {
            SvcState::Clear(..) => Ok(()),
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

            if packet.channel().is_some() && packet.channel().unwrap() != channel {
                todo!("probably just need to ingore this...");
            }

            let (state, condvar) = &*state;

            let mut state = state.lock().unwrap();

            match *state {
                SvcState::Ready => {
                    // uggghh, we only expect an incoming call I guess?
                    // or reset... if this was a PVC - actually PVC
                    // probably goes straight to DataTransfer?
                    unimplemented!("state == ready");
                }
                SvcState::WaitCallAccept => match packet {
                    X25Packet::CallAccept(call_accept) => {
                        let mut params = params.write().unwrap();

                        *params = negotiate(&call_accept, &params);
                        *state = SvcState::DataTransfer(DataTransferState::default());
                    }
                    X25Packet::ClearRequest(X25ClearRequest {
                        cause,
                        diagnostic_code,
                        ..
                    }) => {
                        *state = SvcState::Clear(Some((cause, diagnostic_code)));
                    }
                    X25Packet::CallRequest(_) => {
                        // TODO: how to communicate collision?
                        *state = SvcState::Ready;
                    }
                    _ => {
                        todo!("ignore?");
                    }
                },
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
                    X25Packet::ClearRequest(X25ClearRequest {
                        cause,
                        diagnostic_code,
                        ..
                    }) => {
                        let _ = send_clear_confirm(&send_link, channel, &params);

                        *state = SvcState::Clear(Some((cause, diagnostic_code)));

                        // Wake up the recv_queue waiters, as this is how the
                        // user will be notified of the clearing.
                        recv_queue.1.notify_all();
                    }
                    _ => {
                        todo!("ignore?");
                    }
                },
                SvcState::WaitClearConfirm => match packet {
                    X25Packet::ClearConfirm(_) => {
                        *state = SvcState::Clear(None);
                    }
                    X25Packet::ClearRequest(_) => {
                        // TODO: how to communicate collision?
                        *state = SvcState::Ready;
                    }
                    _ => {
                        todo!("ignore?");
                    }
                },
                SvcState::Clear(..) => {
                    // It is up to the call(), clear() or recv() methods to return
                    // us to ready.
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
}

fn send_call_request(
    link: &Mutex<XotLink>,
    channel: u16,
    addr: &X121Addr,
    call_user_data: &Bytes,
    params: &RwLock<X25Params>,
) -> io::Result<X25CallRequest> {
    let params = params.read().unwrap();

    let call_request = X25CallRequest {
        modulo: params.modulo,
        channel,
        called_addr: addr.clone(),
        calling_addr: params.addr.clone(),
        facilities: (&*params).into(),
        call_user_data: call_user_data.clone(),
    };

    // very hackky...
    let packet = call_request.into();
    send_packet(link, &packet)?;
    let X25Packet::CallRequest(call_request) = packet else { unreachable!() };

    Ok(call_request)
}

fn send_clear_request(
    link: &Mutex<XotLink>,
    channel: u16,
    cause: u8,
    diagnostic_code: u8,
    params: &RwLock<X25Params>,
) -> io::Result<X25ClearRequest> {
    let params = params.read().unwrap();

    let clear_request = X25ClearRequest {
        modulo: params.modulo,
        channel,
        cause,
        diagnostic_code,
        called_addr: X121Addr::null(),
        calling_addr: X121Addr::null(),
        facilities: Vec::new(),
        clear_user_data: Bytes::new(),
    };

    // very hackky...
    let packet = clear_request.into();
    send_packet(link, &packet)?;
    let X25Packet::ClearRequest(clear_request) = packet else { unreachable!() };

    Ok(clear_request)
}

fn send_clear_confirm(
    link: &Mutex<XotLink>,
    channel: u16,
    params: &RwLock<X25Params>,
) -> io::Result<X25ClearConfirm> {
    let params = params.read().unwrap();

    let clear_confirm = X25ClearConfirm {
        modulo: params.modulo,
        channel,
        called_addr: X121Addr::null(),
        calling_addr: X121Addr::null(),
        facilities: Vec::new(),
    };

    // very hackky...
    let packet = clear_confirm.into();
    send_packet(link, &packet)?;
    let X25Packet::ClearConfirm(clear_confirm) = packet else { unreachable!() };

    Ok(clear_confirm)
}

fn send_packet(link: &Mutex<XotLink>, packet: &X25Packet) -> io::Result<()> {
    let mut buf = BytesMut::new();

    packet.encode(&mut buf).map_err(to_other_io_error)?;

    let mut link = link.lock().unwrap();

    link.send(&buf)
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

            // TODO: confirm this doesn't cause a deadlock...
            // Capture the state before we check the queue...
            let state = (*self.state.0.lock().unwrap()).clone();

            if let Some(data) = queue.pop_front() {
                // TODO: there could be MORE!
                return Ok((data.user_data, data.qualifier));
            }

            // There isn't any data...
            match state {
                SvcState::Ready | SvcState::WaitCallAccept => {
                    return Err(to_other_io_error("Not connected".into()));
                }
                SvcState::Clear(request) => {
                    let (cause, diagnostic_code) = request.unwrap_or((0, 0));

                    let message = format!("call cleared: {cause} - {diagnostic_code}");

                    return Err(to_other_io_error(message));
                }
                // TODO: LinkUnavail - i.e. socket closed ???
                _ => {
                    queue = condvar.wait(queue).unwrap();
                }
            };
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

    let tcp_stream = TcpStream::connect(("localhost", xot::TCP_PORT))?;

    let xot_link = XotLink::new(tcp_stream);

    let addr = X121Addr::from_str("73710301").unwrap();
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
