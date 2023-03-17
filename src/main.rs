use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::io;
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

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

#[derive(Debug)]
enum VcState {
    Ready,
    WaitCallAccept(Instant),
    DataTransfer(DataTransferState),
    //WaitResetConfirm,
    WaitClearConfirm(Instant),

    // These are our custom ones...
    Clear(Option<(u8, u8)>),
    OutOfOrder,
}

#[derive(Debug)]
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

struct Svc(Arc<VcInner>);

impl Svc {
    pub fn call(
        link: XotLink,
        channel: u16,
        addr: &X121Addr,
        call_user_data: &Bytes,
        params: &X25Params,
    ) -> io::Result<Self> {
        let svc = Svc::new(link, channel, params);

        svc.0.call(addr, call_user_data)?;

        Ok(svc)
    }

    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        self.0.clear(cause, diagnostic_code)
    }

    pub fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        self.0.send(user_data, qualifier)
    }

    pub fn recv(&self) -> io::Result<(Bytes, bool)> {
        self.0.recv()
    }

    pub fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        self.0.reset(cause, diagnostic_code)
    }

    fn new(link: XotLink, channel: u16, params: &X25Params) -> Self {
        let (send_link, recv_link) = split_xot_link(link);

        let inner = Arc::new(VcInner::new(send_link, channel, params));

        let barrier = Arc::new(Barrier::new(2));

        thread::spawn({
            let inner = Arc::clone(&inner);
            let barrier = Arc::clone(&barrier);

            move || inner.run(recv_link, barrier)
        });

        barrier.wait();

        Svc(inner)
    }
}

struct VcInner {
    send_link: Arc<Mutex<XotLink>>, // does this really need to have a lock?
    engine_recv: Arc<Condvar>,
    channel: u16,
    state: Arc<(Mutex<VcState>, Condvar)>,
    params: Arc<RwLock<X25Params>>,
    send_data_queue: Arc<(Mutex<VecDeque<(Bytes, bool)>>, Condvar)>,
    recv_data_queue: Arc<(Mutex<VecDeque<X25Data>>, Condvar)>,
}

impl VcInner {
    fn new(send_link: XotLink, channel: u16, params: &X25Params) -> Self {
        let state = VcState::Ready;

        VcInner {
            send_link: Arc::new(Mutex::new(send_link)),
            engine_recv: Arc::new(Condvar::new()),
            channel,
            state: Arc::new((Mutex::new(state), Condvar::new())),
            params: Arc::new(RwLock::new(params.clone())),
            send_data_queue: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
            recv_data_queue: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
        }
    }

    fn run(&self, mut recv_link: XotLink, barrier: Arc<Barrier>) {
        println!("VC engine starting...");

        // Create another thread that reads packets, this will allow the main loop
        // wait to be interrupted while the XOT socket read is blocked.
        let recv_queue = Arc::new(Mutex::new(VecDeque::<io::Result<Bytes>>::new()));

        thread::spawn({
            let recv_queue = Arc::clone(&recv_queue);
            let engine_recv = Arc::clone(&self.engine_recv);

            move || {
                loop {
                    let packet = recv_link.recv();

                    let is_err = packet.is_err();

                    recv_queue.lock().unwrap().push_back(packet);
                    engine_recv.notify_all();

                    if is_err {
                        break;
                    }
                }

                println!("recv link done!");
            }
        });

        barrier.wait();

        let mut recv_queue = recv_queue.lock().unwrap();

        loop {
            let mut timeout = Duration::from_secs(1); // TODO

            let packet = recv_queue.pop_front();

            dbg!(&packet);

            // Handle a XOT link error, otherwise pass along the packet.
            let packet = match packet.transpose() {
                Ok(packet) => packet,
                Err(_) => {
                    let mut state = self.state.0.lock().unwrap();

                    self.change_state(&mut state, VcState::OutOfOrder, false, true);

                    break;
                }
            };

            // Decode the packet.
            let packet = match packet.map(X25Packet::decode).transpose() {
                Ok(packet) => packet,
                Err(err) => {
                    dbg!(err);
                    todo!();
                }
            };

            // Validate the packet.
            if let Some(ref packet) = packet {
                // ...
            }

            // Handle the packet.
            {
                let mut state = self.state.0.lock().unwrap();

                match *state {
                    VcState::Ready => {}
                    VcState::WaitCallAccept(start_time) => {
                        let elapsed = start_time.elapsed();
                        let t21 = self.params.read().unwrap().t21;

                        match packet {
                            Some(X25Packet::CallAccept(call_accept)) => {
                                let mut params = self.params.write().unwrap();

                                // TODO: can negotiation "fail"?
                                *params = negotiate(&call_accept, &params);

                                self.change_state(
                                    &mut state,
                                    VcState::DataTransfer(DataTransferState::default()),
                                    false,
                                    false,
                                );
                            }
                            Some(X25Packet::ClearRequest(X25ClearRequest {
                                cause,
                                diagnostic_code,
                                ..
                            })) => {
                                self.change_state(
                                    &mut state,
                                    VcState::Clear(Some((cause, diagnostic_code))),
                                    false,
                                    false,
                                );
                            }
                            Some(_) => {
                                // TODO: ignore?
                            }
                            None if elapsed > t21 => {
                                println!("T21 timeout, sending clear request...");

                                if send_clear_request(
                                    &mut self.send_link.lock().unwrap(),
                                    self.channel,
                                    19, // Local procedure error
                                    49, // Time expired for incoming call
                                    &self.params.read().unwrap(),
                                )
                                .is_err()
                                {
                                    todo!();
                                } else {
                                    self.change_state(
                                        &mut state,
                                        VcState::WaitClearConfirm(Instant::now()),
                                        false,
                                        false,
                                    );

                                    // TODO: we could be smarter about the next timeout here...
                                    timeout = Duration::from_secs(1);
                                }
                            }
                            None => timeout = t21 - elapsed,
                        }
                    }
                    VcState::DataTransfer(_) => {
                        match packet {
                            Some(X25Packet::Data(data)) => {
                                // validate and update windows...

                                self.queue_recv_data(data);

                                // send any queued packets, or respond with RR...
                            }
                            Some(_) => {
                                // TODO: ignore?
                            }
                            None => {}
                        }
                    }
                    //WaitResetConfirm,
                    VcState::WaitClearConfirm(start_time) => {
                        let elapsed = start_time.elapsed();
                        let t23 = self.params.read().unwrap().t23;

                        match packet {
                            Some(X25Packet::ClearConfirm(_)) => {
                                self.change_state(&mut state, VcState::Clear(None), false, false);
                            }
                            Some(X25Packet::ClearRequest(_)) => todo!(),
                            Some(_) => {
                                // TODO: ignore?
                            }
                            None if elapsed > t23 => {
                                println!("T23 timeout");

                                // TODO:
                                // For a timeout on a "call request timeout" that leads to a clear
                                // request Cisco sends "time expired for clear indication" twice (2
                                // retries of THIS state).
                                //
                                // what does it do for a user initiated clear?

                                self.change_state(&mut state, VcState::OutOfOrder, false, false);

                                break;
                            }
                            None => timeout = t23 - elapsed,
                        }
                    }
                    VcState::Clear(_) | VcState::OutOfOrder => {
                        panic!("unexpected state")
                    }
                }
            }

            (recv_queue, _) = self.engine_recv.wait_timeout(recv_queue, timeout).unwrap();
        }

        println!("VC engine done!");
    }

    fn call(&self, addr: &X121Addr, call_user_data: &Bytes) -> io::Result<()> {
        // Send the call request packet.
        {
            let mut state = self.state.0.lock().unwrap();

            if !matches!(*state, VcState::Ready) {
                todo!("invalid state");
            }

            send_call_request(
                &mut self.send_link.lock().unwrap(),
                self.channel,
                addr,
                call_user_data,
                &self.params.read().unwrap(),
            )?;

            self.change_state(
                &mut state,
                VcState::WaitCallAccept(Instant::now()),
                true,
                false,
            );
        }

        // Wait for the result.
        let mut state = self.state.0.lock().unwrap();

        while matches!(*state, VcState::WaitCallAccept(_)) {
            state = self.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::DataTransfer(_) => Ok(()),
            VcState::Clear(clear) => {
                let (cause, diagnostic_code) = clear.unwrap_or((0, 0));

                let msg = format!("CLR {cause} - {diagnostic_code}");

                Err(io::Error::new(io::ErrorKind::ConnectionRefused, msg))
            }
            VcState::WaitClearConfirm(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            VcState::OutOfOrder => Err(to_other_io_error("link is out of order".into())),
            _ => panic!("unexpected state"),
        }
    }

    fn clear(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        // Send the clear request packet.
        {
            let mut state = self.state.0.lock().unwrap();

            if !matches!(
                *state,
                VcState::DataTransfer(_) /* | VcState::WaitResetConfirm*/
            ) {
                todo!("invalid state");
            }

            send_clear_request(
                &mut self.send_link.lock().unwrap(),
                self.channel,
                cause,
                diagnostic_code,
                &self.params.read().unwrap(),
            )?;

            self.change_state(
                &mut state,
                VcState::WaitClearConfirm(Instant::now()),
                true,
                true,
            );
        }

        // Wait for the result.
        let mut state = self.state.0.lock().unwrap();

        while matches!(*state, VcState::WaitClearConfirm(_)) {
            state = self.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::Clear(_) => {
                self.change_state(&mut state, VcState::Ready, true, false);

                Ok(())
            }
            VcState::OutOfOrder => Err(to_other_io_error("link is out of order".into())),
            _ => panic!("unexpected state"),
        }
    }

    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        todo!()
    }

    fn recv(&self) -> io::Result<(Bytes, bool)> {
        todo!()
    }

    fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        todo!()
    }

    // ...

    fn send_queued_data(&self) -> io::Result<(usize, usize)> {
        // returns (pkts sent, pkts remaining)...
        todo!()
    }

    fn queue_recv_data(&self, data: X25Data) {
        let mut queue = self.recv_data_queue.0.lock().unwrap();

        queue.push_back(data);
        self.recv_data_queue.1.notify_all();
    }

    fn change_state(
        &self,
        state: &mut VcState,
        new_state: VcState,
        wake_engine_recv: bool,
        wake_user_recv: bool,
    ) {
        *state = new_state;

        self.state.1.notify_all();

        if wake_engine_recv {
            self.engine_recv.notify_all();
        }

        if wake_user_recv {
            self.recv_data_queue.1.notify_all();
        }
    }
}

fn send_call_request(
    link: &mut XotLink,
    channel: u16,
    addr: &X121Addr,
    call_user_data: &Bytes,
    params: &X25Params,
) -> io::Result<X25CallRequest> {
    let call_request = X25CallRequest {
        modulo: params.modulo,
        channel,
        called_addr: addr.clone(),
        calling_addr: params.addr.clone(),
        facilities: params.into(),
        call_user_data: call_user_data.clone(),
    };

    // very hackky...
    let packet = call_request.into();
    send_packet(link, &packet)?;
    let X25Packet::CallRequest(call_request) = packet else { unreachable!() };

    Ok(call_request)
}

fn send_clear_request(
    link: &mut XotLink,
    channel: u16,
    cause: u8,
    diagnostic_code: u8,
    params: &X25Params,
) -> io::Result<X25ClearRequest> {
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
    link: &mut XotLink,
    channel: u16,
    params: &X25Params,
) -> io::Result<X25ClearConfirm> {
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

fn send_packet(link: &mut XotLink, packet: &X25Packet) -> io::Result<()> {
    let mut buf = BytesMut::new();

    packet.encode(&mut buf).map_err(to_other_io_error)?;

    link.send(&buf)
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

    while let Ok((data, qualifier)) = svc.recv() {
        println!("{:?}", data);
    }

    svc.clear(0, 0)?;

    println!("all done!");

    thread::sleep(Duration::from_secs(2));

    Ok(())
}

fn next_seq(seq: u8, modulo: X25Modulo) -> u8 {
    (seq + 1) % (modulo as u8)
}

fn to_other_io_error(e: String) -> io::Error {
    //io::Error::other(e)
    io::Error::new(io::ErrorKind::Other, e)
}
