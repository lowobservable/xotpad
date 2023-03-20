//! X.25 virtual circuits.
//!
//! This module provides functionality for handling X.25 virtual circuits.

use bytes::{Bytes, BytesMut};
use either::Either;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::x121::X121Addr;
use crate::x25::facility::X25Facility;
use crate::x25::packet::{
    X25CallAccept, X25CallRequest, X25ClearConfirm, X25ClearRequest, X25Data, X25Packet,
    X25ResetConfirm, X25ResetRequest,
};
use crate::x25::params::{X25Modulo, X25Params};
use crate::xot::XotLink;

/// X.25 virtual circuit.
pub trait Vc {
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()>;

    fn recv(&self) -> io::Result<(Bytes, bool)>;

    fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()>;
}

#[derive(Debug)]
enum VcState {
    Ready,
    WaitCallAccept(Instant),
    DataTransfer(DataTransferState),
    WaitResetConfirm(Instant),
    WaitClearConfirm(Instant),

    // These are our custom ones...
    Called(X25CallRequest),
    Cleared(Option<Either<X25ClearRequest, X25ClearConfirm>>),
    OutOfOrder,
}

#[derive(Debug)]
struct DataTransferState {
    send_seq: u8,
    recv_seq: u8,
    // ...
}

/// X.25 _switched_ virtual circuit, or _virtual call_.
pub struct Svc(Arc<VcInner>);

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

    pub fn listen(link: XotLink, channel: u16, params: &X25Params) -> io::Result<SvcIncomingCall> {
        let svc = Svc::new(link, channel, params);

        let call_request = svc.0.listen()?;

        Ok(SvcIncomingCall(svc, call_request))
    }

    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<XotLink> {
        self.0.clear(cause, diagnostic_code)?;

        if let Ok(inner) = Arc::try_unwrap(self.0) {
            Ok(inner.close())
        } else {
            todo!("uuhh?")
        }
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

/// Incoming X.25 _call_ that can be accepted, or cleared.
pub struct SvcIncomingCall(Svc, X25CallRequest);

impl SvcIncomingCall {
    pub fn request(&self) -> &X25CallRequest {
        &self.1
    }

    pub fn accept(self) -> io::Result<Svc> {
        let svc = self.0;

        {
            let inner = &svc.0;

            let mut state = inner.state.0.lock().unwrap();

            // TODO: we should check state here, it may have changed...

            let call_accept = create_call_accept(inner.channel, &inner.params.read().unwrap());

            if let Err(err) = inner.send_packet(&call_accept.into()) {
                inner.out_of_order(&mut state, err);
                return Err(to_other_io_error("todo!"));
            } else {
                inner.data_transfer(&mut state);
            }
        }

        Ok(svc)
    }

    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        let inner = self.0 .0;

        let mut state = inner.state.0.lock().unwrap();

        // TODO: we should check state here, it may have changed...

        let clear_request = X25ClearRequest {
            modulo: inner.params.read().unwrap().modulo,
            channel: inner.channel,
            cause,
            diagnostic_code,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            clear_user_data: Bytes::new(),
        };

        if let Err(err) = inner.send_packet(&clear_request.into()) {
            inner.out_of_order(&mut state, err);
            return Err(to_other_io_error("todo!"));
        } else {
            inner.cleared(&mut state, None);
        }

        Ok(())
    }
}

impl Vc for Svc {
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        self.0.send(user_data, qualifier)
    }

    fn recv(&self) -> io::Result<(Bytes, bool)> {
        self.0.recv()
    }

    fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        self.0.reset(cause, diagnostic_code)
    }
}

struct VcInner {
    send_link: Arc<Mutex<XotLink>>, // does this really need to have a lock?
    engine_wait: Arc<Condvar>,
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
            engine_wait: Arc::new(Condvar::new()),
            channel,
            state: Arc::new((Mutex::new(state), Condvar::new())),
            params: Arc::new(RwLock::new(params.clone())),
            send_data_queue: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
            recv_data_queue: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
        }
    }

    fn close(self) -> XotLink {
        if let Ok(link) = Arc::try_unwrap(self.send_link) {
            link.into_inner().unwrap()
        } else {
            todo!("uuuhhh")
        }
    }

    fn run(&self, mut recv_link: XotLink, barrier: Arc<Barrier>) {
        println!("VC engine starting...");

        // Create another thread that reads packets, this will allow the main loop
        // wait to be interrupted while the XOT socket read is blocked.
        let recv_queue = Arc::new(Mutex::new(VecDeque::<io::Result<Bytes>>::new()));

        thread::spawn({
            let recv_queue = Arc::clone(&recv_queue);
            let engine_wait = Arc::clone(&self.engine_wait);

            move || {
                loop {
                    let packet = recv_link.recv();

                    let is_err = packet.is_err();

                    recv_queue.lock().unwrap().push_back(packet);
                    engine_wait.notify_all();

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
            let mut timeout = Duration::from_secs(100_000); // TODO

            let packet = recv_queue.pop_front();

            dbg!(&packet);

            // Handle a XOT link error, otherwise pass along the packet.
            let packet = match packet.transpose() {
                Ok(packet) => packet,
                Err(err) => {
                    let mut state = self.state.0.lock().unwrap();

                    self.out_of_order(&mut state, err);
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
                    VcState::Ready => {
                        match packet {
                            Some(X25Packet::CallRequest(call_request)) => {
                                let mut params = self.params.write().unwrap();

                                // TODO: can negotiation "fail"?
                                *params = negotiate_called_params(&call_request, &params);

                                self.change_state(
                                    &mut state,
                                    VcState::Called(call_request),
                                    false,
                                    false,
                                );
                            }
                            _ => { /* TODO: Ignore */ }
                        }
                    }
                    VcState::WaitCallAccept(start_time) => {
                        let elapsed = start_time.elapsed();
                        let X25Params { t21, t23, .. } = *self.params.read().unwrap();

                        match packet {
                            Some(X25Packet::CallAccept(call_accept)) => {
                                let mut params = self.params.write().unwrap();

                                // TODO: can negotiation "fail"?
                                *params = negotiate_calling_params(&call_accept, &params);

                                self.data_transfer(&mut state);
                            }
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.cleared(&mut state, Some(Either::Left(clear_request)));
                            }
                            Some(_) => { /* TODO: Ignore? */ }
                            None if elapsed > t21 => {
                                println!("T21 timeout, sending clear request...");

                                self.send_clear_request(
                                    &mut state, 19, // Local procedure error
                                    49, // Time expired for incoming call
                                );

                                timeout = t23;
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
                            Some(X25Packet::ResetRequest(_)) => {
                                println!("RESET");

                                self.send_reset_confirm(&mut state);
                            }
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.send_clear_confirm(clear_request, &mut state);
                            }
                            Some(_) => { /* TODO: Ignore? */ }
                            None => {}
                        }
                    }
                    VcState::WaitResetConfirm(start_time) => {
                        let elapsed = start_time.elapsed();
                        let t22 = self.params.read().unwrap().t23;

                        match packet {
                            Some(X25Packet::ResetConfirm(_)) => {
                                println!("RESET");

                                self.data_transfer(&mut state);
                            }
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.send_clear_confirm(clear_request, &mut state);
                            }
                            None if elapsed > t22 => {
                                println!("T22 timeout");

                                todo!("what does Cisco do?");
                            }
                            None => timeout = t22 - elapsed,
                            Some(_) => { /* TODO: Ignore? */ }
                        }
                    }
                    VcState::WaitClearConfirm(start_time) => {
                        let elapsed = start_time.elapsed();
                        let t23 = self.params.read().unwrap().t23;

                        match packet {
                            Some(X25Packet::ClearConfirm(clear_confirm)) => {
                                self.cleared(&mut state, Some(Either::Right(clear_confirm)));
                            }
                            Some(X25Packet::ClearRequest(_)) => todo!(),
                            Some(_) => { /* TODO: Ignore? */ }
                            None if elapsed > t23 => {
                                println!("T23 timeout");

                                // TODO:
                                // For a timeout on a "call request timeout" that leads to a clear
                                // request Cisco sends "time expired for clear indication" twice (2
                                // retries of THIS state).
                                //
                                // what does it do for a user initiated clear?
                                let err = io::Error::from(io::ErrorKind::TimedOut);

                                self.out_of_order(&mut state, err);
                                break;
                            }
                            None => timeout = t23 - elapsed,
                        }
                    }
                    VcState::Called(_) => {
                        todo!();
                    }
                    VcState::Cleared(_) | VcState::OutOfOrder => {
                        panic!("unexpected state")
                    }
                }

                // Exit loop if we are in a terminal state.
                if matches!(*state, VcState::Cleared(_) | VcState::OutOfOrder) {
                    break;
                }
            }

            (recv_queue, _) = self.engine_wait.wait_timeout(recv_queue, timeout).unwrap();
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

            let call_request = create_call_request(
                self.channel,
                addr,
                call_user_data,
                &self.params.read().unwrap(),
            );

            if let Err(err) = self.send_packet(&call_request.into()) {
                self.out_of_order(&mut state, err);
                return Err(to_other_io_error("todo!"));
            } else {
                let next_state = VcState::WaitCallAccept(Instant::now());

                self.change_state(&mut state, next_state, true, false);
            }
        }

        // Wait for the result.
        let mut state = self.state.0.lock().unwrap();

        while matches!(*state, VcState::WaitCallAccept(_)) {
            state = self.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::DataTransfer(_) => Ok(()),
            VcState::Cleared(Some(Either::Left(ref clear_request))) => {
                let X25ClearRequest {
                    cause,
                    diagnostic_code,
                    ..
                } = clear_request;

                let msg = format!("CLR {cause} - {diagnostic_code}");

                Err(io::Error::new(io::ErrorKind::ConnectionRefused, msg))
            }
            VcState::Cleared(Some(Either::Right(_))) => {
                // If we receive a clear confirm as a result of making a call,
                // it should only be because we experienced a call request
                // timeout - we did receive a clear confirm to our subsequent
                // clear request... so we should consider it a timeout.
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
            VcState::WaitClearConfirm(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            VcState::OutOfOrder => Err(to_other_io_error("link is out of order")),
            _ => panic!("unexpected state"),
        }
    }

    fn listen(&self) -> io::Result<X25CallRequest> {
        let mut state = self.state.0.lock().unwrap();

        while matches!(*state, VcState::Ready) {
            state = self.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::Called(ref call_request) => Ok(call_request.clone()),
            VcState::OutOfOrder => Err(to_other_io_error("link is out of order")),
            _ => panic!("unexpected state"),
        }
    }

    fn clear(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        // Send the clear request packet.
        {
            let mut state = self.state.0.lock().unwrap();

            if !matches!(
                *state,
                VcState::DataTransfer(_) | VcState::WaitResetConfirm(_)
            ) {
                // TODO: what about if the state was cleared by the peer?
                // is that an error... we don't get to clear with OUR cause...
                todo!("invalid state");
            }

            self.send_clear_request(&mut state, cause, diagnostic_code);
        }

        // Wait for the result.
        let mut state = self.state.0.lock().unwrap();

        while matches!(*state, VcState::WaitClearConfirm(_)) {
            state = self.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::Cleared(_) => {
                // TODO: We probably shouldn't do this... just leave it in Cleared
                self.change_state(&mut state, VcState::Ready, true, false);

                Ok(())
            }
            VcState::OutOfOrder => Err(to_other_io_error("link is out of order")),
            _ => panic!("unexpected state"),
        }
    }

    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        todo!()
    }

    fn recv(&self) -> io::Result<(Bytes, bool)> {
        let mut queue = self.recv_data_queue.0.lock().unwrap();

        loop {
            // TODO: confirm this doesn't cause a deadlock...
            // trying this wihtout the need to clone the state...
            {
                let state = self.state.0.lock().unwrap();

                if let Some(data) = queue.pop_front() {
                    // TODO: this should "reconstruct" MORE packets...
                    return Ok((data.user_data, data.qualifier));
                }

                // There is no data...
                match *state {
                    VcState::DataTransfer(_) => { /* we'll try again below, but outside of this lock */
                    }
                    VcState::Cleared(Some(Either::Left(ref clear_request))) => {
                        let X25ClearRequest {
                            cause,
                            diagnostic_code,
                            ..
                        } = clear_request;

                        let msg = format!("CLR {cause} - {diagnostic_code}");

                        return Err(io::Error::new(io::ErrorKind::ConnectionReset, msg));
                    }
                    VcState::Cleared(Some(Either::Right(_))) => {
                        todo!("need to think about why this could happen")
                    }
                    VcState::OutOfOrder => return Err(to_other_io_error("link is out of order")),
                    _ => panic!("unexpected state"),
                }
            }

            queue = self.recv_data_queue.1.wait(queue).unwrap();
        }
    }

    fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        // Send the reset request packet.
        {
            let mut state = self.state.0.lock().unwrap();

            if !matches!(*state, VcState::DataTransfer(_)) {
                // TODO: what about if the state was cleared by the peer?
                // is that an error... we don't get to clear with OUR cause...
                todo!("invalid state");
            }

            self.send_reset_request(&mut state, cause, diagnostic_code);
        }

        // Wait for the result.
        let mut state = self.state.0.lock().unwrap();

        while matches!(*state, VcState::WaitResetConfirm(_)) {
            state = self.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::DataTransfer(_) => Ok(()),
            VcState::Cleared(Some(Either::Right(_))) => {
                // If we receive a clear confirm as a result of reset,
                // it should only be because we experienced a reset request
                // timeout - we did receive a clear confirm to our subsequent
                // clear request... so we should consider it a timeout.
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
            VcState::WaitClearConfirm(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            VcState::OutOfOrder => Err(to_other_io_error("link is out of order")),
            _ => panic!("unexpected state"),
        }
    }

    // ...

    fn data_transfer(&self, state: &mut VcState) {
        let next_state = VcState::DataTransfer(DataTransferState {
            send_seq: 0,
            recv_seq: 0,
            // ...
        });

        self.change_state(state, next_state, false, false);
    }

    fn out_of_order(&self, state: &mut VcState, err: io::Error) {
        let next_state = VcState::OutOfOrder;

        self.change_state(state, next_state, false, true);
    }

    fn cleared(
        &self,
        state: &mut VcState,
        initiator: Option<Either<X25ClearRequest, X25ClearConfirm>>,
    ) {
        let next_state = VcState::Cleared(initiator);

        self.change_state(state, next_state, false, true);
    }

    fn send_clear_request(&self, state: &mut VcState, cause: u8, diagnostic_code: u8) {
        let clear_request = X25ClearRequest {
            modulo: self.params.read().unwrap().modulo,
            channel: self.channel,
            cause,
            diagnostic_code,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
            clear_user_data: Bytes::new(),
        };

        if let Err(err) = self.send_packet(&clear_request.into()) {
            self.out_of_order(state, err);
        } else {
            let next_state = VcState::WaitClearConfirm(Instant::now());

            self.change_state(state, next_state, false, false);
        }
    }

    fn send_clear_confirm(&self, clear_request: X25ClearRequest, state: &mut VcState) {
        let clear_confirm = X25ClearConfirm {
            modulo: self.params.read().unwrap().modulo,
            channel: self.channel,
            called_addr: X121Addr::null(),
            calling_addr: X121Addr::null(),
            facilities: Vec::new(),
        };

        if let Err(err) = self.send_packet(&clear_confirm.into()) {
            self.out_of_order(state, err);
        } else {
            self.cleared(state, Some(Either::Left(clear_request)));
        }
    }

    fn send_reset_request(&self, state: &mut VcState, cause: u8, diagnostic_code: u8) {
        let reset_request = X25ResetRequest {
            modulo: self.params.read().unwrap().modulo,
            channel: self.channel,
            cause,
            diagnostic_code,
        };

        if let Err(err) = self.send_packet(&reset_request.into()) {
            self.out_of_order(state, err);
        } else {
            let next_state = VcState::WaitResetConfirm(Instant::now());

            self.change_state(state, next_state, false, false);
        }
    }

    fn send_reset_confirm(&self, state: &mut VcState) {
        let reset_confirm = X25ResetConfirm {
            modulo: self.params.read().unwrap().modulo,
            channel: self.channel,
        };

        if let Err(err) = self.send_packet(&reset_confirm.into()) {
            self.out_of_order(state, err);
        } else {
            self.data_transfer(state);
        }
    }

    fn change_state(
        &self,
        state: &mut VcState,
        new_state: VcState,
        wake_engine: bool,
        wake_recv: bool,
    ) {
        *state = new_state;

        self.state.1.notify_all();

        if wake_engine {
            self.engine_wait.notify_all();
        }

        if wake_recv {
            self.recv_data_queue.1.notify_all();
        }
    }

    fn send_queued_data(&self) -> io::Result<(usize, usize)> {
        // returns (pkts sent, pkts remaining)...
        todo!()
    }

    fn queue_recv_data(&self, data: X25Data) {
        let mut queue = self.recv_data_queue.0.lock().unwrap();

        queue.push_back(data);
        self.recv_data_queue.1.notify_all();
    }

    fn send_packet(&self, packet: &X25Packet) -> io::Result<()> {
        let mut buf = BytesMut::new();

        packet.encode(&mut buf).map_err(|e| to_other_io_error(&e))?;

        self.send_link.lock().unwrap().send(&buf)
    }
}

fn create_call_request(
    channel: u16,
    addr: &X121Addr,
    call_user_data: &Bytes,
    params: &X25Params,
) -> X25CallRequest {
    let facilities = vec![
        X25Facility::PacketSize {
            from_called: 128,  // TODO
            from_calling: 128, // TODO
        },
        X25Facility::WindowSize {
            from_called: 2,  // TODO
            from_calling: 2, // TODO
        },
    ];

    X25CallRequest {
        modulo: params.modulo,
        channel,
        called_addr: addr.clone(),
        calling_addr: params.addr.clone(),
        facilities,
        call_user_data: call_user_data.clone(),
    }
}

fn create_call_accept(channel: u16, params: &X25Params) -> X25CallAccept {
    let facilities = vec![
        X25Facility::PacketSize {
            from_called: 128,  // TODO
            from_calling: 128, // TODO
        },
        X25Facility::WindowSize {
            from_called: 2,  // TODO
            from_calling: 2, // TODO
        },
    ];

    X25CallAccept {
        modulo: params.modulo,
        channel,
        called_addr: X121Addr::null(),
        calling_addr: X121Addr::null(),
        facilities,
        called_user_data: Bytes::new(),
    }
}

// TODO: can we make this consume the inncombin params? No more clone?
fn negotiate_calling_params(call_accept: &X25CallAccept, params: &X25Params) -> X25Params {
    let params = params.clone();

    X25Params {
        addr: params.addr.clone(),
        modulo: call_accept.modulo,
        ..params
    }
}

// TODO: can we make this consume the inncombin params? No more clone?
fn negotiate_called_params(call_request: &X25CallRequest, params: &X25Params) -> X25Params {
    let params = params.clone();

    X25Params {
        addr: params.addr.clone(),
        modulo: call_request.modulo, // TODO: check Cisco behavior!
        ..params
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

fn next_seq(seq: u8, modulo: X25Modulo) -> u8 {
    (seq + 1) % (modulo as u8)
}

fn to_other_io_error(e: &str) -> io::Error {
    let msg: String = e.into();
    //io::Error::other(e)
    io::Error::new(io::ErrorKind::Other, msg)
}
