//! X.25 virtual circuits.
//!
//! This module provides functionality for handling X.25 virtual circuits.

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::x121::X121Addr;
use crate::x25::facility::X25Facility;
use crate::x25::packet::{
    X25CallAccept, X25CallRequest, X25ClearConfirm, X25ClearRequest, X25Data, X25Packet,
    X25ReceiveReady, X25ResetConfirm, X25ResetRequest,
};
use crate::x25::params::X25Params;
use crate::x25::seq::{next_seq, Window, X25Modulo};
use crate::xot::XotLink;

/// X.25 virtual circuit.
pub trait Vc {
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()>;

    fn recv(&self) -> io::Result<Option<(Bytes, bool)>>;

    fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()>;
}

#[derive(Debug)]
enum VcState {
    Ready,
    WaitCallAccept(Instant),
    DataTransfer(DataTransferState),
    WaitResetConfirm(Instant),
    WaitClearConfirm(Instant, ClearInitiator),

    // These are our custom ones...
    Called(X25CallRequest),
    Cleared(ClearInitiator, Option<X25ClearConfirm>),
    OutOfOrder,
}

#[derive(Debug)]
struct DataTransferState {
    modulo: X25Modulo,
    send_window: Window,
    recv_seq: u8,
}

#[derive(Clone, Debug)]
enum ClearInitiator {
    Local,
    Remote(X25ClearRequest),
    TimeOut(u8),
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

        {
            let inner = &svc.0;

            // Send the call request packet.
            {
                let mut state = inner.state.0.lock().unwrap();

                if !matches!(*state, VcState::Ready) {
                    todo!("invalid state");
                }

                let call_request = create_call_request(channel, addr, call_user_data, params);

                if let Err(err) = inner.send_packet(&call_request.into()) {
                    inner.out_of_order(&mut state, err);
                    inner.engine_wait.notify_all();
                    return Err(to_other_io_error("link is out of order"));
                }

                let next_state = VcState::WaitCallAccept(Instant::now());

                inner.change_state(&mut state, next_state);
                inner.engine_wait.notify_all();
            }

            // Wait for the result.
            let mut state = inner.state.0.lock().unwrap();

            while matches!(*state, VcState::WaitCallAccept(_)) {
                state = inner.state.1.wait(state).unwrap();
            }

            match *state {
                VcState::DataTransfer(_) => { /* This is the expected state */ }
                VcState::Cleared(ClearInitiator::Remote(ref clear_request), _) => {
                    let X25ClearRequest {
                        cause,
                        diagnostic_code,
                        ..
                    } = clear_request;
                    let msg = format!("C:{cause} D:{diagnostic_code}");
                    return Err(io::Error::new(io::ErrorKind::ConnectionReset, msg));
                }
                VcState::WaitClearConfirm(_, ClearInitiator::TimeOut(_))
                | VcState::Cleared(ClearInitiator::TimeOut(_), _) => {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                VcState::OutOfOrder => return Err(to_other_io_error("link is out of order")),
                _ => panic!("unexpected state"),
            }
        }

        Ok(svc)
    }

    pub fn listen(link: XotLink, channel: u16, params: &X25Params) -> io::Result<SvcIncomingCall> {
        let svc = Svc::new(link, channel, params);

        let call_request = {
            let inner = &svc.0;

            let mut state = inner.state.0.lock().unwrap();

            while matches!(*state, VcState::Ready) {
                state = inner.state.1.wait(state).unwrap();
            }

            match *state {
                VcState::Called(ref call_request) => call_request.clone(),
                VcState::OutOfOrder => return Err(to_other_io_error("link is out of order")),
                _ => panic!("unexpected state"),
            }
        };

        Ok(SvcIncomingCall(svc, call_request))
    }

    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        let inner = self.0;

        {
            // Send the clear request packet.
            {
                let mut state = inner.state.0.lock().unwrap();

                if !matches!(
                    *state,
                    VcState::DataTransfer(_) | VcState::WaitResetConfirm(_)
                ) {
                    // TODO: what about if the state was cleared by the peer?
                    // is that an error... we don't get to clear with OUR cause...
                    todo!("invalid state");
                }

                inner.clear_request(&mut state, cause, diagnostic_code, ClearInitiator::Local);
                inner.engine_wait.notify_all();
            }

            // Wait for the result.
            let mut state = inner.state.0.lock().unwrap();

            while matches!(*state, VcState::WaitClearConfirm(_, _)) {
                state = inner.state.1.wait(state).unwrap();
            }

            match *state {
                VcState::Cleared(ClearInitiator::Local, _) => { /* This is the expected state */ }
                VcState::OutOfOrder => return Err(to_other_io_error("link is out of order")),
                _ => panic!("unexpected state"),
            }
        }

        // Even if the client cleared, there may be another thread waiting on
        // recv...
        //
        // TODO: should we move this to "cleared", the function that changes
        // the state?
        inner.recv_data_queue.1.notify_all();

        // TODO: It would be nice to be able to return the XotLink to the caller,
        // but that would require shutting down the receiver thread so that we
        // can take sole ownership of the link...
        //
        // Alternatavely, it may make sense to move the thread into the XotLink
        // so that we can simply return that to the caller.
        //
        // For now we'll just close the socket here, it's not obvious that it even
        // makes sense in the case of an XOT link to reuse it for another call.
        let _ = inner.send_link.lock().unwrap().shutdown();

        Ok(())
    }

    pub fn cleared(&self) -> Option<(u8, u8)> {
        let state = self.0.state.0.lock().unwrap();

        match *state {
            VcState::Cleared(ClearInitiator::Remote(ref clear_request), _) => {
                Some((clear_request.cause, clear_request.diagnostic_code))
            }
            _ => None,
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

            if !matches!(*state, VcState::Called(_)) {
                return Err(to_other_io_error(
                    "other party probably gave up, or link is now out of order",
                ));
            }

            let call_accept = create_call_accept(inner.channel, &inner.params.read().unwrap());

            if let Err(err) = inner.send_packet(&call_accept.into()) {
                inner.out_of_order(&mut state, err);
                inner.engine_wait.notify_all();

                return Err(to_other_io_error("link is out of order"));
            }

            inner.data_transfer(&mut state);
            inner.engine_wait.notify_all();
        }

        Ok(svc)
    }

    pub fn clear(self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        let inner = self.0 .0;

        let mut state = inner.state.0.lock().unwrap();

        if !matches!(*state, VcState::Called(_)) {
            return Err(to_other_io_error(
                "other party probably gave up, or link is now out of order",
            ));
        }

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
            inner.engine_wait.notify_all();

            return Err(to_other_io_error("link is out of order"));
        }

        inner.cleared(&mut state, ClearInitiator::Local, None);
        inner.engine_wait.notify_all();

        Ok(())
    }
}

impl Vc for Svc {
    fn send(&self, user_data: Bytes, qualifier: bool) -> io::Result<()> {
        let inner = &self.0;

        // TODO: check we are connected

        let packet_size = inner.params.read().unwrap().send_packet_size;

        {
            let mut queue = inner.send_data_queue.0.lock().unwrap();

            let mut packets = user_data.chunks(packet_size).peekable();

            while let Some(packet) = packets.next() {
                let is_last = packets.peek().is_none();

                queue.push_back(SendData {
                    user_data: Bytes::copy_from_slice(packet),
                    qualifier,
                    more: !is_last,
                });
            }
        }

        {
            let mut state = inner.state.0.lock().unwrap();

            inner.send_queued_data(&mut state);

            // TODO: check the state (could be out of order now) and alert the
            // client, probably...
        }

        Ok(())
    }

    fn recv(&self) -> io::Result<Option<(Bytes, bool)>> {
        let inner = &self.0;

        let mut queue = inner.recv_data_queue.0.lock().unwrap();

        loop {
            {
                let state = inner.state.0.lock().unwrap();

                if let Some(data) = pop_complete_data(&mut queue) {
                    return Ok(Some(data));
                }

                match *state {
                    VcState::DataTransfer(_) => { /* Try again */ }
                    VcState::Cleared(ClearInitiator::Local, _)
                    | VcState::Cleared(ClearInitiator::Remote(_), _) => {
                        return Ok(None);
                    }
                    VcState::Cleared(ClearInitiator::TimeOut(_), _) => {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    VcState::OutOfOrder => return Err(to_other_io_error("link is out of order")),
                    _ => panic!("unexpected state"),
                }
            }

            queue = inner.recv_data_queue.1.wait(queue).unwrap();
        }
    }

    fn reset(&self, cause: u8, diagnostic_code: u8) -> io::Result<()> {
        let inner = &self.0;

        // Send the reset request packet.
        {
            let mut state = inner.state.0.lock().unwrap();

            if !matches!(*state, VcState::DataTransfer(_)) {
                // TODO: what states is this valid in?
                todo!("invalid state");
            }

            inner.reset_request(&mut state, cause, diagnostic_code);
            inner.engine_wait.notify_all();
        }

        // Wait for the result.
        let mut state = inner.state.0.lock().unwrap();

        while matches!(*state, VcState::WaitResetConfirm(_)) {
            state = inner.state.1.wait(state).unwrap();
        }

        match *state {
            VcState::DataTransfer(_) => { /* This is the expected state */ }
            VcState::WaitClearConfirm(_, ClearInitiator::TimeOut(_))
            | VcState::Cleared(ClearInitiator::TimeOut(_), _) => {
                return Err(io::Error::from(io::ErrorKind::TimedOut))
            }
            VcState::OutOfOrder => return Err(to_other_io_error("link is out of order")),
            _ => panic!("unexpected state"),
        };

        Ok(())
    }
}

impl Clone for Svc {
    fn clone(&self) -> Self {
        // TODO: is an appropriate way to do this, it may be better to "split" into a read
        // and write half.
        Svc(Arc::clone(&self.0))
    }
}

struct VcInner {
    send_link: Arc<Mutex<XotLink>>,
    engine_wait: Arc<Condvar>,
    channel: u16,
    state: Arc<(Mutex<VcState>, Condvar)>,
    params: Arc<RwLock<X25Params>>,
    send_data_queue: Arc<(Mutex<VecDeque<SendData>>, Condvar)>,
    recv_data_queue: Arc<(Mutex<VecDeque<X25Data>>, Condvar)>,
}

struct SendData {
    user_data: Bytes,
    qualifier: bool,
    more: bool,
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

            // Handle a XOT link error, otherwise pass along the packet.
            let packet = match packet.transpose() {
                Ok(packet) => packet,
                Err(err) => {
                    let mut state = self.state.0.lock().unwrap();

                    self.out_of_order(&mut state, err);
                    self.recv_data_queue.1.notify_all();
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
                        if let Some(X25Packet::CallRequest(call_request)) = packet {
                            let mut params = self.params.write().unwrap();

                            // TODO: can negotiation "fail"?
                            *params = negotiate_called_params(&call_request, &params);

                            self.change_state(&mut state, VcState::Called(call_request));
                        }
                    }
                    VcState::Called(_) => {
                        match packet {
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.cleared(
                                    &mut state,
                                    ClearInitiator::Remote(clear_request),
                                    None,
                                );
                            }
                            _ => { /* TODO: ignore? */ }
                        }
                    }
                    VcState::WaitCallAccept(start_time) => {
                        let elapsed = start_time.elapsed();
                        let X25Params { t21, t23, .. } = *self.params.read().unwrap();

                        timeout = t21; // TODO: <- backup

                        match packet {
                            Some(X25Packet::CallAccept(call_accept)) => {
                                {
                                    let mut params = self.params.write().unwrap();

                                    // TODO: can negotiation "fail"?
                                    *params = negotiate_calling_params(&call_accept, &params);
                                }

                                self.data_transfer(&mut state);
                            }
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.cleared(
                                    &mut state,
                                    ClearInitiator::Remote(clear_request),
                                    None,
                                );
                            }
                            Some(_) => { /* TODO: Ignore? */ }
                            None if elapsed > t21 => {
                                println!("T21 timeout, sending clear request...");

                                self.clear_request(
                                    &mut state,
                                    19, // Local procedure error
                                    49, // Time expired for incoming call
                                    ClearInitiator::TimeOut(21),
                                );

                                timeout = t23;
                            }
                            None => timeout = t21 - elapsed,
                        }
                    }
                    VcState::DataTransfer(ref mut data_transfer_state) => {
                        match packet {
                            Some(X25Packet::Data(data)) => 'packet: {
                                if !data_transfer_state.update_recv_seq(data.send_seq) {
                                    self.reset_request(
                                        &mut state, 5, // Local procedure error
                                        1, // Invalid send sequence
                                    );

                                    break 'packet;
                                }

                                if !data_transfer_state.update_send_window(data.recv_seq) {
                                    self.reset_request(
                                        &mut state, 5, // Local procedure error
                                        2, // Invalid receive sequence
                                    );

                                    break 'packet;
                                }

                                // TODO: have this queue_recv_data function check that the
                                // qualifier is consistent across any "more" packets... it can also
                                // check the data length!
                                self.queue_recv_data(data);

                                let (sent_count, _) = self.send_queued_data(&mut state);

                                if !matches!(*state, VcState::DataTransfer(_)) {
                                    break 'packet;
                                }

                                // TODO: clean all of this up and work out if
                                // sometimes, we should hold off...
                                let is_local_ready = true;

                                if sent_count == 0 && is_local_ready {
                                    self.receive_ready(&mut state);
                                }
                            }
                            Some(X25Packet::ReceiveReady(receive_ready)) => 'packet: {
                                if !data_transfer_state.update_send_window(receive_ready.recv_seq) {
                                    self.reset_request(
                                        &mut state, 5, // Local procedure error
                                        2, // Invalid receive sequence
                                    );

                                    break 'packet;
                                }

                                self.send_queued_data(&mut state);
                            }
                            Some(X25Packet::ResetRequest(_)) => {
                                self.reset_confirm(&mut state);
                            }
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.clear_confirm(&mut state, clear_request);
                                self.recv_data_queue.1.notify_all();
                            }
                            Some(_) => { /* TODO: Ignore? */ }
                            None => {}
                        }
                    }
                    VcState::WaitResetConfirm(start_time) => {
                        let elapsed = start_time.elapsed();
                        let X25Params { t22, t23, .. } = *self.params.read().unwrap();

                        timeout = t22; // TODO: backup!

                        match packet {
                            Some(X25Packet::ResetConfirm(_)) => {
                                self.data_transfer(&mut state);
                            }
                            Some(X25Packet::ResetRequest(_)) => {
                                self.reset_confirm(&mut state);
                            }
                            Some(X25Packet::ClearRequest(clear_request)) => {
                                self.clear_confirm(&mut state, clear_request);
                                self.recv_data_queue.1.notify_all();
                            }
                            None if elapsed > t22 => {
                                println!("T22 timeout, sending clear request...");

                                self.clear_request(
                                    &mut state,
                                    19, // Local procedure error
                                    51, // Time expired for reset request
                                    ClearInitiator::TimeOut(22),
                                );

                                timeout = t23;
                            }
                            None => timeout = t22 - elapsed,
                            Some(_) => { /* TODO: Ignore? Or, do you think I need to send a reset request again!!! */
                            }
                        }
                    }
                    VcState::WaitClearConfirm(start_time, ref initiator) => {
                        let elapsed = start_time.elapsed();
                        let t23 = self.params.read().unwrap().t23;

                        timeout = t23;

                        match packet {
                            Some(X25Packet::ClearConfirm(clear_confirm)) => {
                                let initiator = initiator.clone();

                                self.cleared(&mut state, initiator, Some(clear_confirm));
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
                    VcState::Cleared(_, _) | VcState::OutOfOrder => {
                        panic!("unexpected state")
                    }
                }

                // Exit loop if we are in a terminal state.
                if matches!(*state, VcState::Cleared(_, _) | VcState::OutOfOrder) {
                    break;
                }
            }

            // Only wait if the queue is empty, otherwise don't wait as we won't
            // receive a wakeup call.
            if recv_queue.is_empty() {
                (recv_queue, _) = self.engine_wait.wait_timeout(recv_queue, timeout).unwrap();
            }
        }

        println!("VC engine done!");
    }

    fn data_transfer(&self, state: &mut VcState) {
        let X25Params {
            modulo,
            send_window_size,
            ..
        } = *self.params.read().unwrap();

        let next_state = VcState::DataTransfer(DataTransferState {
            modulo,
            send_window: Window::new(send_window_size, modulo),
            recv_seq: 0,
        });

        self.change_state(state, next_state);
    }

    fn cleared(
        &self,
        state: &mut VcState,
        initiator: ClearInitiator,
        clear_confirm: Option<X25ClearConfirm>,
    ) {
        let next_state = VcState::Cleared(initiator, clear_confirm);

        self.change_state(state, next_state);
    }

    fn out_of_order(&self, state: &mut VcState, err: io::Error) {
        let next_state = VcState::OutOfOrder;

        self.change_state(state, next_state);
    }

    fn clear_request(
        &self,
        state: &mut VcState,
        cause: u8,
        diagnostic_code: u8,
        initiator: ClearInitiator,
    ) {
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
            let next_state = VcState::WaitClearConfirm(Instant::now(), initiator);

            self.change_state(state, next_state);
        }
    }

    fn clear_confirm(&self, state: &mut VcState, clear_request: X25ClearRequest) {
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
            self.cleared(state, ClearInitiator::Remote(clear_request), None);
        }
    }

    fn reset_request(&self, state: &mut VcState, cause: u8, diagnostic_code: u8) {
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

            self.change_state(state, next_state);
        }
    }

    fn reset_confirm(&self, state: &mut VcState) {
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

    fn send_queued_data(&self, state: &mut VcState) -> (usize, usize) {
        let data_transfer_state = match *state {
            VcState::DataTransfer(ref mut data_transfer_state) => data_transfer_state,
            _ => panic!("unexpected state"),
        };

        let mut queue = self.send_data_queue.0.lock().unwrap();

        let mut count = 0;

        while !queue.is_empty() && data_transfer_state.send_window.is_open() {
            let SendData {
                user_data,
                qualifier,
                more,
            } = queue.front().unwrap();

            let data = X25Data {
                modulo: self.params.read().unwrap().modulo,
                channel: self.channel,
                send_seq: data_transfer_state.send_window.seq(),
                recv_seq: data_transfer_state.recv_seq,
                qualifier: *qualifier,
                delivery: false,
                more: *more,
                user_data: user_data.clone(),
            };

            if let Err(err) = self.send_packet(&data.into()) {
                self.out_of_order(state, err);
                break;
            }

            queue.pop_front();
            data_transfer_state.send_window.incr();

            count += 1;
        }

        (count, queue.len())
    }

    fn receive_ready(&self, state: &mut VcState) {
        let recv_seq = match *state {
            VcState::DataTransfer(ref data_transfer_state) => data_transfer_state.recv_seq,
            _ => panic!("unexpected state"),
        };

        let receive_ready = X25ReceiveReady {
            modulo: self.params.read().unwrap().modulo,
            channel: self.channel,
            recv_seq,
        };

        if let Err(err) = self.send_packet(&receive_ready.into()) {
            self.out_of_order(state, err);
        }
    }

    fn queue_recv_data(&self, data: X25Data) {
        let mut queue = self.recv_data_queue.0.lock().unwrap();

        queue.push_back(data);
        self.recv_data_queue.1.notify_all();
    }

    fn change_state(&self, state: &mut VcState, new_state: VcState) {
        *state = new_state;
        self.state.1.notify_all();
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

impl DataTransferState {
    #[must_use]
    fn update_recv_seq(&mut self, seq: u8) -> bool {
        if seq != self.recv_seq {
            return false;
        }

        self.recv_seq = next_seq(seq, self.modulo);

        true
    }

    #[must_use]
    fn update_send_window(&mut self, seq: u8) -> bool {
        self.send_window.update_start(seq)
    }
}

fn pop_complete_data(queue: &mut VecDeque<X25Data>) -> Option<(Bytes, bool)> {
    if queue.is_empty() {
        return None;
    }

    let index = queue.iter().position(|d| !d.more)?;

    let packets: Vec<X25Data> = queue.drain(0..=index).collect();

    let user_data_len: usize = packets.iter().map(|p| p.user_data.len()).sum();

    let mut user_data = BytesMut::with_capacity(user_data_len);
    let mut qualifier = false;

    for packet in packets.into_iter() {
        user_data.put(packet.user_data);
        qualifier = packet.qualifier;
    }

    Some((user_data.freeze(), qualifier))
}

fn to_other_io_error(e: &str) -> io::Error {
    let msg: String = e.into();
    //io::Error::other(e)
    io::Error::new(io::ErrorKind::Other, msg)
}

fn split_xot_link(link: XotLink) -> (XotLink, XotLink) {
    // crazy hack...
    let tcp_stream = link.into_stream();

    (
        XotLink::new(tcp_stream.try_clone().unwrap()),
        XotLink::new(tcp_stream),
    )
}
