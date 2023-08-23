use bytes::{Bytes, BytesMut};
use either::Either::{self, Left, Right};
use std::collections::VecDeque;
use std::io;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use tracing_mutex::stdsync::{TracingCondvar, TracingMutex, TracingRwLock};

use crate::x25::{Svc, Vc};
use crate::x29::message::X29PadMessage;
use crate::x3::X3Params;

type RecvQueueMessage = io::Result<Option<Either<Bytes, X29PadSignal>>>;
type IndicateChannelMessage = Vec<(u8, u8)>;

pub struct X29Pad {
    svc: Svc,

    recv_queue: Arc<(TracingMutex<VecDeque<RecvQueueMessage>>, TracingCondvar)>,
    indicate_channel: Arc<TracingMutex<Option<Sender<IndicateChannelMessage>>>>,
}

pub enum X29PadSignal {
    ClearInvitation,
    // ...
}

impl Clone for X29Pad {
    fn clone(&self) -> Self {
        // TODO: is this an appropriate way to do this, it may be better to "split" into a read and
        // write half...
        X29Pad {
            svc: self.svc.clone(),
            recv_queue: Arc::clone(&self.recv_queue),
            indicate_channel: Arc::clone(&self.indicate_channel),
        }
    }
}

// TODO: this is why we INNER...
fn queue_recv(
    recv_queue: &(TracingMutex<VecDeque<RecvQueueMessage>>, TracingCondvar),
    message: RecvQueueMessage,
) {
    recv_queue.0.lock().unwrap().push_back(message);
    recv_queue.1.notify_all();
}

impl X29Pad {
    pub fn new<Q: X3Params + Send + Sync + 'static>(
        svc: Svc,
        params: Arc<TracingRwLock<Q>>,
    ) -> Self {
        let recv_queue = Arc::new((TracingMutex::new(VecDeque::new()), TracingCondvar::new()));
        let indicate_channel = Arc::new(TracingMutex::new(None));

        thread::Builder::new().name("x29_pad".to_string()).spawn({
            let svc = svc.clone();
            let recv_queue = Arc::clone(&recv_queue);

            move || loop {
                let result = svc.recv();

                match result {
                    Ok(Some((data, true))) => {
                        let message = X29PadMessage::decode(data);

                        match message {
                            Ok(X29PadMessage::Set(request)) => {
                                // According to the specification, a response message is only sent
                                // if there are errors. It is not clear to me how that can be
                                // handled by the remote party - how do they know how to long to
                                // wait for an error response versus no response (indicating
                                // success)?
                                if let Some(message) =
                                    set_params(&mut *params.write().unwrap(), &request)
                                {
                                    if let Err(err) = send_message(&svc, message) {
                                        todo!();
                                    }
                                }
                            }
                            Ok(X29PadMessage::Read(request)) => {
                                let message = read_params(&*params.read().unwrap(), &request);

                                if let Err(err) = send_message(&svc, message) {
                                    todo!();
                                }
                            }
                            Ok(X29PadMessage::SetRead(request)) => {
                                let message =
                                    set_read_params(&mut *params.write().unwrap(), &request);

                                if let Err(err) = send_message(&svc, message) {
                                    todo!();
                                }
                            }
                            Ok(X29PadMessage::Indicate(response)) => todo!(),
                            Ok(X29PadMessage::ClearInvitation) => {
                                let signal = X29PadSignal::ClearInvitation;

                                queue_recv(&recv_queue, Ok(Some(Right(signal))));
                            }
                            Err(_) => todo!(),
                        }
                    }
                    Ok(Some((data, false))) => {
                        queue_recv(&recv_queue, Ok(Some(Left(data))));
                    }
                    Ok(None) => {
                        queue_recv(&recv_queue, Ok(None));

                        // TODO: wake up the indicate waiter... actually maybe
                        // we just do that at the end of the loop
                        break;
                    }
                    Err(err) => {
                        queue_recv(&recv_queue, Err(err));

                        // TODO: wake up the indicate waiter... actually maybe
                        // we just do that at the end of the loop
                        break;
                    }
                }
            }
        });

        X29Pad {
            svc,
            recv_queue,
            indicate_channel,
        }
    }

    pub fn send_data(&self, data: Bytes) -> io::Result<()> {
        self.svc.send(data, false)
    }

    pub fn recv(&self) -> io::Result<Option<Either<Bytes, X29PadSignal>>> {
        // TODO: use state to capture when the PAD / connection is DONE!
        let mut queue = self.recv_queue.0.lock().unwrap();

        loop {
            if let Some(message) = queue.pop_front() {
                return message;
            }

            queue = self.recv_queue.1.wait(queue).unwrap();
        }
    }

    pub fn flush(&self) -> io::Result<()> {
        self.svc.flush()
    }

    pub fn into_svc(self) -> Svc {
        self.svc
    }

    pub fn send_clear_invitation(&self) -> io::Result<()> {
        send_message(&self.svc, X29PadMessage::ClearInvitation)
    }

    // TODO: these should return results - using X3ParamError...
    pub fn read_remote_params(&self, request: &[u8]) -> Vec<(u8, u8)> {
        todo!()
    }

    pub fn set_read_remote_params(&self, request: &[(u8, u8)]) -> Vec<(u8, u8)> {
        todo!()
    }
}

fn send_message(svc: &Svc, message: X29PadMessage) -> io::Result<()> {
    svc.flush()?;

    let mut buf = BytesMut::new();

    message.encode(&mut buf);

    svc.send(buf.into(), true)
}

fn read_params<Q: X3Params>(params: &Q, request: &[u8]) -> X29PadMessage {
    let response = if request.is_empty() {
        params.all().to_vec()
    } else {
        request
            .iter()
            .map(|&p| (p, params.get(p).unwrap_or(0x81)))
            .collect()
    };

    X29PadMessage::Indicate(response)
}

fn set_params<Q: X3Params>(params: &mut Q, request: &[(u8, u8)]) -> Option<X29PadMessage> {
    if request.is_empty() {
        // TODO: how do we reset the params here?
        todo!();
    }

    let response: Vec<(u8, u8)> = request
        .iter()
        .map(|&(p, v)| (p, params.set(p, v)))
        .filter_map(|(p, r)| {
            // TODO: improve this, so we can return a correct error code!
            if r.is_err() {
                Some((p, 0x80))
            } else {
                None
            }
        })
        .collect();

    if response.is_empty() {
        return None;
    }

    Some(X29PadMessage::Indicate(response))
}

fn set_read_params<Q: X3Params>(params: &mut Q, request: &[(u8, u8)]) -> X29PadMessage {
    if request.is_empty() {
        // TODO: how do we reset the params here?
        todo!();
    }

    let response: Vec<(u8, u8)> = request
        .iter()
        .map(|&(p, v)| {
            // TODO: improve this, so we can return a correct error code!
            if params.set(p, v).is_err() {
                return (p, 0x80);
            }

            (p, params.get(p).unwrap_or(0x81))
        })
        .collect();

    X29PadMessage::Indicate(response)
}
