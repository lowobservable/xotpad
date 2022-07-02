use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::io;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::x121::X121Address;
use crate::x25::packet::{
    format_packet, parse_packet, X25CallAccepted, X25CallRequest, X25ClearConfirmation,
    X25ClearRequest, X25Data, X25Modulo, X25Packet, X25PacketType, X25ReceiveReady,
    X25ResetConfirmation, X25ResetRequest,
};
use crate::xot::XotCodec;

// TODO: how can I get rid of the dependency on TcpStream and XotCodec here?
pub struct X25LogicalChannel {
    xot_framed: Framed<TcpStream, XotCodec>,
    state: X25LogicalChannelState,
    modulo: X25Modulo,

    send_max_packet_size: usize,
    send_window_size: u16,
    send_queue: VecDeque<(Bytes, bool)>,
    send_sequence: u16,

    receive_sequence: u16,

    is_remote_ready: bool,

    // TODO: clean these up...
    xxx_un_rrd_packets: u32,
    xxx_lower_bound: u16,
}

#[derive(Debug, PartialEq)]
enum X25LogicalChannelState {
    // TODO: X.25 p1
    Ready,

    // TODO: X.25 p2 / p3
    AwaitingCallAccepted,

    // TODO: X.25 p4
    DataTransfer,

    // TODO: X.25 d2 / d3
    AwaitingResetConfirmation,

    // TODO: X.25 p6 / p7
    AwaitingClearConfirmation,
}

impl X25LogicalChannel {
    pub fn new(xot_framed: Framed<TcpStream, XotCodec>, modulo: X25Modulo) -> Self {
        Self {
            xot_framed,
            state: X25LogicalChannelState::Ready,
            modulo,
            send_max_packet_size: 128,
            send_window_size: 2,
            send_queue: VecDeque::new(),
            send_sequence: 0,
            receive_sequence: 0,
            is_remote_ready: true,
            xxx_un_rrd_packets: 0,
            xxx_lower_bound: 0,
        }
    }

    pub async fn call(
        &mut self,
        called_address: &X121Address,
        calling_address: &X121Address,
    ) -> io::Result<X25Packet> {
        if self.state != X25LogicalChannelState::Ready {
            panic!("invalid state"); // TODO
        }

        let call_request = X25Packet::CallRequest(X25CallRequest {
            modulo: self.modulo,
            channel: 1,
            called_address: called_address.clone(), // TODO, can this be a ref?
            calling_address: calling_address.clone(),
            facilities: Some(Bytes::from_static(b"B\x07\x07C\x02\x02")), // TODO
            call_user_data: Some(Bytes::from_static(b"\x01\0\0\0")),     // TODO
        });

        self.state = X25LogicalChannelState::AwaitingCallAccepted;

        // reset all the other things - maybe we just track them in data state?

        self.send_packet(call_request).await?;

        self.wait_for_packet(&[X25PacketType::CallAccepted, X25PacketType::ClearRequest])
            .await
    }

    pub async fn wait_for_call(&mut self) -> io::Result<X25CallRequest> {
        if self.state != X25LogicalChannelState::Ready {
            panic!("invalid state"); // TODO
        }

        let packet = self.wait_for_packet(&[X25PacketType::CallRequest]).await?;

        if let X25Packet::CallRequest(call_request) = packet {
            return Ok(call_request);
        }

        panic!("TODO");
    }

    pub async fn accept_call(&mut self) -> io::Result<()> {
        if self.state != X25LogicalChannelState::AwaitingCallAccepted {
            panic!("invalid state"); // TODO
        }

        let call_accepted = X25Packet::CallAccepted(X25CallAccepted {
            modulo: self.modulo,
            channel: 1,
        });

        self.send_packet(call_accepted).await?;

        self.state = X25LogicalChannelState::DataTransfer;

        Ok(())
    }

    pub async fn clear_call(&mut self, cause: u8) -> io::Result<()> {
        // TODO: states?

        let clear_request = X25Packet::ClearRequest(X25ClearRequest {
            modulo: self.modulo,
            channel: 1,
            cause,
            diagnostic_code: None,
        });

        // TODO: reset some things, right?

        self.send_packet(clear_request).await?;

        if self.state == X25LogicalChannelState::AwaitingCallAccepted {
            self.state = X25LogicalChannelState::Ready;
        } else {
            self.state = X25LogicalChannelState::AwaitingClearConfirmation;

            self.wait_for_packet(&[X25PacketType::ClearConfirmation])
                .await?;
        }

        Ok(())
    }

    pub async fn reset(&mut self, cause: u8) -> io::Result<()> {
        // TODO: states?

        let reset_request = X25Packet::ResetRequest(X25ResetRequest {
            modulo: self.modulo,
            channel: 1,
            cause,
            diagnostic_code: None,
        });

        self.send_packet(reset_request).await?;

        self.state = X25LogicalChannelState::AwaitingResetConfirmation;

        // TODO: wait for the reset confirmation...

        Ok(())
    }

    pub async fn send_data(&mut self, mut buffer: Bytes) -> io::Result<()> {
        if self.state != X25LogicalChannelState::DataTransfer {
            panic!("invalid state"); // TODO
        }

        let max_packet_size = self.send_max_packet_size;

        while buffer.len() > max_packet_size {
            self.send_queue
                .push_back((buffer.split_to(max_packet_size), true));
        }

        self.send_queue.push_back((buffer, false));

        self.xxx_send_all_that_i_can().await
    }

    async fn receive_ready(&mut self) -> io::Result<()> {
        let receive_ready = X25Packet::ReceiveReady(X25ReceiveReady {
            modulo: self.modulo,
            channel: 1,
            receive_sequence: self.receive_sequence,
        });

        self.send_packet(receive_ready).await?;

        self.xxx_un_rrd_packets = 0;

        Ok(())
    }

    async fn clear_confirmation(&mut self) -> io::Result<()> {
        let clear_confirmation = X25Packet::ClearConfirmation(X25ClearConfirmation {
            modulo: self.modulo,
            channel: 1,
        });

        self.send_packet(clear_confirmation).await
    }

    async fn reset_confirmation(&mut self) -> io::Result<()> {
        let reset_confirmation = X25Packet::ResetConfirmation(X25ResetConfirmation {
            modulo: self.modulo,
            channel: 1,
        });

        self.send_packet(reset_confirmation).await
    }

    async fn xxx_send_all_that_i_can(&mut self) -> io::Result<()> {
        if self.state != X25LogicalChannelState::DataTransfer {
            panic!("invalid state"); // TODO
        }

        let stop_sequence = (self.xxx_lower_bound + self.send_window_size) % (self.modulo as u16);

        while !self.send_queue.is_empty()
            && self.is_remote_ready
            && self.send_sequence != stop_sequence
        {
            let (buffer, more_data) = self.send_queue.pop_front().unwrap();

            let data = X25Packet::Data(X25Data {
                modulo: self.modulo,
                channel: 1,
                qualifier: false,
                delivery_confirmation: false,
                more_data,
                receive_sequence: self.receive_sequence,
                send_sequence: self.send_sequence,
                buffer,
            });

            self.send_packet(data).await?;

            sequence_increment(&mut self.send_sequence, self.modulo);

            // TODO: should we do this?
            if self.send_sequence == stop_sequence {
                self.is_remote_ready = false;
            }
        }

        Ok(())
    }

    async fn send_packet(&mut self, packet: X25Packet) -> io::Result<()> {
        let buffer = format_packet(&packet);

        self.xot_framed.send(buffer).await
    }

    async fn wait_for_packet(&mut self, packet_types: &[X25PacketType]) -> io::Result<X25Packet> {
        while let Some(result) = self.xxx_next().await {
            let packet = result?;

            if packet_types.contains(&packet.packet_type()) {
                return Ok(packet);
            }
        }

        Err(io::Error::new(io::ErrorKind::ConnectionReset, "TODO"))
    }

    // Uuh.. can this be moved into a impl Iterator for X25LogicalChannel?
    // TODO: this needs to be something like x25::Result<X25State|X25Data??>
    pub async fn xxx_next(&mut self) -> Option<io::Result<X25Packet>> {
        let packet = self.xot_framed.next().await;

        // Unwrap the packet.
        let packet = match packet {
            None => return None,
            Some(Ok(p)) => p,
            Some(Err(e)) => return Some(Err(e)),
        };

        // Parse the packet.
        let packet = match parse_packet(packet) {
            Ok(p) => p,
            Err(_) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "TODO"))),
        };

        //
        if packet.modulo() != self.modulo {
            todo!("XXX");
        }

        // vvv
        if self.state == X25LogicalChannelState::Ready {
            match packet {
                X25Packet::CallRequest(_) => {
                    self.state = X25LogicalChannelState::AwaitingCallAccepted;
                }
                _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
            }
        } else if self.state == X25LogicalChannelState::AwaitingCallAccepted {
            match packet {
                X25Packet::CallAccepted(_) => {
                    self.state = X25LogicalChannelState::DataTransfer;
                }
                X25Packet::ClearRequest(_) => {
                    self.state = X25LogicalChannelState::Ready;
                }
                _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
            }
        } else if self.state == X25LogicalChannelState::DataTransfer {
            match packet {
                X25Packet::Data(ref data) => {
                    // TODO: validate the sequence...

                    sequence_increment(&mut self.receive_sequence, self.modulo);

                    self.xxx_lower_bound = data.receive_sequence;
                    // We do NOT set self.is_remote_ready = true here, only RR and
                    // reset can do that!

                    // TODO: clean this stuff up...
                    self.xxx_un_rrd_packets += 1;

                    if self.xxx_un_rrd_packets >= 2 {
                        if let Err(e) = self.receive_ready().await {
                            return Some(Err(e));
                        }
                    }
                }
                X25Packet::ReceiveReady(ref receive_ready) => {
                    self.xxx_lower_bound = receive_ready.receive_sequence;
                    self.is_remote_ready = true;

                    if let Err(e) = self.xxx_send_all_that_i_can().await {
                        return Some(Err(e));
                    }
                }
                X25Packet::ReceiveNotReady(ref receive_not_ready) => {
                    self.xxx_lower_bound = receive_not_ready.receive_sequence;
                    self.is_remote_ready = false;
                }
                X25Packet::ClearRequest(_) => {
                    // TODO: not sure about this, we should move into a clearing
                    // state, but maybe not that doesn't make sense if all we
                    // are going to do is send a clear confirmation...
                    if let Err(e) = self.clear_confirmation().await {
                        return Some(Err(e));
                    }

                    self.state = X25LogicalChannelState::Ready;
                }
                X25Packet::ResetRequest(_) => {
                    print!("\r\nGOT RESET REQUEST\r\n");

                    if let Err(e) = self.reset_confirmation().await {
                        return Some(Err(e));
                    }

                    // TODO: move this to a function...
                    self.receive_sequence = 0;
                    self.send_sequence = 0;
                    self.is_remote_ready = true;
                    self.xxx_lower_bound = 0;
                    //self.xxx_un_rrd_packets: 0,

                    // TODO: do we need to resend anything?
                }
                _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
            }
        } else if self.state == X25LogicalChannelState::AwaitingResetConfirmation {
            match packet {
                X25Packet::ResetRequest(_) => {
                    print!("\r\nGOT RESET REQUEST\r\n");

                    if let Err(e) = self.reset_confirmation().await {
                        return Some(Err(e));
                    }

                    // TODO: move this to a function...
                    self.receive_sequence = 0;
                    self.send_sequence = 0;
                    self.is_remote_ready = true;
                    self.xxx_lower_bound = 0;
                    //self.xxx_un_rrd_packets: 0,

                    // TODO: do we need to resend anything?

                    self.state = X25LogicalChannelState::DataTransfer;
                }

                X25Packet::ResetConfirmation(_) => {
                    print!("\r\nGOT RESET CONFIRMATION\r\n");

                    // TODO: move this to a function...
                    self.receive_sequence = 0;
                    self.send_sequence = 0;
                    self.is_remote_ready = true;
                    self.xxx_lower_bound = 0;
                    //self.xxx_un_rrd_packets: 0,

                    // TODO: do we need to resend anything?

                    self.state = X25LogicalChannelState::DataTransfer;
                }
                // TODO: ClearRequest is valid here...
                _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
            }
        } else if self.state == X25LogicalChannelState::AwaitingClearConfirmation {
            match packet {
                X25Packet::ClearConfirmation(_) => {
                    self.state = X25LogicalChannelState::Ready;
                }
                _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
            }
        }
        // ^^^

        Some(Ok(packet))
    }
}

fn sequence_increment(sequence: &mut u16, modulo: X25Modulo) {
    *sequence = (*sequence + 1) % (modulo as u16);
}
