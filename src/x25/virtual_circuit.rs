use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::cmp::min;
use std::collections::VecDeque;
use std::io;
use std::str::FromStr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::x121::X121Address;
use crate::x25::facility::X25Facility;
use crate::x25::packet::{
    format_packet, parse_packet, X25CallAccepted, X25CallRequest, X25ClearConfirmation,
    X25ClearRequest, X25Data, X25Modulo, X25Packet, X25PacketType, X25ReceiveReady,
    X25ResetConfirmation, X25ResetRequest,
};
use crate::x25::parameters::X25Parameters;
use crate::xot::XotCodec;

// TODO: how can I get rid of the dependency on TcpStream and XotCodec here?
pub struct X25VirtualCircuit {
    link: Framed<TcpStream, XotCodec>,
    state: X25VirtualCircuitState,
    modulo: X25Modulo,

    call_request: Option<X25CallRequest>,

    send_max_packet_size: usize,
    send_window_size: u16,
    send_queue: VecDeque<(Bytes, bool, bool)>,
    send_sequence: u16,
    send_window_lower_edge: u16,

    receive_max_packet_size: usize,
    receive_window_size: u16,
    receive_sequence: u16,

    is_remote_ready: bool,

    // TODO: clean these up...
    xxx_un_rrd_packets: u16,
}

#[derive(Debug, PartialEq)]
enum X25VirtualCircuitState {
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

impl X25VirtualCircuit {
    fn new(link: Framed<TcpStream, XotCodec>, parameters: &X25Parameters) -> Self {
        Self {
            link,
            state: X25VirtualCircuitState::Ready,
            modulo: parameters.modulo(),
            call_request: None,
            send_max_packet_size: parameters.send_max_packet_size(),
            send_window_size: parameters.send_window_size(),
            send_queue: VecDeque::new(),
            send_sequence: 0,
            send_window_lower_edge: 0,
            receive_max_packet_size: parameters.receive_max_packet_size(),
            receive_window_size: parameters.receive_window_size(),
            receive_sequence: 0,
            is_remote_ready: true,
            xxx_un_rrd_packets: 0,
        }
    }

    pub async fn call(
        link: Framed<TcpStream, XotCodec>,
        parameters: &X25Parameters,
        called_address: &X121Address,
        calling_address: &X121Address,
        call_user_data: &Bytes,
    ) -> io::Result<Self> {
        let mut virtual_circuit = Self::new(link, parameters);

        let facilities = vec![
            X25Facility::PacketSize {
                from_called: virtual_circuit.receive_max_packet_size,
                from_calling: virtual_circuit.send_max_packet_size,
            },
            X25Facility::WindowSize {
                from_called: virtual_circuit.receive_window_size as u8,
                from_calling: virtual_circuit.send_window_size as u8,
            },
        ];

        let call_request = X25CallRequest {
            modulo: virtual_circuit.modulo,
            channel: 1,
            called_address: called_address.clone(), // TODO, can these be refs?
            calling_address: calling_address.clone(),
            facilities,
            call_user_data: call_user_data.clone(),
        };

        virtual_circuit.send_packet(call_request.clone()).await?;

        virtual_circuit.call_request = Some(call_request);
        virtual_circuit.state = X25VirtualCircuitState::AwaitingCallAccepted;

        let packet = virtual_circuit
            .wait_for_packet(&[X25PacketType::CallAccepted, X25PacketType::ClearRequest])
            .await?;

        match packet {
            X25Packet::CallAccepted(_) => Ok(virtual_circuit),
            X25Packet::ClearRequest(_) => {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "TODO"))
            }
            _ => panic!("TODO"),
        }
    }

    pub async fn wait_for_call(
        link: Framed<TcpStream, XotCodec>,
        parameters: &X25Parameters,
    ) -> io::Result<(X25VirtualCircuit, X25CallRequest)> {
        let mut virtual_circuit = Self::new(link, parameters);

        let packet = virtual_circuit
            .wait_for_packet(&[X25PacketType::CallRequest])
            .await?;

        if let X25Packet::CallRequest(call_request) = packet {
            virtual_circuit.call_request = Some(call_request.clone());

            return Ok((virtual_circuit, call_request));
        }

        panic!("TODO");
    }

    pub async fn accept_call(&mut self) -> io::Result<()> {
        if self.state != X25VirtualCircuitState::AwaitingCallAccepted {
            panic!("invalid state"); // TODO
        }

        let call_request = self.call_request.take().expect("TODO");

        let facilities = self.negotiate_facilities(&call_request);

        let call_accepted = X25CallAccepted {
            modulo: self.modulo,
            channel: 1,
            called_address: X121Address::from_str("").unwrap(),
            calling_address: X121Address::from_str("").unwrap(),
            facilities,
        };

        self.send_packet(call_accepted).await?;

        self.state = X25VirtualCircuitState::DataTransfer;

        Ok(())
    }

    pub async fn clear_call(&mut self, cause: u8, diagnostic_code: Option<u8>) -> io::Result<()> {
        // TODO: states?

        let clear_request = X25ClearRequest {
            modulo: self.modulo,
            channel: 1,
            cause,
            diagnostic_code,
        };

        // TODO: reset some things, right?

        self.send_packet(clear_request).await?;

        self.call_request = None;

        if self.state == X25VirtualCircuitState::AwaitingCallAccepted {
            self.state = X25VirtualCircuitState::Ready;
        } else {
            self.state = X25VirtualCircuitState::AwaitingClearConfirmation;

            self.wait_for_packet(&[X25PacketType::ClearConfirmation])
                .await?;
        }

        Ok(())
    }

    pub async fn send_data(&mut self, mut buffer: Bytes, qualifier: bool) -> io::Result<()> {
        if self.state != X25VirtualCircuitState::DataTransfer {
            panic!("invalid state"); // TODO
        }

        let max_packet_size = self.send_max_packet_size;

        while buffer.len() > max_packet_size {
            self.send_queue
                .push_back((buffer.split_to(max_packet_size), qualifier, true));
        }

        self.send_queue.push_back((buffer, qualifier, false));

        self.send_queued().await?;

        Ok(())
    }

    pub async fn reset(&mut self, cause: u8, diagnostic_code: Option<u8>) -> io::Result<()> {
        // TODO: states?

        let reset_request = X25ResetRequest {
            modulo: self.modulo,
            channel: 1,
            cause,
            diagnostic_code,
        };

        self.send_packet(reset_request).await?;

        self.xxx_reset_state();

        self.state = X25VirtualCircuitState::AwaitingResetConfirmation;

        // TODO: wait for the reset confirmation...

        Ok(())
    }

    async fn send_queued(&mut self) -> io::Result<usize> {
        if self.state != X25VirtualCircuitState::DataTransfer {
            panic!("invalid state"); // TODO
        }

        let stop_sequence =
            (self.send_window_lower_edge + self.send_window_size) % (self.modulo as u16);

        let mut count = 0;

        while !self.send_queue.is_empty()
            && self.is_remote_ready
            && self.send_sequence != stop_sequence
        {
            let (buffer, qualifier, more_data) = self.send_queue.pop_front().unwrap();

            let data = X25Data {
                modulo: self.modulo,
                channel: 1,
                qualifier,
                delivery_confirmation: false,
                more_data,
                receive_sequence: self.receive_sequence,
                send_sequence: self.send_sequence,
                buffer,
            };

            self.send_packet(data).await?;

            self.send_sequence = (self.send_sequence + 1) % (self.modulo as u16);

            // TODO: should we do this?
            if self.send_sequence == stop_sequence {
                self.is_remote_ready = false;
            }

            count += 1;
        }

        Ok(count)
    }

    async fn receive_ready(&mut self) -> io::Result<()> {
        let receive_ready = X25ReceiveReady {
            modulo: self.modulo,
            channel: 1,
            receive_sequence: self.receive_sequence,
        };

        self.send_packet(receive_ready).await?;

        self.xxx_un_rrd_packets = 0;

        Ok(())
    }

    async fn clear_confirmation(&mut self) -> io::Result<()> {
        let clear_confirmation = X25ClearConfirmation {
            modulo: self.modulo,
            channel: 1,
        };

        self.send_packet(clear_confirmation).await
    }

    async fn reset_confirmation(&mut self) -> io::Result<()> {
        let reset_confirmation = X25ResetConfirmation {
            modulo: self.modulo,
            channel: 1,
        };

        self.send_packet(reset_confirmation).await
    }

    async fn send_packet<P: Into<X25Packet>>(&mut self, packet: P) -> io::Result<()> {
        let buffer = format_packet(&packet.into())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        self.link.send(buffer).await
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

    // Uuh.. can this be moved into a impl Iterator for X25VirtualCircuit?
    // TODO: this needs to be something like x25::Result<X25State|X25Data??>
    pub async fn xxx_next(&mut self) -> Option<io::Result<X25Packet>> {
        loop {
            let packet = self.link.next().await;

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
            if self.state == X25VirtualCircuitState::Ready {
                match packet {
                    X25Packet::CallRequest(ref call_request) => {
                        self.call_request = Some(call_request.clone());

                        self.state = X25VirtualCircuitState::AwaitingCallAccepted;
                    }
                    _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
                }
            } else if self.state == X25VirtualCircuitState::AwaitingCallAccepted {
                match packet {
                    X25Packet::CallAccepted(ref call_accepted) => {
                        // Adopt the facilities provided by the other party.
                        self.adopt_facilities(call_accepted);

                        self.state = X25VirtualCircuitState::DataTransfer;
                    }
                    X25Packet::ClearRequest(_) => {
                        self.state = X25VirtualCircuitState::Ready;
                    }
                    // TODO: Call collision...
                    _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
                }
            } else if self.state == X25VirtualCircuitState::DataTransfer {
                match packet {
                    X25Packet::Data(ref data) => {
                        if !self.update_receive_sequence(data.send_sequence) {
                            if let Err(e) = self.reset(0x05, Some(0x01)).await {
                                return Some(Err(e));
                            }
                            continue;
                        }

                        if !self.update_send_window(data.receive_sequence) {
                            if let Err(e) = self.reset(0x0b, Some(0x02)).await {
                                return Some(Err(e));
                            }
                            continue;
                        }

                        // We do NOT set self.is_remote_ready = true here, only RR and
                        // reset can do that!

                        // TODO: clean this stuff up... try and send anything we have
                        // queued as that will send a P(R), if there isn't anything
                        // queued then explicitly send a RR if necessary.
                        match self.send_queued().await {
                            Ok(count) => {
                                if count == 0 {
                                    self.xxx_un_rrd_packets += 1;

                                    // Okay, now we have to do something...
                                    if self.xxx_un_rrd_packets >= self.receive_window_size {
                                        if let Err(e) = self.receive_ready().await {
                                            return Some(Err(e));
                                        }
                                    }
                                }
                            }
                            Err(e) => return Some(Err(e)),
                        }
                    }
                    X25Packet::ReceiveReady(ref receive_ready) => {
                        if !self.update_send_window(receive_ready.receive_sequence) {
                            if let Err(e) = self.reset(0x0b, Some(0x02)).await {
                                return Some(Err(e));
                            }
                            continue;
                        }

                        self.is_remote_ready = true;

                        if let Err(e) = self.send_queued().await {
                            return Some(Err(e));
                        }
                    }
                    X25Packet::ReceiveNotReady(ref receive_not_ready) => {
                        if !self.update_send_window(receive_not_ready.receive_sequence) {
                            if let Err(e) = self.reset(0x0b, Some(0x02)).await {
                                return Some(Err(e));
                            }
                            continue;
                        }

                        self.is_remote_ready = false;
                    }
                    X25Packet::ClearRequest(_) => {
                        // TODO: not sure about this, we should move into a clearing
                        // state, but maybe not that doesn't make sense if all we
                        // are going to do is send a clear confirmation...
                        if let Err(e) = self.clear_confirmation().await {
                            return Some(Err(e));
                        }

                        self.state = X25VirtualCircuitState::Ready;
                    }
                    X25Packet::ResetRequest(_) => {
                        if let Err(e) = self.reset_confirmation().await {
                            return Some(Err(e));
                        }

                        self.xxx_reset_state();

                        // TODO: do we need to resend anything?
                    }
                    _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
                }
            } else if self.state == X25VirtualCircuitState::AwaitingResetConfirmation {
                match packet {
                    X25Packet::ResetRequest(_) => {
                        if let Err(e) = self.reset_confirmation().await {
                            return Some(Err(e));
                        }

                        self.xxx_reset_state();

                        // TODO: do we need to resend anything?

                        self.state = X25VirtualCircuitState::DataTransfer;
                    }

                    X25Packet::ResetConfirmation(_) => {
                        self.xxx_reset_state();

                        // TODO: do we need to resend anything?

                        self.state = X25VirtualCircuitState::DataTransfer;
                    }
                    // TODO: ClearRequest is valid here...
                    _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
                }
            } else if self.state == X25VirtualCircuitState::AwaitingClearConfirmation {
                match packet {
                    X25Packet::ClearConfirmation(_) => {
                        self.state = X25VirtualCircuitState::Ready;
                    }
                    _ => todo!("state = {:?}, packet = {:?}", self.state, packet),
                }
            }
            // ^^^

            return Some(Ok(packet));
        }
    }

    fn xxx_reset_state(&mut self) {
        self.send_sequence = 0;
        self.send_window_lower_edge = 0;
        self.receive_sequence = 0;
        self.is_remote_ready = true;
        //self.xxx_un_rrd_packets: 0,
    }

    #[must_use]
    fn update_receive_sequence(&mut self, sequence: u16) -> bool {
        if sequence != self.receive_sequence {
            return false;
        }

        self.receive_sequence = (sequence + 1) % (self.modulo as u16);

        true
    }

    #[must_use]
    fn update_send_window(&mut self, receive_sequence: u16) -> bool {
        if !is_sequence_in_range(
            receive_sequence,
            self.send_window_lower_edge,
            self.send_sequence,
        ) {
            return false;
        }

        self.send_window_lower_edge = receive_sequence;

        true
    }

    fn adopt_facilities(&mut self, call_accepted: &X25CallAccepted) {
        let facilities = &call_accepted.facilities;

        // When adopting facilities from a received call accepted packet, we are
        // the "calling" party.
        if let Some((from_called, from_calling)) = facilities.iter().find_map(|f| match f {
            X25Facility::PacketSize {
                from_called,
                from_calling,
            } => Some((from_called, from_calling)),
            _ => None,
        }) {
            self.send_max_packet_size = *from_calling;
            self.receive_max_packet_size = *from_called;
        }

        if let Some((from_called, from_calling)) = facilities.iter().find_map(|f| match f {
            X25Facility::WindowSize {
                from_called,
                from_calling,
            } => Some((from_called, from_calling)),
            _ => None,
        }) {
            self.send_window_size = *from_calling as u16;
            self.receive_window_size = *from_called as u16;
        }
    }

    fn negotiate_facilities(&mut self, call_request: &X25CallRequest) -> Vec<X25Facility> {
        let request_facilities = &call_request.facilities;

        let mut facilities = Vec::new();

        // When negotiating facilities from a received call request packet, we are
        // the "called" party.
        if let Some((from_called, from_calling)) = request_facilities.iter().find_map(|f| match f {
            X25Facility::PacketSize {
                from_called,
                from_calling,
            } => Some((from_called, from_calling)),
            _ => None,
        }) {
            self.send_max_packet_size = min(self.send_max_packet_size, *from_called);
            self.receive_max_packet_size = min(self.receive_max_packet_size, *from_calling);

            facilities.push(X25Facility::PacketSize {
                from_called: self.send_max_packet_size,
                from_calling: self.receive_max_packet_size,
            });
        }

        if let Some((from_called, from_calling)) = request_facilities.iter().find_map(|f| match f {
            X25Facility::WindowSize {
                from_called,
                from_calling,
            } => Some((from_called, from_calling)),
            _ => None,
        }) {
            self.send_window_size = min(self.send_window_size, *from_called as u16);
            self.receive_window_size = min(self.receive_window_size, *from_calling as u16);

            facilities.push(X25Facility::WindowSize {
                from_called: self.send_window_size as u8,
                from_calling: self.receive_window_size as u8,
            });
        }

        facilities
    }
}

fn is_sequence_in_range(sequence: u16, start: u16, end: u16) -> bool {
    if start == end && sequence == start {
        return true;
    }

    if start < end && sequence >= start && sequence <= end {
        return true;
    }

    if start > end && (sequence >= start || sequence <= end) {
        return true;
    }

    false
}
