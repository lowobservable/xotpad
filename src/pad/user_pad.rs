use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio_util::codec::Framed;

use crate::x121::X121Address;
use crate::x25::{X25CallRequest, X25Modulo, X25Packet, X25VirtualCircuit};
use crate::xot;
use crate::xot::{XotCodec, XotResolver};

macro_rules! async_write {
    ($dst: expr, $fmt: expr) => {
        {
            use std::io::Write;
            let mut buf = Vec::<u8>::new();
            write!(buf, $fmt)?;
            tokio::io::AsyncWriteExt::write_all(&mut $dst, &buf).await
        }
    };
    ($dst: expr, $fmt: expr, $($arg: tt)*) => {
        {
            use std::io::Write;
            let mut buf = Vec::<u8>::new();
            write!(buf, $fmt, $( $arg )*)?;
            tokio::io::AsyncWriteExt::write_all(&mut $dst, &buf).await
        }
    };
}

pub struct UserPad<'a, R, W> {
    state: UserPadState,
    reader: BufReader<R>,
    writer: BufWriter<W>,
    modulo: X25Modulo,
    address: &'a X121Address,
    xot_resolver: &'a XotResolver,
    circuit: Option<X25VirtualCircuit>,
    listener: Option<TcpListener>,
    command: String,
    data: BytesMut,
    xxx_one_shot: bool,
}

#[derive(PartialEq)]
enum UserPadState {
    Command,
    Data,
    Shutdown,
}

impl<'a, R: AsyncRead + std::marker::Unpin, W: AsyncWrite + std::marker::Unpin> UserPad<'a, R, W> {
    pub fn new(
        reader: R,
        writer: W,
        modulo: X25Modulo,
        address: &'a X121Address,
        xot_resolver: &'a XotResolver,
        listener: Option<TcpListener>,
        // TODO: Paraemters / Profiles / Profile?
        xxx_one_shot: bool,
    ) -> Self {
        Self {
            state: UserPadState::Command,
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            modulo,
            address,
            xot_resolver,
            circuit: None,
            listener,
            command: String::new(),
            data: BytesMut::new(),
            xxx_one_shot,
        }
    }

    pub async fn call(&mut self, address: &X121Address) -> io::Result<()> {
        let xot_gateway = self.xot_resolver.resolve(address);

        if xot_gateway.is_none() {
            async_write!(self.writer, "CLR PAD C:0 D:0\r\n\r\n")?; // Huh???
            return Ok(());
        }

        let xot_gateway = xot_gateway.unwrap();

        let tcp_stream = TcpStream::connect((xot_gateway, xot::TCP_PORT)).await?;

        let link = Framed::new(tcp_stream, XotCodec::new());

        let call_user_data = Bytes::from_static(b"\x01\0\0\0");

        let circuit =
            X25VirtualCircuit::call(link, self.modulo, address, self.address, &call_user_data)
                .await;

        match circuit {
            Ok(circuit) => {
                async_write!(self.writer, "COM\r\n")?;

                self.circuit = Some(circuit);

                self.switch_to_data_mode()?;
            }
            Err(_) => {
                /*
                let cause = clear_request.cause;
                let diagnostic_code = clear_request.diagnostic_code.unwrap_or(0);
                */
                let cause = 123;
                let diagnostic_code = 456;

                async_write!(self.writer, "CLR XXX C:{} D:{}\r\n", cause, diagnostic_code)?;
            }
        }

        Ok(())
    }

    async fn clear(&mut self) -> io::Result<()> {
        self.circuit
            .as_mut()
            .unwrap()
            .clear_call(0, Some(0))
            .await?;

        async_write!(self.writer, "CLR CONF\r\n")?;

        // Okay, so we will have sent the clear confirmation so we
        // can try and close the circuit now?
        self.circuit = None;

        self.data.clear();

        Ok(())
    }

    pub async fn run(mut self) -> io::Result<()> {
        // We need to print the prompt, if we start out in command mode!
        if self.state == UserPadState::Command {
            self.print_command_prompt().await?;
            self.writer.flush().await?;
        }

        while self.state != UserPadState::Shutdown {
            let is_in_data_state = self.state == UserPadState::Data;

            select! {
                byte = self.reader.read_u8() => {
                    match byte {
                        Ok(byte) => self.handle_user_input(byte).await?,
                        Err(error) => panic!("{}", error),
                    }
                },

                packet = read_packet(self.circuit.as_mut(), is_in_data_state) => {
                    match packet {
                        Some(Ok(packet)) => self.handle_packet(packet).await?,
                        Some(Err(error)) => panic!("{}", error),
                        None => {
                            self.circuit = None;

                            if self.xxx_one_shot {
                                break;
                            } else {
                                self.switch_to_command_mode().await?;
                            }
                        },
                    }
                },

                // TODO: really, this needs to go in a separate thread so it
                // does not block while we are trying to accept the call...
                call = wait_for_call(self.modulo, &mut self.listener, true) => {
                    match call {
                        Ok((circuit, call_request)) => self.handle_incoming_call(circuit, call_request).await?,
                        Err(error) => panic!("{}", error),
                    }
                },
            }

            self.writer.flush().await?;
        }

        Ok(())
    }

    async fn handle_user_input(&mut self, byte: u8) -> io::Result<()> {
        let mut is_connected = self.circuit.is_some();

        match self.state {
            UserPadState::Command => {
                if byte == 0x10 && self.command.is_empty() {
                    if is_connected {
                        self.switch_to_data_mode()?;
                        self.queue_and_maybe_send_data(byte).await?;
                    }
                } else if byte == 0x0d {
                    let command = self.command.clone();
                    let command = command.trim();

                    if !command.is_empty() {
                        async_write!(self.writer, "\r\n")?;

                        self.execute_command(command).await?;

                        self.command.clear();

                        // This could have changed, if we executed a command...
                        is_connected = self.circuit.is_some();
                    } else if !is_connected {
                        async_write!(self.writer, "\r\n")?;
                    }

                    // Okay, if we are still in command mode - maybe we are in
                    // data, or maybe we are in shutdown...
                    if self.state == UserPadState::Command {
                        // XXX: if we are connected, a command is a one time thing!
                        if is_connected {
                            self.switch_to_data_mode()?;
                        } else {
                            self.print_command_prompt().await?;
                        }
                    }
                } else {
                    // We need to echo command input as we are in raw mode...
                    self.writer.write_all(&[byte]).await?;

                    // And then append it to the command string!
                    self.command.push(byte as char);
                }
            }

            UserPadState::Data => {
                if byte == 0x10 {
                    self.switch_to_command_mode().await?;
                } else {
                    self.queue_and_maybe_send_data(byte).await?;
                }
            }

            _ => {} /* TODO */
        }

        Ok(())
    }

    async fn handle_packet(&mut self, packet: X25Packet) -> io::Result<()> {
        match packet {
            X25Packet::Data(data) => self.writer.write_all(&data.buffer).await?,
            X25Packet::ClearRequest(clear_request) => {
                let cause = clear_request.cause;
                let diagnostic_code = clear_request.diagnostic_code.unwrap_or(0);

                async_write!(
                    self.writer,
                    "\r\nCLR XXX C:{} D:{}\r\n",
                    cause,
                    diagnostic_code
                )?;

                // Okay, so we will have sent the clear confirmation so we
                // can try and close the circuit now?
                self.circuit = None;

                self.data.clear();

                self.switch_to_command_mode().await?;
            }
            _ => { /* TODO: most packets have to be ignored, for now */ }
        }

        Ok(())
    }

    async fn handle_incoming_call(
        &mut self,
        mut circuit: X25VirtualCircuit,
        call_request: X25CallRequest,
    ) -> io::Result<()> {
        let called_address = call_request.called_address.to_string();

        if self.circuit.is_some() {
            let cause = 1; // "OCC" - number busy

            circuit.clear_call(cause, Some(0)).await?;
        } else if called_address.starts_with(&self.address.to_string()) {
            circuit.accept_call().await?;

            async_write!(self.writer, "\r\nCOM\r\n")?;

            self.circuit = Some(circuit);
            self.switch_to_data_mode()?;
        } else {
            let cause = 0; // TODO: what should this be?

            circuit.clear_call(cause, Some(0)).await?;
        }

        Ok(())
    }

    async fn switch_to_command_mode(&mut self) -> io::Result<()> {
        self.command.clear();

        self.state = UserPadState::Command;

        async_write!(self.writer, "\r\n")?;

        self.print_command_prompt().await
    }

    async fn print_command_prompt(&mut self) -> io::Result<()> {
        async_write!(self.writer, "*")
    }

    async fn execute_command(&mut self, line: &str) -> io::Result<()> {
        // It looks like additional arguments (i.e. an argument to reset)
        // are just ignored, based on Cisco x28 command at least...

        match parse_command_line(line) {
            Some((UserPadCommand::Call, args)) => {
                if self.circuit.is_some() {
                    async_write!(self.writer, "ERR\r\n\r\n")?;
                } else {
                    let address: X121Address = args[0].parse().unwrap();

                    self.call(&address).await?;
                }
            }
            Some((UserPadCommand::Clear, _)) => {
                if self.circuit.is_none() {
                    async_write!(self.writer, "ERR\r\n\r\n")?;
                } else {
                    self.clear().await?;
                }
            }
            Some((UserPadCommand::Reset, _)) => {
                if self.circuit.is_none() {
                    async_write!(self.writer, "ERR\r\n\r\n")?;
                } else {
                    self.circuit.as_mut().unwrap().reset(0, Some(0)).await?;

                    // TODO: is this correct, we wait for conf. before we
                    // indicate RESET?
                }
            }
            Some((UserPadCommand::Status, _)) => {
                if self.circuit.is_some() {
                    async_write!(self.writer, "ENGAGED\r\n\r\n")?;
                } else {
                    async_write!(self.writer, "FREE\r\n\r\n")?;
                }
            }
            Some((UserPadCommand::Exit, _)) => {
                self.state = UserPadState::Shutdown;
            }
            None => async_write!(self.writer, "ERR\r\n\r\n")?,
        }

        Ok(())
    }

    fn switch_to_data_mode(&mut self) -> io::Result<()> {
        self.command.clear();

        self.state = UserPadState::Data;

        Ok(())
    }

    async fn queue_and_maybe_send_data(&mut self, byte: u8) -> io::Result<()> {
        self.data.put_u8(byte);

        // TODO
        if true {
            let data = self.data.clone().freeze();

            self.circuit.as_mut().unwrap().send_data(data).await?;

            self.data.clear();
        }

        Ok(())
    }
}

async fn wait_for_call(
    modulo: X25Modulo,
    listener: &mut Option<TcpListener>,
    enable: bool,
) -> io::Result<(X25VirtualCircuit, X25CallRequest)> {
    if listener.is_none() || !enable {
        return futures::future::pending().await;
    }

    let (tcp_stream, _tcp_address) = listener.as_ref().unwrap().accept().await?;

    let link = Framed::new(tcp_stream, XotCodec::new());

    X25VirtualCircuit::wait_for_call(link, modulo).await
}

async fn read_packet(
    circuit: Option<&mut X25VirtualCircuit>,
    enable: bool,
) -> Option<io::Result<X25Packet>> {
    // TODO: would it be better to run select on a list that ONLY contains
    // the sources we are interested in - instead of this "dummy" future?
    if circuit.is_none() || !enable {
        return futures::future::pending().await;
    }

    circuit.unwrap().xxx_next().await
}

// ...

#[derive(Copy, Clone, Debug)]
enum UserPadCommand {
    // BREAK
    Call,
    Clear,
    // HELP - see X.28 5.4... "help LIST" is the main one!
    // ICLR, ICLEAR
    // INT, INTERRUPT
    // PAR?, PARAMETER, PAR
    // PROFILE, PROF
    // READ
    Reset,
    // RPAR?, RREAD
    // RESETREAD, RSET?
    Status,
    // SET?, SETREAD
    // SET
    Exit,
}

const COMMANDS: [(&str, UserPadCommand); 5] = [
    ("CALL", UserPadCommand::Call),
    ("CLEAR", UserPadCommand::Clear),
    ("RESET", UserPadCommand::Reset),
    ("STATUS", UserPadCommand::Status),
    ("EXIT", UserPadCommand::Exit),
];

fn parse_command(text: &str) -> Option<UserPadCommand> {
    let text = text.trim().to_uppercase();

    let matches: Vec<UserPadCommand> = COMMANDS
        .iter()
        .filter(|c| c.0.starts_with(&text))
        .map(|c| c.1)
        .collect();

    if matches.len() != 1 {
        return None;
    }

    Some(matches[0])
}

fn parse_command_line(line: &str) -> Option<(UserPadCommand, Vec<&str>)> {
    let words: Vec<&str> = line.split_whitespace().collect();

    if words.is_empty() {
        return None;
    }

    parse_command(words[0]).map(|command| (command, words[1..].to_vec()))
}
