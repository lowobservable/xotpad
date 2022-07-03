use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::select;

use crate::x25::{X25LogicalChannel, X25Packet};

pub struct HostPad<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    channel: X25LogicalChannel,
    data: BytesMut,
    is_running: bool,
}

impl<R: AsyncRead + std::marker::Unpin, W: AsyncWrite + std::marker::Unpin> HostPad<R, W> {
    pub fn new(
        reader: R,
        writer: W,
        channel: X25LogicalChannel,
        // TODO: X3Parameters,
    ) -> Self {
        // TODO: check channel state, must be ready...

        Self {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            channel,
            data: BytesMut::new(),
            is_running: false,
        }
    }

    pub async fn run(mut self) -> io::Result<()> {
        self.is_running = true;

        let mut buffer: [u8; 1024] = [0; 1024];

        while self.is_running {
            select! {
                length = self.reader.read(&mut buffer) => {
                    match length {
                        Ok(length) => {
                            self.handle_host_output(&buffer[0..length]).await?
                        }
                        Err(_) => {
                            self.channel.clear_call(0).await?; // TODO: cause?

                            self.is_running = false;
                        },
                    }
                },

                packet = self.channel.xxx_next() => {
                    match packet {
                        Some(Ok(packet)) => self.handle_packet(packet).await?,
                        Some(Err(error)) => panic!("{}", error),
                        None => {
                            todo!();
                        },
                    }
                },
            }
        }

        Ok(())
    }

    async fn handle_host_output(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.queue_and_maybe_send_data(buffer).await
    }

    async fn handle_packet(&mut self, packet: X25Packet) -> io::Result<()> {
        match packet {
            X25Packet::Data(data) => {
                self.writer.write_all(&data.buffer).await?;
                self.writer.flush().await?;
            }
            X25Packet::ClearRequest(_) => {
                self.is_running = false;
            }
            X25Packet::ClearConfirmation(_) => {
                self.is_running = false;
            }
            _ => { /* TODO: most packets have to be ignored, for now */ }
        }

        Ok(())
    }

    async fn queue_and_maybe_send_data(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.data.extend_from_slice(buffer);

        // TODO: Does this make sense, do we check the last byte on host output?
        let data = self.data.clone().freeze();

        self.channel.send_data(data).await?;

        self.data.clear();

        Ok(())
    }
}
