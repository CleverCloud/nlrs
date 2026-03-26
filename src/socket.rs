// SPDX-License-Identifier: MIT
#[cfg(target_os = "linux")]
use crate::netlink::socket::NlSocket;

use std::io::{Read, Seek, SeekFrom, Write};

/// buffered synchronous netlink socket
#[derive(Debug)]
pub struct NetlinkSocket<
    Snd: Write + AsRef<[u8]>,
    Rcv: Write + AsRef<[u8]> + AsMut<[u8]>,
    Fd: Read + Write,
> {
    pub snd_buffer: ::std::io::Cursor<Snd>,
    pub rcv_buffer: ::std::io::Cursor<Rcv>,
    pub socket: Fd,
    pub sequence_number: u32,
}

#[cfg(target_os = "linux")]
impl NetlinkSocket<Vec<u8>, Vec<u8>, NlSocket> {
    /// vector buffered synchronous netlink socket
    #[inline]
    pub fn new_vectored(
        r#type: crate::netlink::socket::NlSocketType,
    ) -> Result<Self, crate::netlink::socket::NlSocketError> {
        Ok(Self::vectored_from_socket(NlSocket::new(r#type)?))
    }

    /// default sized read vector buffered synchronous netlink socket from raw ['NlSocket']
    pub fn vectored_from_socket(socket: NlSocket) -> Self {
        Self::vectored_from_socket_with_capacity(
            socket,
            crate::netlink::socket::NL_SOCKET_DUMP_SIZE,
        )
    }

    /// sized read vector buffered synchronous netlink socket from raw ['NlSocket']
    pub fn vectored_from_socket_with_capacity(socket: NlSocket, capacity: usize) -> Self {
        Self {
            snd_buffer: ::std::io::Cursor::new(Vec::new()),
            rcv_buffer: ::std::io::Cursor::new(vec![0; capacity]),
            socket,
            sequence_number: 0,
        }
    }
}

impl<'a, Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write>
    NetlinkSocket<Snd, Rcv, Fd>
{
    /// get a message builder writing to the socket buffer
    pub fn message_builder<M: crate::MessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        input: M::Input,
    ) -> M {
        self.message_builder_and_sequence_id(input).0
    }

    /// get a message builder writing to the socket buffer, and the sequence id used with the messages
    pub fn message_builder_and_sequence_id<M: crate::MessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        input: M::Input,
    ) -> (M, u32) {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        M::new(self, self.sequence_number, input)
    }

    /// get a message builder writing to the socket buffer, by providing a custom netlink message header
    pub fn message_builder_with_nelink_header<M: crate::MessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        nl_msg_header: crate::netlink::msg::NlMsgHeader,
        input: M::Input,
    ) -> M {
        M::new_with_header(self, nl_msg_header, input)
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write> Read
    for NetlinkSocket<Snd, Rcv, Fd>
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.rcv_buffer.read(buf)
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write> Write
    for NetlinkSocket<Snd, Rcv, Fd>
where
    std::io::Cursor<Snd>: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.snd_buffer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.snd_buffer.flush()
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write>
    NetlinkSocket<Snd, Rcv, Fd>
where
    std::io::Cursor<Rcv>: Read,
{
    /// send a request and return the number of written bytes
    ///
    /// the request must be already written into the socket
    pub fn send(&mut self) -> Result<usize, std::io::Error> {
        let request_len = self.snd_buffer.stream_position()? as usize;

        // resetting sender buffer position
        self.snd_buffer.seek(SeekFrom::Start(0))?;

        // sending request
        let written_bytes = self
            .socket
            .write(&self.snd_buffer.get_ref().as_ref()[0..request_len])?;
        //partial write?

        Ok(written_bytes)
    }

    /// get a response and return the number of read bytes
    ///
    /// the request must be already sent
    pub fn receive(&mut self) -> Result<usize, std::io::Error> {
        // clearing receiving buffer
        self.rcv_buffer.seek(SeekFrom::Start(0))?;

        let mut total_read_bytes = 0;
        loop {
            // receiving response
            let read_bytes = self
                .socket
                .read(&mut self.rcv_buffer.get_mut().as_mut()[total_read_bytes..])?;

            let mut header_reader = std::io::Cursor::new(
                &self.rcv_buffer.get_ref().as_ref()
                    [total_read_bytes..total_read_bytes + read_bytes],
            );

            let mut remaining_bytes = read_bytes;
            let mut header;
            loop {
                header = crate::netlink::msg::NlMsgHeader::read(&mut header_reader)?;
                crate::netlink::utils::skip_n_bytes(
                    &mut header_reader,
                    header.len as usize - crate::netlink::msg::NlMsgHeader::SIZE,
                )?;
                remaining_bytes -= header.len as usize;
                if remaining_bytes == 0 {
                    break;
                }
            }

            total_read_bytes += read_bytes;

            if !header.is_multi() || header.is_done() {
                break;
            }
        }

        // preparing to parse bytes from receiving buffer
        self.rcv_buffer.seek(SeekFrom::Start(0))?;

        Ok(total_read_bytes)
    }
}

/// helper trait to make request from a [`NetlinkSocket`]'s message builder
pub trait RequestBuilder<Buffer, Output, ParseError>: Sized {
    /// send request
    fn send(self) -> Result<usize, std::io::Error>;
    /// send request, receive response and parse it
    fn call(self) -> Result<Output, crate::ResponseError<ParseError>>;
}

impl<'a, T, Snd, Rcv, Fd> RequestBuilder<NetlinkSocket<Snd, Rcv, Fd>, T::Output, T::ParseError>
    for T
where
    Snd: Write + AsRef<[u8]> + 'a,
    Rcv: Write + AsRef<[u8]> + AsMut<[u8]> + 'a,
    Fd: Read + Write + 'a,
    T: crate::MessageBuilder<'a, Buffer = NetlinkSocket<Snd, Rcv, Fd>>,
{
    fn send(self) -> Result<usize, std::io::Error> {
        let (socket, _) = self.build()?;
        socket.send()
    }

    fn call(self) -> Result<T::Output, crate::ResponseError<T::ParseError>> {
        let (socket, _) = self.build()?;
        socket.send().map_err(crate::ResponseError::Io)?;
        socket.receive().map_err(crate::ResponseError::Io)?;
        T::parse_response(socket)
    }
}

#[cfg(target_os = "linux")]
impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>> std::os::fd::AsRawFd
    for NetlinkSocket<Snd, Rcv, NlSocket>
{
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}

/// buffered asynchronous netlink socket
#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
#[derive(Debug)]
#[repr(transparent)]
pub struct AsyncNetlinkSocket<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>> {
    pub socket: tokio::io::unix::AsyncFd<NetlinkSocket<Snd, Rcv, NlSocket>>,
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>>
    AsyncNetlinkSocket<Snd, Rcv>
{
    pub fn new(socket: NetlinkSocket<Snd, Rcv, NlSocket>) -> Result<Self, std::io::Error> {
        let socket = tokio::io::unix::AsyncFd::new(socket)?;
        Ok(Self { socket })
    }
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
impl<'a, Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>>
    AsyncNetlinkSocket<Snd, Rcv>
{
    /// get a message builder writing to the socket buffer
    pub fn message_builder<M: crate::MessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        input: M::Input,
    ) -> M {
        self.message_builder_and_sequence_id(input).0
    }

    /// get a message builder writing to the socket buffer, and the sequence id used with the messages
    pub fn message_builder_and_sequence_id<M: crate::MessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        input: M::Input,
    ) -> (M, u32) {
        self.socket.get_mut().sequence_number =
            self.socket.get_ref().sequence_number.wrapping_add(1);
        M::new(self, self.socket.get_ref().sequence_number, input)
    }

    /// get a message builder writing to the socket buffer, by providing a custom netlink message header
    pub fn message_builder_with_nelink_header<M: crate::MessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        nl_msg_header: crate::netlink::msg::NlMsgHeader,
        input: M::Input,
    ) -> M {
        M::new_with_header(self, nl_msg_header, input)
    }
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>> Read
    for AsyncNetlinkSocket<Snd, Rcv>
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.socket.get_mut().rcv_buffer.read(buf)
    }
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>> Write
    for AsyncNetlinkSocket<Snd, Rcv>
where
    std::io::Cursor<Snd>: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.get_mut().snd_buffer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.get_mut().snd_buffer.flush()
    }
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>> AsyncNetlinkSocket<Snd, Rcv>
where
    std::io::Cursor<Rcv>: Read,
{
    /// send a request and return the number of written bytes
    ///
    /// the request must be already written into the socket
    pub async fn send(&mut self) -> Result<usize, std::io::Error> {
        let request_len = self.socket.get_mut().snd_buffer.stream_position()? as usize;

        // resetting sender buffer position
        self.socket.get_mut().snd_buffer.seek(SeekFrom::Start(0))?;

        loop {
            let mut guard = self.socket.writable_mut().await?;

            // sending request
            match guard.try_io(|socket| {
                let inner_socket = socket.get_mut();
                inner_socket
                    .socket
                    .write(&inner_socket.snd_buffer.get_ref().as_ref()[0..request_len])
            }) {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }

    /// get a response and return the number of read bytes
    ///
    /// the request must be already sent
    pub async fn receive(&mut self) -> Result<usize, std::io::Error> {
        use std::io::{Seek, SeekFrom};

        // Clear receiving buffer
        self.socket.get_mut().rcv_buffer.seek(SeekFrom::Start(0))?;

        let mut total_read_bytes = 0;
        loop {
            let mut guard = self.socket.readable_mut().await?;

            // read response into buffer at the correct offset
            let read_bytes = match guard.try_io(|socket| {
                let inner_socket = socket.get_mut();
                inner_socket
                    .socket
                    .read(&mut inner_socket.rcv_buffer.get_mut().as_mut()[total_read_bytes..])
            }) {
                Ok(result) => result?,
                Err(_would_block) => continue,
            };

            let mut header_reader = std::io::Cursor::new(
                &self.socket.get_ref().rcv_buffer.get_ref().as_ref()
                    [total_read_bytes..total_read_bytes + read_bytes],
            );

            let mut remaining_bytes = read_bytes;
            let mut header;
            loop {
                header = crate::netlink::msg::NlMsgHeader::read(&mut header_reader)?;
                crate::netlink::utils::skip_n_bytes(
                    &mut header_reader,
                    header.len as usize - crate::netlink::msg::NlMsgHeader::SIZE,
                )?;
                remaining_bytes -= header.len as usize;
                if remaining_bytes == 0 {
                    break;
                }
            }

            total_read_bytes += read_bytes;

            if !header.is_multi() || header.is_done() {
                break;
            }
        }

        // prepare to parse bytes from receiving buffer
        self.socket.get_mut().rcv_buffer.seek(SeekFrom::Start(0))?;

        Ok(total_read_bytes)
    }
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
/// helper trait to make async request from a [`AsyncNetlinkSocket`]'s message builder
pub trait AsyncRequestBuilder<'a, Buffer, Output, ParseError>: Sized {
    /// send request
    #[allow(async_fn_in_trait)]
    async fn send(self) -> Result<usize, std::io::Error>;
    /// send request, receive response and parse it
    #[allow(async_fn_in_trait)]
    async fn call(self) -> Result<Output, crate::ResponseError<ParseError>>;
}

#[cfg(all(target_os = "linux", feature = "tokio-socket"))]
impl<'a, T, Snd, Rcv>
    AsyncRequestBuilder<'a, AsyncNetlinkSocket<Snd, Rcv>, T::Output, T::ParseError> for T
where
    Snd: Write + AsRef<[u8]> + 'a,
    Rcv: Write + AsRef<[u8]> + AsMut<[u8]> + 'a,
    T: crate::MessageBuilder<'a, Buffer = AsyncNetlinkSocket<Snd, Rcv>>,
{
    async fn send(self) -> Result<usize, std::io::Error> {
        let (socket, _) = self.build()?;
        socket.send().await
    }

    async fn call(self) -> Result<T::Output, crate::ResponseError<T::ParseError>> {
        let (socket, _) = self.build()?;
        socket.send().await.map_err(crate::ResponseError::Io)?;
        socket.receive().await.map_err(crate::ResponseError::Io)?;
        T::parse_response(socket)
    }
}
