// SPDX-License-Identifier: MIT
use std::io::{Read, Write};

/// generic netlink wrapper of
/// [`crate::socket::NetlinkSocket`]
#[derive(Debug)]
pub struct GenericNetlinkSocket<
    Snd: Write + AsRef<[u8]>,
    Rcv: Write + AsRef<[u8]> + AsMut<[u8]>,
    Fd: Read + Write,
> {
    pub family_id: u16,
    pub socket: crate::socket::NetlinkSocket<Snd, Rcv, Fd>,
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write>
    GenericNetlinkSocket<Snd, Rcv, Fd>
where
    std::io::Cursor<Snd>: Write,
{
    pub fn from_netlink_socket(
        mut socket: crate::socket::NetlinkSocket<Snd, Rcv, Fd>,
        family_name: String,
    ) -> Result<Self, crate::ResponseError<super::msg::ResolveFamilyIdParseError>> {
        use crate::socket::RequestBuilder;

        let resolve_family_id: super::msg::ResolveFamilyIdMsgBuilder<_> =
            socket.message_builder(family_name);

        let family_resolution = resolve_family_id.call()?;

        Ok(Self {
            family_id: family_resolution.family_id,
            socket,
        })
    }
}

impl<'a, Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write>
    GenericNetlinkSocket<Snd, Rcv, Fd>
{
    /// get a generic message builder writing to the socket buffer
    pub fn message_builder<M: super::GenericMessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        input: M::Input,
    ) -> M {
        self.message_builder_and_sequence_id(input).0
    }

    /// get a generic message builder writing to the socket buffer, and the sequence id used with the messages
    pub fn message_builder_and_sequence_id<M: super::GenericMessageBuilder<'a, Buffer = Self>>(
        &'a mut self,
        input: M::Input,
    ) -> (M, u32) {
        self.socket.sequence_number = self.socket.sequence_number.wrapping_add(1);
        M::new(self, self.family_id, self.socket.sequence_number, input)
    }

    /// get a generic message builder writing to the socket buffer, by providing a custom netlink message header
    pub fn message_builder_with_nelink_header<
        M: super::GenericMessageBuilder<'a, Buffer = Self>,
    >(
        &'a mut self,
        nl_msg_header: crate::netlink::msg::NlMsgHeader,
        input: M::Input,
    ) -> M {
        M::new_with_header(self, nl_msg_header, self.family_id, input)
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write>
    std::ops::Deref for GenericNetlinkSocket<Snd, Rcv, Fd>
{
    type Target = crate::socket::NetlinkSocket<Snd, Rcv, Fd>;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write>
    std::ops::DerefMut for GenericNetlinkSocket<Snd, Rcv, Fd>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write> Read
    for GenericNetlinkSocket<Snd, Rcv, Fd>
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.rcv_buffer.read(buf)
    }
}

impl<Snd: Write + AsRef<[u8]>, Rcv: Write + AsRef<[u8]> + AsMut<[u8]>, Fd: Read + Write> Write
    for GenericNetlinkSocket<Snd, Rcv, Fd>
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

/// helper trait to make request from a [`GenericNetlinkSocket`]'s generic message builder
pub trait GenericRequestBuilder<Buffer, Output, ParseError>: Sized {
    /// send request
    fn send(self) -> Result<usize, std::io::Error>;
    /// send request, receive response and parse it
    fn call(self) -> Result<Output, crate::ResponseError<ParseError>>;
}

impl<'a, T, Snd, Rcv, Fd>
    GenericRequestBuilder<GenericNetlinkSocket<Snd, Rcv, Fd>, T::Output, T::ParseError> for T
where
    Snd: Write + AsRef<[u8]> + 'a,
    Rcv: Write + AsRef<[u8]> + AsMut<[u8]> + 'a,
    Fd: Read + Write + 'a,
    T: crate::genetlink::GenericMessageBuilder<'a, Buffer = GenericNetlinkSocket<Snd, Rcv, Fd>>,
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
