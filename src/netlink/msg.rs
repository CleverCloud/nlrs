// SPDX-License-Identifier: MIT
/// header of a netlink message
/// ```
/// <------------------ 4 bytes -------------------->
/// |-----------------------------------------------|
/// |      Message length (including header)        |
/// |-----------------------------------------------|
/// |     Message type     |     Message flags      |
/// |-----------------------------------------------|
/// |           Message sequence number             |
/// |-----------------------------------------------|
/// |                 Netlink PortID                |
/// |-----------------------------------------------|
/// |                                               |
/// |                  Payload                      |
/// |_______________________________________________|
///
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct NlMsgHeader {
    /// length of message including header
    pub len: u32,
    /// message content type
    pub r#type: u16,
    /// additional flags
    pub flags: u16,
    /// sequence number
    pub seq: u32,
    /// sending process port id
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NlMsgHeaderType {
    /// nothing
    NlmsgNoop = 1,
    /// error
    NlmsgError = 2,
    /// end of a dump
    NlmsgDone = 3,
    /// data lost
    NlmsgOverrun = 4,
}

impl NlMsgHeader {
    /// size of a [`NlMsgHeader`] in bytes
    pub const SIZE: usize = std::mem::size_of::<NlMsgHeader>();

    /// create a netlink message header with seq and pid field set
    ///
    /// len is set at [`NlMsgHeader::SIZE`]
    /// others are set to 0
    #[inline]
    pub fn new_with_seq_and_pid(seq: u32, pid: u32) -> Self {
        NlMsgHeader {
            len: Self::SIZE as u32,
            r#type: 0,
            flags: 0,
            seq,
            pid,
        }
    }

    /// set the message total length from the playload length
    ///
    /// provided length must only be the playload length
    /// as the header length is added here
    #[inline]
    pub fn set_playload_length(&mut self, mut len: usize) -> usize {
        len += Self::SIZE;

        self.len = len as u32;
        len
    }

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        super::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<NlMsgHeader, std::io::Error> {
        super::utils::transpose_read(reader)
    }

    /// try to parse a knowned message type, otherwise return the message type
    pub fn parse_type(&self) -> Result<NlMsgHeaderType, u16> {
        match self.r#type {
            1 => Ok(NlMsgHeaderType::NlmsgNoop),
            2 => Ok(NlMsgHeaderType::NlmsgError),
            3 => Ok(NlMsgHeaderType::NlmsgDone),
            4 => Ok(NlMsgHeaderType::NlmsgOverrun),
            _ => Err(self.r#type),
        }
    }

    /// check if the NLM_F_MULTI flag is set
    pub const fn is_multi(&self) -> bool {
        (self.flags & flags::NLM_F_MULTI) != 0
    }

    /// check if the NLM_F_MULTI flag is set
    pub const fn is_done(&self) -> bool {
        self.r#type == 3
    }
}

pub const NLMSG_MIN_TYPE: u16 = 0x10;

#[derive(Debug)]
pub enum NlMsgHeaderParseError {
    Io(std::io::Error),
    Netlink(i32),
    DataLoss,
}

impl core::fmt::Display for NlMsgHeaderParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlMsgHeaderParseError::Io(error) => {
                write!(
                    f,
                    "io error occured while parsing netlink message header: {error}"
                )
            }
            #[cfg(target_os = "linux")]
            NlMsgHeaderParseError::Netlink(error) => write!(
                f,
                "netlink socket returned an error: {}",
                std::io::Error::from_raw_os_error(*error)
            ),
            #[cfg(not(target_os = "linux"))]
            NlMsgHeaderParseError::Netlink(error) => {
                write!(f, "netlink returned an error: {error}")
            }
            NlMsgHeaderParseError::DataLoss => {
                write!(f, "netlink socket returned a data loss error")
            }
        }
    }
}

impl core::error::Error for NlMsgHeaderParseError {}

pub struct NlMsgIter<'a, R: std::io::Read, O> {
    pub reader: &'a mut R,
    pub payload_parser: fn(&mut R, usize) -> O,
    pub has_parsed_error: bool,
}

impl<'a, R: std::io::Read, O> NlMsgIter<'a, R, O> {
    pub fn new(reader: &'a mut R, payload_parser: fn(&mut R, usize) -> O) -> Self {
        Self {
            reader,
            payload_parser,
            has_parsed_error: false,
        }
    }
}

impl<'a, R: std::io::Read, O> Iterator for NlMsgIter<'a, R, O> {
    type Item = Result<O, NlMsgHeaderParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_parsed_error {
            return None;
        }

        let header = match NlMsgHeader::read(&mut self.reader).map_err(NlMsgHeaderParseError::Io) {
            Ok(h) => h,
            Err(err) => return Some(Err(err)),
        };
        match header.parse_type() {
            Err(_) => Some(Ok((self.payload_parser)(
                self.reader,
                header.len as usize - NlMsgHeader::SIZE,
            ))),
            Ok(NlMsgHeaderType::NlmsgDone) => None,
            Ok(NlMsgHeaderType::NlmsgOverrun) => Some(Err(NlMsgHeaderParseError::DataLoss)),
            Ok(NlMsgHeaderType::NlmsgError) => {
                let remaining_bytes = header.len as usize - NlMsgHeader::SIZE;

                let mut err = [0u8; 4];
                if let Err(err) = self
                    .reader
                    .read(&mut err)
                    .map_err(NlMsgHeaderParseError::Io)
                {
                    return Some(Err(err));
                }
                let err = i32::from_le_bytes(err);

                if let Err(err) = super::utils::skip_n_bytes(self.reader, remaining_bytes - 4)
                    .map_err(NlMsgHeaderParseError::Io)
                {
                    return Some(Err(err));
                }

                if err != 0 {
                    self.has_parsed_error = true;
                    Some(Err(NlMsgHeaderParseError::Netlink(-err)))
                } else {
                    // ACK message
                    None
                }
            }
            _ => unimplemented!(),
        }
    }
}

pub fn validate_ack(reader: &mut impl std::io::Read) -> Result<(), NlMsgHeaderParseError> {
    fn unsued_parser(_reader: &mut impl std::io::Read, _len: usize) {}
    NlMsgIter::new(reader, unsued_parser)
        .next()
        .unwrap_or(Ok(()))
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    /* time.h */
    #[doc(hidden)]
    fn time(__timer: *const u64) -> u64;
}

/// sequence number generated with libc time function
#[inline]
#[cfg(target_os = "linux")]
pub fn generate_sequence_number() -> u32 {
    unsafe { self::time(std::ptr::null()) as u32 }
}

/// netlink message header type
pub mod types {
    /// nothing.
    pub const NLMSG_NOOP: u16 = 1;
    /// error
    pub const NLMSG_ERROR: u16 = 2;
    /// end of a dump
    pub const NLMSG_DONE: u16 = 3;
    /// data lost
    pub const NLMSG_OVERRUN: u16 = 4;
}

/// netlink message header flags
pub mod flags {
    /// request message.
    pub const NLM_F_REQUEST: u16 = 0x01;
    /// multipart message, terminated by NLMSG_DONE
    pub const NLM_F_MULTI: u16 = 0x02;
    /// reply with ack, with zero or error code
    pub const NLM_F_ACK: u16 = 0x04;
    /// receive resulting notifications
    pub const NLM_F_ECHO: u16 = 0x08;
    /// dump was inconsistent due to sequence change
    pub const NLM_F_DUMP_INTR: u16 = 0x10;
    /// dump was filtered as requested
    pub const NLM_F_DUMP_FILTERED: u16 = 0x20;

    /* modifiers to GET request */
    /// specify tree root
    pub const NLM_F_ROOT: u16 = 0x100;
    /// return all matching
    pub const NLM_F_MATCH: u16 = 0x200;
    /// atomic GET
    pub const NLM_F_ATOMIC: u16 = 0x400;
    /// dump requests
    pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

    /* Modifiers to NEW request */
    /// Override existing
    pub const NLM_F_REPLACE: u16 = 0x100;
    /// Do not touch, if it exists
    pub const NLM_F_EXCL: u16 = 0x200;
    /// Create, if it does not exist
    pub const NLM_F_CREATE: u16 = 0x400;
    /// Add to end of list
    pub const NLM_F_APPEND: u16 = 0x800;

    /* Modifiers to DELETE request */
    /// do not delete recursively
    pub const NLM_F_NONREC: u16 = 0x100;
    /// Delete multiple objects
    pub const NLM_F_BULK: u16 = 0x200;

    /*Flags for ACK message */
    /// request was capped
    pub const NLM_F_CAPPED: u16 = 0x100;
    /// extended ACK TVLs were included
    pub const NLM_F_ACK_TLVS: u16 = 0x200;
}
