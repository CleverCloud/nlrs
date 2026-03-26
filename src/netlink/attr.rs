// SPDX-License-Identifier: MIT
/// basic element of a netlink message playload
#[derive(Debug)]
#[repr(C, packed)]
pub struct NlAttribute {
    pub len: u16,
    pub r#type: u16,
}

impl NlAttribute {
    /// size of a [`NlAttribute`] in bytes
    pub const SIZE: usize = std::mem::size_of::<NlAttribute>();

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        super::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<NlAttribute, std::io::Error> {
        super::utils::transpose_read(reader)
    }
}

/// netlink attibutes are aligned with 4 bytes
pub const NL_ATTR_ALIGN_TO: usize = 4;

/// nested flag on an attribute type
pub const NLA_F_NESTED: u16 = 1 << 15;

/// apply [`NLA_F_NESTED`] to a netlink attribute type
#[inline]
pub const fn nl_nest(r#type: u16) -> u16 {
    r#type | NLA_F_NESTED
}

/// compute the 'real' len of an attribute by adding the right padding to the len
#[inline]
pub const fn nl_attr_align(len: usize) -> usize {
    (len + NL_ATTR_ALIGN_TO - 1) & !(NL_ATTR_ALIGN_TO - 1)
}

/// helper that correctly align after an attribute was written
#[inline]
pub fn nl_attr_align_writer(
    writer: &mut impl std::io::Write,
    written_bytes: usize,
) -> Result<usize, std::io::Error> {
    let zeroed = [0u8; NL_ATTR_ALIGN_TO];
    let alignement = nl_attr_align(written_bytes);
    let padding = alignement - written_bytes;

    _ = writer.write(&zeroed[0..padding])?;

    Ok(padding)
}

/// helper to set the length of an attribute with alignement
#[inline]
pub const fn set_attr_length_aligned(len: usize) -> usize {
    nl_attr_align(NlAttribute::SIZE + len)
}

/// helper to set the length of a string attribute with alignement
#[inline]
pub const fn set_string_length_aligned(len: usize) -> usize {
    // c string end with '\0'
    set_attr_length_aligned(len + 1)
}

/// helper to set the length of an ip address attribute with alignement
#[inline]
pub const fn set_ip_address_attr_length_aligned(ip_address: &std::net::IpAddr) -> usize {
    if ip_address.is_ipv4() {
        set_attr_length_aligned(4)
    } else {
        set_attr_length_aligned(16)
    }
}

#[inline]
/// helper to set the length of an attribute
pub const fn set_attr_length(len: usize) -> usize {
    NlAttribute::SIZE + len
}

#[inline]
/// helper to set the length of a string attribute
pub const fn set_string_attr_length(len: usize) -> usize {
    // c string end with '\0'
    set_attr_length(len + 1)
}

/// helper to set the length of an ip address attribute
#[inline]
pub const fn set_ip_address_attr_length(ip_address: &std::net::IpAddr) -> usize {
    if ip_address.is_ipv4() {
        set_attr_length(4)
    } else {
        set_attr_length(16)
    }
}

/// try to write an u8
pub fn write_u8_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: u8,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(1) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&u8::to_le_bytes(value))?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an u16
pub fn write_u16_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: u16,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(2) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&u16::to_le_bytes(value))?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an u16 (big-endian)
pub fn write_be_u16_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: u16,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(2) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&value.to_be_bytes())?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an u32
pub fn write_u32_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: u32,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(4) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&u32::to_le_bytes(value))?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an u64
pub fn write_u64_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: u64,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = crate::netlink::attr::NlAttribute {
        len: crate::netlink::attr::set_attr_length(8) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&u64::to_le_bytes(value))?;

    written_bytes = crate::netlink::attr::nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an u128
pub fn write_u128_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: u128,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = crate::netlink::attr::NlAttribute {
        len: crate::netlink::attr::set_attr_length(16) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&u128::to_le_bytes(value))?;

    written_bytes = crate::netlink::attr::nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an i32
pub fn write_i32_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: i32,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(4) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&i32::to_le_bytes(value))?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write a sized array
pub fn write_array_attr<const N: usize>(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: [u8; N],
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(N) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(&value)?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write a byte slice
pub fn write_slice_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    value: &[u8],
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_attr_length(value.len()) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(value)?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write a string
pub fn write_string_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    str: &str,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;
    let attr = NlAttribute {
        len: set_string_attr_length(str.len()) as u16,
        r#type,
    };

    written_bytes += attr.write(writer)?;
    written_bytes += writer.write(str.as_bytes())?;
    written_bytes += writer.write(b"\0")?;

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// try to write an ip address
pub fn write_ip_address_attr(
    writer: &mut impl std::io::Write,
    r#type: u16,
    ip_address: &std::net::IpAddr,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;

    match ip_address {
        std::net::IpAddr::V4(ipv4_addr) => {
            let attr = NlAttribute {
                len: set_attr_length(4) as u16,
                r#type,
            };

            written_bytes += attr.write(writer)?;
            written_bytes += writer.write(&ipv4_addr.octets())?;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            let attr = NlAttribute {
                len: set_attr_length(16) as u16,
                r#type,
            };

            written_bytes += attr.write(writer)?;
            written_bytes += writer.write(&ipv6_addr.octets())?;
        }
    }

    written_bytes = nl_attr_align_writer(writer, written_bytes)?;

    Ok(written_bytes)
}

/// util to skip the correct amount of bytes when a parser failed
pub fn recover_read<R: std::io::Read, O, E: From<std::io::Error>>(
    reader: &mut R,
    len: usize,
    parser: fn(&mut R, usize) -> Result<Option<O>, std::io::Error>,
    parse_error: E,
) -> Result<O, E> {
    match (parser)(reader, len)? {
        Some(result) => Ok(result),
        None => {
            super::utils::skip_n_bytes(reader, len)?;
            Err(parse_error)
        }
    }
}

/// try to read an u8, does not read bytes otherwise
pub fn read_u8_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<u8>, std::io::Error> {
    if len == 1 {
        let mut buff = [0u8; 1];
        reader.read_exact(&mut buff)?;
        Ok(Some(buff[0]))
    } else {
        Ok(None)
    }
}

/// try to read an u16, does not read bytes otherwise
pub fn read_u16_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<u16>, std::io::Error> {
    if len == 2 {
        let mut buff = [0u8; 2];
        reader.read_exact(&mut buff)?;
        Ok(Some(u16::from_le_bytes(buff)))
    } else {
        Ok(None)
    }
}

/// try to read a u16 (big-endian), does not read bytes otherwise
pub fn read_be_u16_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<u16>, std::io::Error> {
    if len == 2 {
        let mut buff = [0u8; 2];
        reader.read_exact(&mut buff)?;
        Ok(Some(u16::from_be_bytes(buff)))
    } else {
        Ok(None)
    }
}

/// try to read an u32, does not read bytes otherwise
pub fn read_u32_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<u32>, std::io::Error> {
    if len == 4 {
        let mut buff = [0u8; 4];
        reader.read_exact(&mut buff)?;
        Ok(Some(u32::from_le_bytes(buff)))
    } else {
        Ok(None)
    }
}

/// try to read an i32, does not read bytes otherwise
pub fn read_i32_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<i32>, std::io::Error> {
    if len == 4 {
        let mut buff = [0u8; 4];
        reader.read_exact(&mut buff)?;
        Ok(Some(i32::from_le_bytes(buff)))
    } else {
        Ok(None)
    }
}

/// try to read a u64, does not read bytes otherwise
pub fn read_u64_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<u64>, std::io::Error> {
    if len == 8 {
        let mut buff = [0u8; 8];
        reader.read_exact(&mut buff)?;
        Ok(Some(u64::from_le_bytes(buff)))
    } else {
        Ok(None)
    }
}

/// try to read a u128, does not read bytes otherwise
pub fn read_u128_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<u128>, std::io::Error> {
    if len == 16 {
        let mut buff = [0u8; 16];
        reader.read_exact(&mut buff)?;
        Ok(Some(u128::from_le_bytes(buff)))
    } else {
        Ok(None)
    }
}

/// try to read a fixed sized array, does not read bytes otherwise
pub fn read_array_attr<const N: usize>(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<[u8; N]>, std::io::Error> {
    if len == N {
        let mut array = [0u8; N];
        reader.read_exact(&mut array)?;
        Ok(Some(array))
    } else {
        Ok(None)
    }
}

/// try to read an dynamic array, does not read bytes otherwise
pub fn read_vec_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let mut res = vec![0; len];
    reader.read_exact(&mut res)?;
    Ok(res)
}

/// try to read an ip address, does not read bytes otherwise
pub fn read_ip_address_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<std::net::IpAddr>, std::io::Error> {
    if len == 4 {
        let mut buff = [0u8; 4];
        reader.read_exact(&mut buff)?;
        Ok(Some(std::net::IpAddr::from(buff)))
    } else if len == 16 {
        let mut buff = [0u8; 16];
        reader.read_exact(&mut buff)?;
        Ok(Some(std::net::IpAddr::from(buff)))
    } else {
        Ok(None)
    }
}

/// try to read a string
pub fn read_string_attr(
    reader: &mut impl std::io::Read,
    mut len: usize,
) -> Result<Option<String>, std::io::Error> {
    // c string end with '\0'
    len -= 1;
    let mut res = Vec::with_capacity(len);
    let mut buf = [0u8; 1024];

    while len > 0 {
        let to_read = std::cmp::min(len, buf.len());
        let read = reader.read(&mut buf[..to_read])?;
        if read == 0 {
            // EOF
            return Ok(None);
        }
        res.extend(&buf[..read]);
        len -= read;
    }
    // c string end with '\0'
    reader.read_exact(&mut buf[..1])?;

    let valid_str = String::from_utf8(res).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid UTF-8: {e}"),
        )
    })?;
    Ok(Some(valid_str))
}

/// iterator that parse multiple netlink attributes
pub struct NlAttributeIter<'a, R: std::io::Read, O> {
    pub reader: &'a mut R,
    pub attributes_parser: fn(&mut R, NlAttribute) -> O,
    pub remaining_bytes: usize,
}

impl<'a, R: std::io::Read, O> NlAttributeIter<'a, R, O> {
    pub fn new(
        reader: &'a mut R,
        attributes_parser: fn(&mut R, NlAttribute) -> O,
        remaining_bytes: usize,
    ) -> Self {
        Self {
            reader,
            attributes_parser,
            remaining_bytes,
        }
    }
}

impl<'a, R: std::io::Read, O> Iterator for NlAttributeIter<'a, R, O> {
    type Item = Result<O, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_bytes == 0 {
            return None;
        }

        let mut attribute = match NlAttribute::read(&mut self.reader) {
            Ok(h) => h,
            Err(err) => return Some(Err(err)),
        };

        let alignement = nl_attr_align(attribute.len as usize);
        // TODO safe underflow detection
        self.remaining_bytes -= alignement;

        let padding = alignement - attribute.len as usize;
        attribute.len -= NlAttribute::SIZE as u16;

        let result = (self.attributes_parser)(self.reader, attribute);

        if padding != 0 {
            let mut sink = [0u8; NL_ATTR_ALIGN_TO];
            if let Err(error) = self.reader.read_exact(&mut sink[0..padding]) {
                return Some(Err(error));
            }
        }

        Some(Ok(result))
    }
}
