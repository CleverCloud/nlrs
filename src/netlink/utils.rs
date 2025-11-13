// SPDX-License-Identifier: MIT
/// write a structure to a bytes writter
#[inline]
pub fn transprose_write<T: Sized>(
    value: &T,
    writer: &mut impl std::io::Write,
) -> Result<usize, std::io::Error> {
    // SAFETY: this works because of #[repr(C, packed)], padding would break this
    writer.write(unsafe {
        let slice: &[u8] = ::core::slice::from_raw_parts(
            ::core::ptr::from_ref(value).cast(),
            ::core::mem::size_of::<T>(),
        );
        slice
    })
}

/// read / map a structure from a bytes reader
#[inline]
pub fn transpose_read<T: Sized>(reader: &mut impl std::io::Read) -> Result<T, std::io::Error> {
    #[allow(invalid_value)]
    #[allow(clippy::uninit_assumed_init)]
    let mut data: T = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    // SAFETY: this works because of #[repr(C, packed)], padding would break this
    let slice: &mut [u8] = unsafe {
        ::core::slice::from_raw_parts_mut(
            ::core::ptr::from_mut(&mut data).cast(),
            ::core::mem::size_of::<T>(),
        )
    };
    reader.read_exact(slice).map(|_| data)
}

/// util to skip n bytes when parsing has failed
pub fn skip_n_bytes(reader: &mut impl std::io::Read, mut n: usize) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 1024];
    while n > 0 {
        let to_read = std::cmp::min(n, buf.len());
        let read = reader.read(&mut buf[..to_read])?;
        if read == 0 {
            break;
        } // EOF
        n -= read;
    }
    Ok(())
}
