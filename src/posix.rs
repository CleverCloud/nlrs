// SPDX-License-Identifier: MIT
use core::ffi::{CStr, c_char, c_uint};
use std::ffi::CString;

#[doc(hidden)]
#[repr(C)]
struct IfNameIndex {
    if_index: c_uint,
    if_name: *mut c_char,
}

unsafe extern "C" {
    /* net/if.h */
    #[doc(hidden)]
    fn if_nametoindex(ifname: *const c_char) -> c_uint;
    #[doc(hidden)]
    fn if_indextoname(ifindex: c_uint, ifname: *mut c_char) -> *mut c_char;
    #[doc(hidden)]
    fn if_nameindex() -> *mut IfNameIndex;
    #[doc(hidden)]
    fn if_freenameindex(ptr: *mut IfNameIndex);
}

/// returns the index of the network interface corresponding to the name of this interface
pub fn interface_name_to_index(ifname: &str) -> Option<u32> {
    let c_ifname = CString::new(ifname).ok()?;
    let idx = unsafe { if_nametoindex(c_ifname.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

/// returns the name of the network interface corresponding to the interface index
pub fn interface_index_to_name(ifindex: u32) -> Option<String> {
    // IF_NAMESIZE is 16 on linux, to be safe we use 64
    const IF_NAMESIZE: usize = 64;
    let mut buf = [0u8; IF_NAMESIZE];
    let ptr = buf.as_mut_ptr() as *mut c_char;
    let res = unsafe { if_indextoname(ifindex, ptr) };
    if res.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_str().map(|s| s.to_owned()).ok()
    }
}

/// return a list of the interfaces names and indexes
pub fn list_interfaces() -> Vec<(String, u32)> {
    let mut res = Vec::with_capacity(0);
    unsafe {
        let ptr = if_nameindex();
        if ptr.is_null() {
            return res;
        }

        let mut current = ptr;
        while !(*current).if_name.is_null() || (*current).if_index != 0 {
            if !(*current).if_name.is_null() && (*current).if_index != 0 {
                let name = CStr::from_ptr((*current).if_name)
                    .to_string_lossy()
                    .to_string();
                let index = (*current).if_index;
                res.push((name, index));
            }
            current = current.add(1);
        }

        if_freenameindex(ptr);
    }

    res
}
