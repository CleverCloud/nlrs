# nlrs

A minimal rust crate for simple and efficient Netlink requests

## Overview

**nlrs** is a Rust library made to communicate with the Linux kernel's netlink protocol.
It provides a straightforward API for constructing and handling netlink requests, making it easier to interact with various kernel networking features from Rust.
Designed for transparency and flexibility, nlrs exposes every part of its implementation, giving you complete control, with nothing hidden behind opaque abstractions.

Netlink is a powerful protocol in Linux, commonly used for tasks such as managing network interfaces, addresses, routes, and more.

## Features

- Netlink and Generic Netlink helper to implemement protocols
- Rtnetlink protocols 
- Ipvs protocol
- Async requests with tokio
- Network namespaces
- Easy to copy, modify, or integrate into your own codebase

## Altnernatives

They are other crate to send netlink request:

- [https://github.com/rust-netlink](https://github.com/rust-netlink)
- [https://github.com/jbaublitz/neli](https://github.com/jbaublitz/neli)

**nlrs** differs from other implementations by:

- Simpler straightforward implementation
- No dependencies by default (only for tokio for async requests)
- Code base is in the same crate
- Every part of the code is public
- Requests are sans-io builder patterns
- Full control for all requests
- Easy copy paste in other code bases

## Getting Started

### Installation

Add nlrs to your `Cargo.toml`:

```toml
[dependencies]
nlrs = "0.1"
```

### Basic Usage

Here's a minimal example of how to use nlrs to get all ip addresses on a system :

```rust
use nlrs::{
    netlink::socket::NlSocketType,
    rtnetlink::addr::GetAllAddressMsgBuilder,
    socket::{NetlinkSocket, RequestBuilder},
};

fn main() {
    let mut socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE).unwrap();

    let message_builder: GetAllAddressMsgBuilder<_> = socket.message_builder(());
    let res = message_builder.call();

    println!("{res:#?}");
}
```

For more detailed examples and API documentation, see the [documentation](https://docs.rs/nlrs).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
