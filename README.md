# nlrs

A minimal rust crate for simple and efficient Netlink requests

## Overview

**nlrs** is a Rust library made to communicate with the Linux kernel's netlink protocol.
It provides a straightforward API for constructing and handling netlink requests, making it easier to interact with various kernel networking features from Rust.
Designed for transparency and flexibility, nlrs exposes every part of its implementation, giving you complete control, with nothing hidden behind opaque abstractions.

Netlink is a powerful protocol in Linux, commonly used for tasks such as managing network interfaces, addresses, routes, and more.

## Features

- Netlink and Generic Netlink helper to implement protocols
- Rtnetlink protocols 
- Ipvs protocol
- Async requests with tokio
- Network namespaces
- Easy to copy, modify, or integrate into your own codebase

## Alternatives

There are other crates to send netlink requests:

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
nlrs = "0.2.4"
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

### Network namespace helper failures

Namespace creation reports a helper child terminated by a signal as
`NetnsCreationError::ForkFailed`. A failed creation can leave a placeholder.
Creation at an existing path succeeds only when Linux verifies it as a network
namespace (`NS_GET_NSTYPE`, Linux 4.11 or later). An unverified path returns
`NetnsCreationError::NetnsFileCreationFailed` with `AlreadyExists`. Confirm
that a placeholder is stale before removing it to retry. `netns_exists` checks
path presence. The path-based create and delete APIs preserve non-UTF-8 OS
path bytes.

Both `execute_into_netns` and `async_execute_into_netns` report signal
termination and unexpected nonzero exit codes as
`NetnsEnterError::ReadingErrorFailed`. The error includes the signal or exit
code. Callback errors are returned in the inner `Result`.

### Descriptors inherited by the namespace helper

The execution helpers fork, and the child holds a copy of every descriptor of
the process until it exits. A socket the parent closes meanwhile stays open,
and so does the network namespace it belongs to. `execute_into_netns_closing_descriptors`
and `async_execute_into_netns_closing_descriptors` close every inherited
descriptor except stdio and the ones passed in `keep` before calling the
function, using `close_range(2)` (Linux 5.9 or later), else one `close` per
descriptor below the descriptor limit. Pass every descriptor the function uses.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
