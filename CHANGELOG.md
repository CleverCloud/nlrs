# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.2.1 - 2026-03-26

### 🌟 Features

- We implemented **ipvlan child creation** in network namespaces. This is useful when upstream network equipment filters by MAC and a unique MAC per namespace is not feasible.
- We provided **interface enslaving message**, to set or unset the master device of a network interface. This is used to enslave an interface to a bridge, bond, or other master device.
- We added **u64 and u128 attributes** reading and writing helper functions.
- We added **ip v4/v6 attributes** reading and writing helper functions.

### ✍️ Changed

- We renamed some functions in the wireguard implementation to better match what they actualy do.

### ⛑️ Fixed

- We fixed, **variable length link address** reading, by using vectors instead of fixed length arrays.
- We corrected **sequence number start** in messages by starting the sequence at 0 and not 1. 

## 0.2.0 - 2025-11-13

Initial open-source release of **nlrs** - a minimal Rust crate for simple and efficient Netlink requests to communicate with the Linux kernel's networking API. This release consolidates all core functionality including Generic Netlink, IPVS, RTNetlink, WireGuard support, and network namespace utilities.

### 🌟 Features

- We implemented a complete **Generic Netlink** foundation with family resolution and socket abstractions. The implementation provides a transparent and flexible API for constructing and handling netlink requests, allowing developers to communicate efficiently with the Linux kernel's generic netlink interface.
- We added comprehensive **IPVS (IP Virtual Server)** protocol support for load balancing and service management. This includes service and destination control messages, flush commands, destination weight management, and better parsing of IPVS destinations. The IPVS structs are clonable and hashable for easier integration into applications.
- We built a **RTNetlink** implementation covering network interfaces (links), IP addresses, routes and gateways, neighbors, and VETH pair creation. This provides full control over Linux network stack configuration, including interface creation and deletion, address management, route control, and VETH peer setup in network namespaces.
- We integrated **WireGuard** protocol support via netlink, enabling WireGuard VPN configuration through kernel netlink interface. This includes proper handling of endpoint port endianess for correct network communication.
- We developed **network namespace** utilities with async execution helpers. This includes functions to test if a namespace exists, async fork execution helpers for running operations in different network namespaces, and proper cleanup and documentation.
- We provided **POSIX utilities** for interface management, including functions to map interface names to indices and list all network interfaces on the system. These utilities simplify working with network interfaces across the codebase.

### ⛑️ Fixed

- We corrected **WireGuard socket address port endianess** issues that could cause incorrect port handling in WireGuard configurations. This ensures proper network communication with WireGuard peers.

### 📚 Documentation

- We created comprehensive documentation including initial README with usage examples, Cargo.toml metadata, and MIT license. Module-level documentation was added for IPVS, Generic Netlink, and network namespaces.
