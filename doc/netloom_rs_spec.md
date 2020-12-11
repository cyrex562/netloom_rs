# Netloom-RS Specification

## Introduction

Netloom-RS (NLRS) is a framework for processing packets, communicating with various network protocols, and providing networking functions. The Lightweight IP stack library inspired the development of NLRS.  NLRS started as a direct port of LWiP to modern C++. The lead developer decided to use Rust after some experimentation in 2019. NLRS aims to provide four sets of functionality for different scenarios:

* A set of libraries to assist developers in handling various network protocols
* A command-line tool similar to a combination of tcpdump and netcat
* A Proxy server enabling applications to send/receive and forward traffic in various protocols
* An embedded network stack suitable for processing network traffic with low overhead and latency.

## Goals

1. NLRS should support the following four scenarios:

    * A set of static and dynamic C-compatible libraries that provide network traffic processing and handling for various protocols.
    * A command-line tool that can dump network traffic and provide netcat-like functionality for a variety of prevalent protocols.
    * A proxy server that enables applications to send/receive and forward traffic over various protocols via proxy address, socket, or API (TBD)
    * An embedded network stack for bare metal applications that efficiently processes network traffic with low latency and overhead.

2. NLRS should provide store-and-forward functionality for network traffic it processes via DTN/LTP (Delay/Disruption Tolerant Networking/Licklider Transport Protocol) and possibly the IPFS protocol


## Architectural Overview

## Components

PCAP Interface: Send and Receive packets via sniffing and injection

IP over Serial Support (SLIP) Interface: Send and receive packets over a serial connection, including those created by Hypervisors

Packet Processing

Virtual Network Interfaces

Socket Interfaces

Configuration API

Monitoring API

Embedded key/value storage

Network Stack
    Ethernet
    IPv4, IPv6, ARP
    ICMPv4, ICMPv6, TCP, UDP, SCTP
    DNS, DHCP, TFTP, PXE/BOOTP, HTTP, TLS, Telnet, SSH

### Libraries

### Command Line Tool

### Proxy Server

### Embedded Network Stack

## Supported Protocols

* Ethernet
* IPv4
* IPv6
* ARP
* ICMPv4
* ICMPv6
* TCP
* UDP
* SCTP
* HTTP
* TLS
* DNS
* DHCP
* TFTP
* PXE/BOOTP
* Telnet, SSH

## Data Structures and Storage

## Security Considerations



