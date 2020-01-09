///
/// ## main.rs
///
/// Main program source file
///
/// ### note
///
///  in some cases where the call to get adapters finds only one device on windows, this is because the npcap driver is not loaded properly. Re-load/re-install npcap to fix this issue. Does this happen after every reboot or just after each update to windows?
///
extern crate clap;
extern crate kernel32;
extern crate libc;
extern crate num;
extern crate num_derive;
extern crate user32;
extern crate winapi;
extern crate yaml_rust;

use clap::{App, Arg};
use log::{debug, error, info, warn};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

mod arp;
mod config;
mod ethernet;
mod ip_proto;
mod ipv4;
mod ipv6;
mod packet_data;
mod packet_headers;
mod packet_info;
mod pcap;
mod tcp;
mod transport_proto;
mod udp;
mod util;

use crate::ethernet::{EtherType, EthernetFrame};
use crate::ip_proto::Ipv4Proto;
use crate::ipv4::Ipv4Header;
use crate::ipv6::Ipv6Header;
use crate::packet_info::PacketInfo;
use crate::tcp::TcpHeader;
use crate::udp::UdpHeader;
use config::Config;

fn main() {
    let _result = util::setup_logger();
    // let window = initscr();
    // window.keypad(true);
    // window.nodelay(true);

    info!("netloom_rs starting");

    // create and parse command line using clap
    // https://docs.rs/clap/2.33.0/clap/
    let matches = App::new("NetloomRS")
        .version("0.1")
        .author("Josh M. <jm@5thcol.tech>")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("config file to use")
                .takes_value(true),
        )
        .get_matches();

    // load specifed or default config file
    // load file using open from rust
    // https://doc.rust-lang.org/rust-by-example/std_misc/file/open.html
    let config_file = matches.value_of("config").unwrap_or("default_config.yml");
    debug!("config file: {}", config_file);
    let config_file_path = Path::new(config_file);
    let display = config_file_path.display();
    let mut config_fd = match File::open(&config_file_path) {
        Err(why) => panic!("couldnt open {}: {}", display, why.description()),
        Ok(config_fd) => config_fd,
    };

    let mut yaml_str = String::new();
    match config_fd.read_to_string(&mut yaml_str) {
        Err(why) => panic!("couldnt read {}: {}", display, why.description()),
        Ok(_) => debug!("file read"),
    };

    // https://crates.io/crates/yaml-rust
    // https://serde.rs/#data-formats
    // https://docs.rs/serde_yaml/0.8.11/serde_yaml/fn.from_str.html
    let config: Config = match serde_yaml::from_str(&yaml_str) {
        Err(why) => panic!("couldn't parse {}", why.description()),
        Ok(config) => config,
    };

    let ifc_info: pcap::PcapIfcInfo = match pcap::get_pcap_ifc_by_ip4addr(&config) {
        Err(why) => panic!("failed to get interface: {}", why),
        Ok(ifc_info) => ifc_info,
    };

    // get pcap capture handle
    let cap_handle: *mut pcap::pcap_t = match pcap::get_cap_handle(&ifc_info) {
        Err(why) => panic!("failed to get pcap handle: {}", why),
        Ok(cap_handle) => cap_handle,
    };

    // set capture timeout
    pcap::set_pcap_timeout(cap_handle, 1000);

    // activate handle
    if !pcap::activate_pcap_handle(cap_handle) {
        error!("failed to activate pcap handle");
        pcap::close_cap_handle(cap_handle);
        return;
    }

    // capture packets using capture handle
    // todo: loop and capture packets
    let mut count: u32 = 0;
    loop {
        if config.max_loop > 0 && count >= config.max_loop { break; }

        let mut pkt_info = PacketInfo::new();
        pkt_info.packet_data = match pcap::get_packet(cap_handle) {
            Err(why) => panic!("failed to get packet: {}", why),
            Ok(pkt) => pkt,
        };
        info!("got packet");

        // todo: parse packets
        let ether_frame = ethernet::EthernetFrame::new(&pkt_info.packet_data.data[0..]);
        info!("Ethernet Header: {}", ether_frame.to_string());
        pkt_info
            .headers
            .push(packet_headers::PacketHeader::Ethernet(ether_frame));

        let mut frame_ptr = std::mem::size_of::<EthernetFrame>();

        let mut ip_proto: Ipv4Proto = Ipv4Proto::Reserved;

        match ether_frame.ether_type {
            EtherType::Arp => {
                let arp_msg = arp::ArpPacket::new(&pkt_info.packet_data.data[frame_ptr..]);
                pkt_info
                    .headers
                    .push(packet_headers::PacketHeader::Arp(arp_msg));
                info!("ARP Message: {}", arp_msg.to_string());
            }
            EtherType::Ipv4 => {
                let ipv4_hdr = ipv4::Ipv4Header::new(&pkt_info.packet_data.data[frame_ptr..]);
                info!("IPv4 Header: {}", ipv4_hdr.to_string());
                pkt_info
                    .headers
                    .push(packet_headers::PacketHeader::Ipv4(ipv4_hdr));
                frame_ptr += std::mem::size_of::<Ipv4Header>();
                ip_proto = ipv4_hdr.proto;
            }
            EtherType::Ipv6 => {
                let ipv6_hdr = Ipv6Header::new(&pkt_info.packet_data.data[frame_ptr..]);
                info!("IPv6 Header: {}", ipv6_hdr.to_string());
                pkt_info
                    .headers
                    .push(packet_headers::PacketHeader::Ipv6(ipv6_hdr));
                frame_ptr += std::mem::size_of::<Ipv6Header>();
                ip_proto = ipv6_hdr.next_hdr;
            }
            _ => info!(
                "unhandled packet type: {:04X}",
                ether_frame.ether_type as u16
            ),
        }
        count += 1;

        if ether_frame.ether_type == EtherType::Ipv4 || ether_frame.ether_type == EtherType::Ipv6 {
            match ip_proto {
                Ipv4Proto::Udp => {
                    let udp_hdr = UdpHeader::new(&pkt_info.packet_data.data[frame_ptr..]);
                    info!("UDP Header: {}", udp_hdr.to_string());
                    pkt_info
                        .headers
                        .push(packet_headers::PacketHeader::Udp(udp_hdr));
                    frame_ptr += std::mem::size_of::<UdpHeader>();
                }
                Ipv4Proto::Tcp => {
                    let tcp_hdr = TcpHeader::new(&pkt_info.packet_data.data[frame_ptr..]);
                    info!(
                        "TCP Header: {:?}",
                        tcp_hdr.to_string(
                            &pkt_info.packet_data.data
                                [frame_ptr + std::mem::size_of::<TcpHeader>()..]
                        )
                    );
                    frame_ptr += (tcp_hdr.data_off() * 32) as usize;
                    pkt_info
                        .headers
                        .push(packet_headers::PacketHeader::Tcp(tcp_hdr));

                    // process based on port
                    // if tcp_hdr.src_port == 80 || tcp_hdr.dst_port == 80 {

                    // }
                }
                _ => warn!("unprocessed IP proto: {:?}", ip_proto),
            }
        }

        // Guess at traffic based on port
    } // End of packet capture loop

    // close pcap handle
    if !cap_handle.is_null() {
        pcap::close_cap_handle(cap_handle);
    }

    debug!("finished!");
}

// END OF FILE
