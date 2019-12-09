extern crate clap;
extern crate kernel32;
extern crate libc;
extern crate num;
extern crate user32;
extern crate winapi;
extern crate yaml_rust;
extern crate num_derive;

use clap::{App, Arg};
use log::{debug, error, info, trace, warn};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::{stdin};
use std::path::Path;
mod config;
mod ethernet;
mod packet_data;
mod packet_headers;
mod packet_info;
mod pcap;
mod util;

use crate::packet_info::PacketInfo;
use config::Config;

fn main() {
    let _result = util::setup_logger();

    info!("netloom_rs starting!");

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
        if config.max_loop > 0 {
            if count >= config.max_loop {
                break;
            }
        }
        let mut pkt_info = PacketInfo::new();
        pkt_info.packet_data = match pcap::get_packet(cap_handle) {
            Err(why) => panic!("failed to get packet: {}", why),
            Ok(pkt) => pkt,
        };
        
        info!("got packet");


        // todo: parse packets
        let _ether_frame: ethernet::EthernetFrame =
            ethernet::EthernetFrame::parse(&pkt_info.packet_data.data);
        pkt_info
            .headers
            .push(packet_headers::PacketHeader::Ethernet(_ether_frame));
        
        count += 1; 

    }

    // close pcap handle
    if !cap_handle.is_null() {
        pcap::close_cap_handle(cap_handle);
    }

    debug!("finished!");
    return;
}
