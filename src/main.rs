extern crate clap;
extern crate kernel32;
extern crate libc;
extern crate num;
extern crate user32;
extern crate winapi;
extern crate yaml_rust;
#[macro_use]
extern crate num_derive;

use clap::{Arg, App};
// use yaml_rust::{YamlLoader};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use serde::{Serialize, Deserialize};
use std::net::Ipv4Addr;

mod pcap;
mod config;

fn main() {
    println!("netloom_rs starting!");

    // create and parse command line using clap
    // https://docs.rs/clap/2.33.0/clap/
    let matches = App::new("NetloomRS")
        .version("0.1")
        .author("Josh M. <jm@5thcol.tech>")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("config file to use")
            .takes_value(true))
        .get_matches();

    // load specifed or default config file
    // load file using open from rust
    // https://doc.rust-lang.org/rust-by-example/std_misc/file/open.html
    let config_file = matches.value_of("config").unwrap_or("default_config.yml");
    println!("config file: {}", config_file);
    let config_file_path = Path::new(config_file);
    let display = config_file_path.display();
    let mut config_fd = match File::open(&config_file_path) {
        Err(why) => panic!("couldnt open {}: {}", display, why.description()),
        Ok(config_fd) => config_fd,
    };

    let mut yaml_str = String::new();
    match config_fd.read_to_string(&mut yaml_str) {
        Err(why) => panic!("couldnt read {}: {}", display, why.description()),
        Ok(_) => println!("file read"),
    };

    // https://crates.io/crates/yaml-rust
    // https://serde.rs/#data-formats
    // https://docs.rs/serde_yaml/0.8.11/serde_yaml/fn.from_str.html
    let config : config::Config = match serde_yaml::from_str(&yaml_str) {
        Err(why) => panic!("couldn't parse {}", why.description()),
        Ok(config) => config,
    };


    //Ok(());

    // get pcap interface by ip address
    println!("getting list of adapters");

    let pcap_info : Vec<pcap::PcapIfcInfo> = pcap::get_net_ifcs();



    // https://doc.rust-lang.org/std/vec/struct.Vec.html
    let mut tgt_pcap_info : pcap::PcapIfcInfo = {name: "", 
                                                 descritpion: "", 
                                                 addresses: Vec::new()};
    let mut found : bool = false;
    for pi in &pcap_info {
        println!("name: {}, desc: {}", pi.name, pi.description);
        for ai in &pi.addresses {
            if ai.addr.family == pcap::AddressFamily::AF_INET {
                let pcap_addr = Ipv4Addr::new(ai.addr.data[0], ai.addr.data[1], ai.addr.data[2], ai.addr.data[3]);
                for net_dev in &config.network_devices {
                    let tgt_addr = net_dev.address.parse::<Ipv4Addr>().unwrap();
                    if tgt_addr == pcap_addr {
                        tgt_pcap_info.name = (*pi).name.clone();
                        tgt_pcap_info.description = (*pi).description;
                        tgt_pcap_info.addresses = (*pi).addresses;
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }
    }

    println!("finished!");

    return;
}
