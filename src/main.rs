extern crate clap;
extern crate kernel32;
extern crate libc;
extern crate num;
extern crate user32;
extern crate winapi;
#[macro_use]
extern crate num_derive;

use clap::{Arg, App};

mod pcap;

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
    
    let config = matches.value_of("config").unwrap_or("default.yml")
    println!("config file: {}", config);

    // load specifed or default config file


    // get pcap interface by ip address
    println!("getting list of adapters");

    let _pcap_info = pcap::get_net_ifcs();

    println!("finished!");

    return;
}
