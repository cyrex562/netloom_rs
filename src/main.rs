extern crate clap;
extern crate kernel32;
extern crate libc;
extern crate num;
extern crate user32;
extern crate winapi;
#[macro_use]
extern crate num_derive;

mod pcap;

use libc::c_char;
use std::ffi::CString;
use std::ptr;

// todo: define error codes





fn get_net_ifcs() -> Vec<pcap::PcapIfcInfo> {
    let mut err_buf: [c_char; 0xff] = [0; 0xff];
    let mut dev_list: *mut pcap::pcap_if_t = ptr::null_mut();
    let dev_list_ptr = &mut dev_list as *mut *mut pcap::pcap_if_t;
    let result = unsafe {
        let result = pcap::pcap_findalldevs(dev_list_ptr, err_buf.as_mut_ptr());
    };
    let mut curr_dev: *mut pcap::pcap_if_t = dev_list;
    let mut out_ifc_info: Vec<pcap::PcapIfcInfo> = Vec::new();
    while !curr_dev.is_null() {
        // parse device name
        let dev_name_cstr: CString = unsafe { CString::from_raw((*curr_dev).name) };
        let dev_name_str_result = dev_name_cstr.into_string();
        assert_eq!(dev_name_str_result.is_ok(), true);
        let dev_name = dev_name_str_result.unwrap();
        let dev_desc_cstr = unsafe { CString::from_raw((*curr_dev).description) };
        let dev_desc_str_result = dev_desc_cstr.into_string();
        assert_eq!(dev_desc_str_result.is_ok(), true);
        let dev_desc = dev_desc_str_result.unwrap();

        println!("name: {}", dev_name);
        println!("description: {}", dev_desc);

        let mut info = pcap::PcapIfcInfo {
            name: dev_name,
            description: dev_desc,
            addresses: Vec::new(),
        };

        unsafe {
            let mut addresses = (*curr_dev).addresses;
            while !addresses.is_null() {
                let netmask: pcap::PcapAddr = pcap::extract_addr_netmask(addresses);
                let addr: pcap::PcapAddr = pcap::extract_addr_addr(addresses);
                let bcast: pcap::PcapAddr = pcap::extract_addr_bcast(addresses);
                let dest: pcap::PcapAddr = pcap::extract_addr_dest(addresses);
                let addr_info = pcap::PcapIfcAddrInfo {
                    netmask: netmask,
                    addr: addr,
                    bcast_addr: bcast,
                    dest_addr: dest,
                };
                info.addresses.push(addr_info);
                // tail
                addresses = (*addresses).next;
            } // end of addresses while loop
        }; // end of unsafe block
        out_ifc_info.push(info);
        // tail
        curr_dev = (*curr_dev).next;
    } // end of interfaces while loop
      // pcap::pcap_freealldevs(dev_list);
    return out_ifc_info;
}

fn main() {
    println!("netloom_rs starting!");

    // get pcap interface by ip address
    println!("getting list of adapters");

    // pcap_info = get_net_ifcs();

    println!("finished!");

    // return;
}
