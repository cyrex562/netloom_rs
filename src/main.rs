extern crate libc;
extern crate winapi;
extern crate user32;
extern crate kernel32;
extern crate clap;
extern crate num;
#[macro_use]
extern crate num_derive;

mod pcap;

use libc::{c_char, c_int, c_uint, c_ushort, c_uchar, c_long, FILE};
use std::ptr;
use std::ffi::CString;

// todo: define error codes




fn main() {
    println!("netloom_rs starting!");

    // get pcap interface by ip address
    println!("getting list of adapters");
    unsafe {
        let mut err_buf : [c_char; 0xff] = [0; 0xff];
        let mut dev_list : *mut pcap::pcap_if_t = ptr::null_mut();
        let dev_list_ptr = &mut dev_list as *mut *mut pcap::pcap_if_t;
        // let err_buf_ptr = err_buf as *mut c_char;
        let result = pcap::pcap_findalldevs(dev_list_ptr, err_buf.as_mut_ptr());
        let mut curr_dev : *mut pcap::pcap_if_t = dev_list;
        let mut out_ifc_info: Vec<pcap::PcapIfcInfo> = Vec::new();
        while !curr_dev.is_null() {
            let dev_name_cstr= CString::from_raw((*curr_dev).name);
            let dev_desc_cstr = CString::from_raw((*curr_dev).description);
            let dev_name_str_result = dev_name_cstr.into_string();
            let dev_desc_str_result = dev_desc_cstr.into_string();
            assert_eq!(dev_name_str_result.is_ok(), true);
            assert_eq!(dev_desc_str_result.is_ok(), true);
            let dev_name = dev_name_str_result.unwrap();
            let dev_desc = dev_desc_str_result.unwrap();
            println!("name: {}", dev_name);
            println!("description: {}", dev_desc);

            let mut info  = pcap::PcapIfcInfo {
                name : dev_name,
                description : dev_desc,
                addresses : Vec::new()};

            let mut addresses = (*curr_dev).addresses;
            while !addresses.is_null() {

                let netmask: pcap::PcapAddr;
                // let netmask = (*addresses).netmask;
                if !(*addresses).netmask.is_null() {
                    netmask = pcap::PcapAddr {
                    family : num::FromPrimitive::from_u16((*(*addresses).netmask).sa_family).unwrap(),
                    data : [(*(*addresses).netmask).sa_data[0],
                        (*(*addresses).netmask).sa_data[1],
                        (*(*addresses).netmask).sa_data[2],
                        (*(*addresses).netmask).sa_data[3],
                        (*(*addresses).netmask).sa_data[4],
                        (*(*addresses).netmask).sa_data[5],
                        (*(*addresses).netmask).sa_data[6],
                        (*(*addresses).netmask).sa_data[7],
                        (*(*addresses).netmask).sa_data[8],
                        (*(*addresses).netmask).sa_data[9],
                        (*(*addresses).netmask).sa_data[10],
                        (*(*addresses).netmask).sa_data[11],
                        (*(*addresses).netmask).sa_data[12],
                        (*(*addresses).netmask).sa_data[13],
                        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
                    };
                } else {
                    netmask = pcap::PcapAddr {
                        family : pcap::AddressFamily::AF_UNSPEC,
                        data : [0; 32],
                    };
                }
                
                let addr: pcap::PcapAddr;
                // let addr = (*addresses).addr;
                if !(*addresses).addr.is_null() {
                    addr = pcap::PcapAddr {
                    family : num::FromPrimitive::from_u16((*(*addresses).addr).sa_family).unwrap(),
                    data : [(*(*addresses).addr).sa_data[0],
                        (*(*addresses).addr).sa_data[1],
                        (*(*addresses).addr).sa_data[2],
                        (*(*addresses).addr).sa_data[3],
                        (*(*addresses).addr).sa_data[4],
                        (*(*addresses).addr).sa_data[5],
                        (*(*addresses).addr).sa_data[6],
                        (*(*addresses).addr).sa_data[7],
                        (*(*addresses).addr).sa_data[8],
                        (*(*addresses).addr).sa_data[9],
                        (*(*addresses).addr).sa_data[10],
                        (*(*addresses).addr).sa_data[11],
                        (*(*addresses).addr).sa_data[12],
                        (*(*addresses).addr).sa_data[13],
                        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
                    };
                } else {
                    addr = pcap::PcapAddr {
                        family : pcap::AddressFamily::AF_UNSPEC,
                        data : [0; 32],
                    };
                }
                

                //let broadaddr = (*addresses).broadaddr;
                let bcast : pcap::PcapAddr;
                if !(*addresses).broadaddr.is_null() {
                    bcast = pcap::PcapAddr {
                    family : num::FromPrimitive::from_u16((*(*addresses).broadaddr).sa_family).unwrap(),
                    data : [(*(*addresses).broadaddr).sa_data[0],
                        (*(*addresses).broadaddr).sa_data[1],
                        (*(*addresses).broadaddr).sa_data[2],
                        (*(*addresses).broadaddr).sa_data[3],
                        (*(*addresses).broadaddr).sa_data[4],
                        (*(*addresses).broadaddr).sa_data[5],
                        (*(*addresses).broadaddr).sa_data[6],
                        (*(*addresses).broadaddr).sa_data[7],
                        (*(*addresses).broadaddr).sa_data[8],
                        (*(*addresses).broadaddr).sa_data[9],
                        (*(*addresses).broadaddr).sa_data[10],
                        (*(*addresses).broadaddr).sa_data[11],
                        (*(*addresses).broadaddr).sa_data[12],
                        (*(*addresses).broadaddr).sa_data[13],
                        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
                    };
                } else {
                    bcast = pcap::PcapAddr {
                        family : pcap::AddressFamily::AF_UNSPEC,
                        data : [0; 32],
                    };
                }
                

                // let dstaddr = (*addresses).dstaddr;
                let dest: pcap::PcapAddr;
                if !(*addresses).dstaddr.is_null() {
                    dest = pcap::PcapAddr {
                    family : num::FromPrimitive::from_u16((*(*addresses).dstaddr).sa_family).unwrap(),
                    data : [(*(*addresses).dstaddr).sa_data[0],
                        (*(*addresses).dstaddr).sa_data[1],
                        (*(*addresses).dstaddr).sa_data[2],
                        (*(*addresses).dstaddr).sa_data[3],
                        (*(*addresses).dstaddr).sa_data[4],
                        (*(*addresses).dstaddr).sa_data[5],
                        (*(*addresses).dstaddr).sa_data[6],
                        (*(*addresses).dstaddr).sa_data[7],
                        (*(*addresses).dstaddr).sa_data[8],
                        (*(*addresses).dstaddr).sa_data[9],
                        (*(*addresses).dstaddr).sa_data[10],
                        (*(*addresses).dstaddr).sa_data[11],
                        (*(*addresses).dstaddr).sa_data[12],
                        (*(*addresses).dstaddr).sa_data[13],
                        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
                    };
                } else {
                    dest =  pcap::PcapAddr {
                        family : pcap::AddressFamily::AF_UNSPEC,
                        data : [0; 32],
                    };
                }
                

                let addr_info = pcap::PcapIfcAddrInfo {
                    netmask: netmask,
                    addr : addr,
                    bcast_addr : bcast,
                    dest_addr : dest,
                };

                info.addresses.push(addr_info);

                // tail
                addresses = (*addresses).next;
            }

            out_ifc_info.push(info);

            // tail
            curr_dev = (*curr_dev).next;
        }
        pcap::pcap_freealldevs(dev_list);
    }

    println!("finished!");

    // return;
}
