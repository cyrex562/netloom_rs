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

unsafe fn extract_addr_netmask(addresses: *mut pcap::pcap_addr) -> pcap::PcapAddr {
    let netmask: pcap::PcapAddr;
    if !(*addresses).netmask.is_null() {
        netmask = pcap::PcapAddr {
            family: num::FromPrimitive::from_u16((*(*addresses).netmask).sa_family).unwrap(),
            data: [
                (*(*addresses).netmask).sa_data[0],
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
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        };
    } else {
        netmask = pcap::PcapAddr {
            family: pcap::AddressFamily::AF_UNSPEC,
            data: [0; 32],
        };
    }
    return netmask;
}

unsafe fn extract_addr_addr(addresses: *mut pcap::pcap_addr) -> pcap::PcapAddr {
    let addr: pcap::PcapAddr;
                // let addr = (*addresses).addr;
                if !(*addresses).addr.is_null() {
                    addr = pcap::PcapAddr {
                        family: num::FromPrimitive::from_u16((*(*addresses).addr).sa_family)
                            .unwrap(),
                        data: [
                            (*(*addresses).addr).sa_data[0],
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
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                    };
                } else {
                    addr = pcap::PcapAddr {
                        family: pcap::AddressFamily::AF_UNSPEC,
                        data: [0; 32],
                    };
                }
                return addr;
}

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
                let netmask: pcap::PcapAddr = extract_addr_netmask(addresses);
                
                

                //let broadaddr = (*addresses).broadaddr;
                let bcast: pcap::PcapAddr;
                if !(*addresses).broadaddr.is_null() {
                    bcast = pcap::PcapAddr {
                        family: num::FromPrimitive::from_u16((*(*addresses).broadaddr).sa_family)
                            .unwrap(),
                        data: [
                            (*(*addresses).broadaddr).sa_data[0],
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
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                    };
                } else {
                    bcast = pcap::PcapAddr {
                        family: pcap::AddressFamily::AF_UNSPEC,
                        data: [0; 32],
                    };
                }

                // let dstaddr = (*addresses).dstaddr;
                let dest: pcap::PcapAddr;
                if !(*addresses).dstaddr.is_null() {
                    dest = pcap::PcapAddr {
                        family: num::FromPrimitive::from_u16((*(*addresses).dstaddr).sa_family)
                            .unwrap(),
                        data: [
                            (*(*addresses).dstaddr).sa_data[0],
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
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                    };
                } else {
                    dest = pcap::PcapAddr {
                        family: pcap::AddressFamily::AF_UNSPEC,
                        data: [0; 32],
                    };
                }

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
