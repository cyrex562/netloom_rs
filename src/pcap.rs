// todo: get rid of this warn mask
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::FILE;
use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_ushort, sockaddr};
use log::{debug, error, warn};
use num_derive::FromPrimitive;
use std::ffi::CString;
use std::ptr;
use std::result;
// use num_traits::FromPrimitive;
use std::net::Ipv4Addr;

use crate::config::Config;
use crate::packet_data::PacketData;

// #define PCAP_IF_LOOPBACK				0x00000001	/* interface is loopback */
const PCAP_IF_LOOPBACK: u32 = 0x0000_0001;
// #define PCAP_IF_UP					0x00000002	/* interface is up */
const PCAP_IF_UP: u32 = 0x0000_0002;
// #define PCAP_IF_RUNNING					0x00000004	/* interface is running */
const PCAP_IF_RUNNING: u32 = 0x0000_0004;
// #define PCAP_IF_WIRELESS				0x00000008	/* interface is wireless (*NOT* necessarily Wi-Fi!) */
const PCAP_IF_WIRELESS: u32 = 0x0000_0008;
// #define PCAP_IF_CONNECTION_STATUS			0x00000030	/* connection status: */
const PCAP_IF_CONNECTION_STATUS: u32 = 0x0000_0030;
// #define PCAP_IF_CONNECTION_STATUS_UNKNOWN		0x00000000	/* unknown */
const PCAP_IF_CONNECTION_STATUS_UNKNOWN: u32 = 0x0000_0000;
// #define PCAP_IF_CONNECTION_STATUS_CONNECTED		0x00000010	/* connected */
const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 0x0000_0010;
// #define PCAP_IF_CONNECTION_STATUS_DISCONNECTED		0x00000020	/* disconnected */
const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x0000_0020;
// #define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE	0x00000030	/* not applicable */
const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE: u32 = 0x0000_0030;

// #define PCAP_ERROR			-1	/* generic error code */
const PCAP_ERROR: i32 = -1;
// #define PCAP_ERROR_BREAK		-2	/* loop terminated by pcap_breakloop */
const PCAP_ERROR_BREAK: i32 = -2;
// #define PCAP_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */
const PCAP_ERROR_NOT_ACTIVATED: i32 = -3;
// #define PCAP_ERROR_ACTIVATED		-4	/* the operation can't be performed on already activated captures */
const PCAP_ERROR_ACTIVATED: i32 = -4;
// #define PCAP_ERROR_NO_SUCH_DEVICE	-5	/* no such device exists */
const PCAP_ERROR_NO_SUCH_DEVICE: i32 = -5;
// #define PCAP_ERROR_RFMON_NOTSUP		-6	/* this device doesn't support rfmon (monitor) mode */
const PCAP_ERROR_RFMON_NOTSUP: i32 = -6;
// #define PCAP_ERROR_NOT_RFMON		-7	/* operation supported only in monitor mode */
const PCAP_ERROR_NOT_RFMON: i32 = -7;
// #define PCAP_ERROR_PERM_DENIED		-8	/* no permission to open the device */
const PCAP_ERROR_PERM_DENIED: i32 = -8;
// #define PCAP_ERROR_IFACE_NOT_UP		-9	/* interface isn't up */
const PCAP_ERROR_IFACE_NOT_UP: i32 = -9;
// #define PCAP_ERROR_CANTSET_TSTAMP_TYPE	-10	/* this device doesn't support setting the time stamp type */
const PCAP_ERROR_CANTSET_TSTAMP_TYPE: i32 = -10;
// #define PCAP_ERROR_PROMISC_PERM_DENIED	-11	/* you don't have permission to capture in promiscuous mode */
const PCAP_ERROR_PROMISC_PERM_DENIED: i32 = -11;
// #define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP -12  /* the requested time stamp precision is not supported */
const PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: i32 = -12;

// #define PCAP_WARNING			1	/* generic warning code */
const PCAP_WARNING: i32 = 1;
// #define PCAP_WARNING_PROMISC_NOTSUP	2	/* this device doesn't support promiscuous mode */
const PCAP_WARNING_PROMISC_NOTSUP: i32 = 2;
// #define PCAP_WARNING_TSTAMP_TYPE_NOTSUP	3	/* the requested time stamp type is not supported */
const PCAP_WARNING_TSTAMP_TYPE_NOTSUP: i32 = 3;

#[derive(FromPrimitive, Clone, Copy)]
pub enum AddressFamily {
    AF_UNSPEC = 0,
    AF_UNIX = 1,      // unix domain socket
    AF_INET = 2,      // IP Protocol
    AF_AX25 = 3,      // Amateur radio AX.25
    AF_IPX = 4,       // Novell IPX
    AF_APPLETALK = 5, // AppleTalk DDP
    AF_NETROM = 6,    // Amateur Radio NetROM
    AF_BRIDGE = 7,    // Multi-protocol bridge
    AF_AAL25 = 8,     // Reserved for Werner's ATM
    AF_X25 = 9,       // Reserved for X.25 project
    AF_INET6 = 10,    // IP Version 6
    AF_ROSE = 11,     // Amateur Radio X.25 PLP
    AF_DECNET = 12,   // Reserved for DECnet project
    AF_NETBEUI = 13,  // Reserved for 802.2LLC project
    AF_SECURITY = 14, // Security callback pseudo AF
    AF_KEY = 15,      // PF_KEY key management API
    AF_NETLINK = 16,  // netlink
    // AF_ROUTE = AF_NETLINK,
    AF_PACKET = 17,     // Packet family
    AF_ASH = 18,        // Ash
    AF_ECONET = 19,     // Acorn Econet
    AF_ATMSVC = 20,     // ATM SVCs
    AF_RDS = 21,        // RDS Sockets
    AF_SNA = 22,        // Linux SNA Project
    AF_IRDA = 23,       // IRDA Sockets
    AF_PPPOX = 24,      // PPPoX sockets
    AF_WANPIPE = 25,    // Wanpipe API sockets
    AF_LLC = 26,        // Linux LLC
    AF_IB = 27,         // native infiniband address
    AF_MPLS = 28,       // MPLS
    AF_CAN = 29,        // Controller Area Network
    AF_TIPC = 30,       // TIPC sockets
    AF_BLUETOOTH = 31,  // Bluetooth sockets
    AF_IUCV = 32,       // IUCV sockets
    AF_RXRPC = 33,      // RxRPC sockets
    AF_ISDN = 34,       // mISDN sockets
    AF_PHONET = 35,     // Phonet sockets
    AF_IEEE802154 = 36, // IEEE802154 sockets
    AF_CAIF = 37,       // CAIF sockets
    AF_ALG = 38,        // Algorithm sockets
    AF_NFC = 39,        // NFC sockets
    AF_VSOCK = 40,      // vSockets
    AF_KCM = 41,        // Kernel Connection Multiplexor
    AF_QIPCRTR = 42,    // Qualcomm IPC router
    AF_SMC = 43,        // SMC sockets PF_SMC
    AF_XD = 44,         // XDP sockets
    AF_MAX = 45,        // highest for now
}

pub fn check_addr_family(val1: &AddressFamily, val2: &AddressFamily) -> bool {
    *val1 as u32 == *val2 as u32
}

type time_t = c_long;
type suseconds_t = c_long;

// https://doc.rust-lang.org/nomicon/ffi.html

// #[repr(C)]
// pub struct pcap_t {
//     _private: [u8; 0],
// }

pub enum pcap_t {}

#[repr(C)]
pub struct pcap_dumper_t {
    _private: [u8; 0],
}
// #[repr(C)]
// pub struct sockaddr {
//     pub sa_family: c_ushort,
//     pub sa_data: [u8; 14],
// }

// PCAP_IF_LOOPBACK set if the device is a loopback interface
// PCAP_IF_UP set if the device is up
// PCAP_IF_RUNNING set if the device is running
// PCAP_IF_WIRELESS set if the device is a wireless interface; this includes IrDA as well as radio-based networks such as IEEE 802.15.4 and IEEE 802.11, so it doesn't just mean Wi-Fi
// PCAP_IF_CONNECTION_STATUS a bitmask for an indication of whether the adapter is connected or not; for wireless interfaces, "connected" means "associated with a network"
// The possible values for the connection status bits are:
// PCAP_IF_CONNECTION_STATUS_UNKNOWN it's unknown whether the adapter is connected or not
// PCAP_IF_CONNECTION_STATUS_CONNECTED the adapter is connected
// PCAP_IF_CONNECTION_STATUS_DISCONNECTED the adapter is disconnected
// PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE the notion of "connected" and "disconnected" don't apply to this interface; for example, it doesn't apply to a loopback device
#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_if_t {
    pub next: *mut pcap_if_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut pcap_addr,
    pub flags: c_uint,
}

#[repr(C)]
pub struct pcap_addr {
    pub next: *mut pcap_addr,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}

#[repr(C)]
pub struct bpf_insn {
    code: c_ushort,
    jt: c_uchar,
    jf: c_uchar,
    k: c_int,
}

#[repr(C)]
pub struct bpf_program {
    bf_len: c_uint,
    bf_isns: *mut bpf_insn,
}

#[repr(C)]
pub struct timeval {
    tv_sec: time_t,
    tv_usec: suseconds_t,
}

#[repr(C)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: u32,
    pub len: u32,
}

#[cfg(target_os = "linux")]
#[link(name = "pcap")]
extern "C" {
    // create a live capture handle
    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t *pcap_create(const char *source, char *errbuf);
    pub fn pcap_create(source: *const c_uchar, errbuf: *mut c_char) -> *mut pcap_t;

    // activate a capture handle
    // int pcap_activate(pcap_t *p);
    pub fn pcap_activate(p: *mut pcap_t) -> c_int;

    // construct a list of network devices
    // int 	pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
    pub fn pcap_findalldevs(alldevsp: *mut *mut pcap_if_t, errbuf: *mut c_char) -> c_int;

    // free an interface list
    // void 	pcap_freealldevs (pcap_if_t *alldevsp)
    pub fn pcap_freealldevs(alldevsp: *mut pcap_if_t);

    // find the default device on which to capture
    // char * 	pcap_lookupdev (char *errbuf)
    // this function is deprecated
    // fn pcap_lookupdev(errbuf : *mut c_char) -> *mut c_char;

    // open a saved capture file for reading
    // pcap_t *pcap_open_offline(const char *fname, char *errbuf);
    // pcap_t *pcap_open_offline_with_tstamp_precision(const char *fname, u_int precision, char *errbuf);
    // pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf);
    // pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *fp, u_int precision, char *errbuf);
    pub fn pcap_open_offline(fname: *const c_char, errbuf: *mut c_char) -> *mut pcap_t;

    // todo: get linktype enum
    // open a fake pcap_t for compiling filters or opening a capture for output
    // pcap_t *pcap_open_dead(int linktype, int snaplen);
    // pcap_t *pcap_open_dead_with_tstamp_precision(int linktype, int snaplen,     u_int precision);
    pub fn pcap_open_dead(linktype: c_int, snaplen: c_int) -> *mut pcap_t;

    // close a pcap_t
    // void pcap_close(pcap_t *p);
    pub fn pcap_close(p: *mut pcap_t);

    // set the snapshot length for a not-yet-activated capture handle
    // int pcap_set_snaplen(pcap_t *p, int snaplen);
    pub fn pcap_set_snaplen(p: *mut pcap_t, snaplen: c_int) -> c_int;

    // get the snapshot len
    // int pcap_snapshot(pcap_t *p);
    pub fn pcap_snapshot(p: *mut pcap_t) -> c_int;

    // set the promiscuous mode for a not-yet-activated pcap handle
    // int pcap_set_promisc(pcap_t *p, int promisc);
    pub fn pcap_set_promisc(p: *mut pcap_t, promisc: c_int) -> c_int;

    // set capture protocol for a not-yet-activated capture handle
    // int pcap_set_protocol_linux(pcap_t *p, int protocol);

    // set monitor mode for a not-yet-activated capture handle
    // int pcap_set_rfmon(pcap_t *p, int rfmon);

    // check whether monitor mode can be set for a not-yet-activated capture handle
    // int pcap_can_set_rfmon(pcap_t *p);

    // set the packet buffer timeout for a not-yet-activated capture handle
    // int pcap_set_timeout(pcap_t *p, int to_ms);
    pub fn pcap_set_timeout(p: *mut pcap_t, to_ms: c_int) -> c_int;

    // set the buffer size for a not-yet-activated capture handle
    // int pcap_set_buffer_size(pcap_t *p, int buffer_size);
    pub fn pcap_set_buffer_size(p: *mut pcap_t, buffer_size: c_int) -> c_int;

    // set the time stamp type to be used by a capture device
    // int pcap_set_tstamp_type(pcap_t *p, int tstamp_type);
    pub fn pcap_set_tstamp_type(p: *mut pcap_t, tstamp_type: c_int) -> c_int;

    // get list of time stamp types supported by a capture device, and free that list
    // int pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp);
    pub fn pcap_list_tstamp_types(p: *mut pcap_t, tstamp_typesp: *mut *mut c_int) -> c_int;

    // void pcap_free_tstamp_types(int *tstamp_types);
    pub fn pcap_free_tstamp_types(tstamp_types: *mut c_int);

    // get a name or description for a time stamp value type
    // const char *pcap_tstamp_type_val_to_name(int tstamp_type);
    pub fn pcap_tstamp_type_val_to_name(tstamp_type: c_int) -> *const c_char;

    // const char *pcap_tstamp_type_val_to_description(int tstamp_type);
    pub fn pcap_tstamp_type_val_to_description(tstamp_type: c_int) -> *const c_char;

    // get the time stamp time value corresponding to a time stamp type name
    // int pcap_tstamp_type_name_to_val(const char *name);
    pub fn pcap_tstamp_type_name_to_val(name: *const c_char) -> c_int;

    // set the time stamp precision returned in captures
    // int pcap_set_tstamp_precision(pcap_t *p, int tstamp_precision);
    pub fn pcap_set_tstamp_precision(p: *mut pcap_t, tstamp_precision: c_int) -> c_int;

    // get the time stamp precision returned in captures
    // int pcap_get_tstamp_precision(pcap_t *p);
    pub fn pcap_get_tstamp_precision(p: *mut pcap_t) -> c_int;

    // get the link-layer header type
    // int pcap_datalink(pcap_t *p);
    pub fn pcap_datalink(p: *mut pcap_t) -> c_int;

    //  get the standard I/O stream for a savefile being read
    // FILE *pcap_file(pcap_t *p);
    pub fn pcap_file(p: *mut pcap_t) -> *mut FILE;

    // find out whether a savefile has the native byte order
    // int pcap_is_swapped(pcap_t *p);
    pub fn pcap_is_swapped(p: *mut pcap_t) -> c_int;

    //  get the version number of a savefile
    // int pcap_major_version(pcap_t *p);
    pub fn pcap_major_version(p: *mut pcap_t) -> c_int;

    // int pcap_minor_version(pcap_t *p);
    pub fn pcap_minor_version(p: *mut pcap_t) -> c_int;

    // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    //     const u_char **pkt_data);
    pub fn pcap_next_ex(
        p: *mut pcap_t,
        pkt_header: *mut *mut pcap_pkthdr,
        pkt_data: *mut *const c_uchar,
    ) -> c_int;

    // const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
    pub fn pcap_next(p: *mut pcap_t, h: *mut pcap_pkthdr) -> *mut c_uchar;
    // char *pcap_geterr(pcap_t *p);
    // pcap_geterr() returns the error text pertaining to the last pcap library error
    pub fn pcap_geterr(p: *mut pcap_t) -> *mut c_uchar;

// void pcap_perror(pcap_t *p, const char *prefix);
// pcap_perror() prints the text of the last pcap library error on stderr, prefixed by prefix
}

// #[cfg(target_os = "windows")]
// #[link(name = "wpcap")]

#[derive(Copy, Clone)]
pub struct PcapAddr {
    pub family: AddressFamily,
    pub data: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct PcapIfcAddrInfo {
    pub addr: PcapAddr,
    pub netmask: PcapAddr,
    pub bcast_addr: PcapAddr,
    pub dest_addr: PcapAddr,
}

#[derive(Clone)]
pub struct PcapIfcInfo {
    pub name: String,
    pub description: String,
    pub addresses: Vec<PcapIfcAddrInfo>,
}

impl PcapIfcInfo {
    pub fn new() -> PcapIfcInfo {
        PcapIfcInfo {
            name: String::new(),
            description: String::new(),
            addresses: Vec::<PcapIfcAddrInfo>::new(),
        }
    }
}

// https://doc.rust-lang.org/nomicon/working-with-unsafe.html

pub unsafe fn extract_addr_netmask(addresses: *mut pcap_addr) -> PcapAddr {
    if !(*addresses).netmask.is_null() {
        PcapAddr {
            family: num::FromPrimitive::from_u16((*(*addresses).netmask).sa_family).unwrap(),
            data: [
                (*(*addresses).netmask).sa_data[0] as u8,
                (*(*addresses).netmask).sa_data[1] as u8,
                (*(*addresses).netmask).sa_data[2] as u8,
                (*(*addresses).netmask).sa_data[3] as u8,
                (*(*addresses).netmask).sa_data[4] as u8,
                (*(*addresses).netmask).sa_data[5] as u8,
                (*(*addresses).netmask).sa_data[6] as u8,
                (*(*addresses).netmask).sa_data[7] as u8,
                (*(*addresses).netmask).sa_data[8] as u8,
                (*(*addresses).netmask).sa_data[9] as u8,
                (*(*addresses).netmask).sa_data[10] as u8,
                (*(*addresses).netmask).sa_data[11] as u8,
                (*(*addresses).netmask).sa_data[12] as u8,
                (*(*addresses).netmask).sa_data[13] as u8,
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
        }
    } else {
        PcapAddr {
            family: AddressFamily::AF_UNSPEC,
            data: [0; 32],
        }
    }
}

pub unsafe fn extract_addr_addr(addresses: *mut pcap_addr) -> PcapAddr {
    if !(*addresses).addr.is_null() {
        PcapAddr {
            family: num::FromPrimitive::from_u16((*(*addresses).addr).sa_family).unwrap(),
            data: [
                (*(*addresses).addr).sa_data[0] as u8,
                (*(*addresses).addr).sa_data[1] as u8,
                (*(*addresses).addr).sa_data[2] as u8,
                (*(*addresses).addr).sa_data[3] as u8,
                (*(*addresses).addr).sa_data[4] as u8,
                (*(*addresses).addr).sa_data[5] as u8,
                (*(*addresses).addr).sa_data[6] as u8,
                (*(*addresses).addr).sa_data[7] as u8,
                (*(*addresses).addr).sa_data[8] as u8,
                (*(*addresses).addr).sa_data[9] as u8,
                (*(*addresses).addr).sa_data[10] as u8,
                (*(*addresses).addr).sa_data[11] as u8,
                (*(*addresses).addr).sa_data[12] as u8,
                (*(*addresses).addr).sa_data[13] as u8,
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
        }
    } else {
        PcapAddr {
            family: AddressFamily::AF_UNSPEC,
            data: [0; 32],
        }
    }
}

pub unsafe fn extract_addr_bcast(addresses: *mut pcap_addr) -> PcapAddr {
    if !(*addresses).broadaddr.is_null() {
        PcapAddr {
            family: num::FromPrimitive::from_u16((*(*addresses).broadaddr).sa_family).unwrap(),
            data: [
                (*(*addresses).broadaddr).sa_data[0] as u8,
                (*(*addresses).broadaddr).sa_data[1] as u8,
                (*(*addresses).broadaddr).sa_data[2] as u8,
                (*(*addresses).broadaddr).sa_data[3] as u8,
                (*(*addresses).broadaddr).sa_data[4] as u8,
                (*(*addresses).broadaddr).sa_data[5] as u8,
                (*(*addresses).broadaddr).sa_data[6] as u8,
                (*(*addresses).broadaddr).sa_data[7] as u8,
                (*(*addresses).broadaddr).sa_data[8] as u8,
                (*(*addresses).broadaddr).sa_data[9] as u8,
                (*(*addresses).broadaddr).sa_data[10] as u8,
                (*(*addresses).broadaddr).sa_data[11] as u8,
                (*(*addresses).broadaddr).sa_data[12] as u8,
                (*(*addresses).broadaddr).sa_data[13] as u8,
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
        }
    } else {
        PcapAddr {
            family: AddressFamily::AF_UNSPEC,
            data: [0; 32],
        }
    }
}

pub unsafe fn extract_addr_dest(addresses: *mut pcap_addr) -> PcapAddr {
    if !(*addresses).dstaddr.is_null() {
        PcapAddr {
            family: num::FromPrimitive::from_u16((*(*addresses).dstaddr).sa_family).unwrap(),
            data: [
                (*(*addresses).dstaddr).sa_data[0] as u8,
                (*(*addresses).dstaddr).sa_data[1] as u8,
                (*(*addresses).dstaddr).sa_data[2] as u8,
                (*(*addresses).dstaddr).sa_data[3] as u8,
                (*(*addresses).dstaddr).sa_data[4] as u8,
                (*(*addresses).dstaddr).sa_data[5] as u8,
                (*(*addresses).dstaddr).sa_data[6] as u8,
                (*(*addresses).dstaddr).sa_data[7] as u8,
                (*(*addresses).dstaddr).sa_data[8] as u8,
                (*(*addresses).dstaddr).sa_data[9] as u8,
                (*(*addresses).dstaddr).sa_data[10] as u8,
                (*(*addresses).dstaddr).sa_data[11] as u8,
                (*(*addresses).dstaddr).sa_data[12] as u8,
                (*(*addresses).dstaddr).sa_data[13] as u8,
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
        }
    } else {
        PcapAddr {
            family: AddressFamily::AF_UNSPEC,
            data: [0; 32],
        }
    }

}

pub fn extract_dev_name(curr_dev: *mut pcap_if_t) -> String {
    unsafe {
        if (*curr_dev).name.is_null() {
            warn!("name field of interface is null");
            return "".to_string();
        }
    };

    let dev_name_cstr: CString = unsafe { CString::from_raw((*curr_dev).name) };
    let dev_name_str_result = dev_name_cstr.into_string();
    assert_eq!(dev_name_str_result.is_ok(), true);
    dev_name_str_result.unwrap()
}

pub fn extract_dev_desc(curr_dev: *mut pcap_if_t) -> String {
    unsafe {
        if (*curr_dev).description.is_null() {
            warn!("name field of interface is null");
            return "".to_string();
        }
    };

    let dev_desc_cstr = unsafe { CString::from_raw((*curr_dev).description) };
    let dev_desc_str_result = dev_desc_cstr.into_string();
    assert_eq!(dev_desc_str_result.is_ok(), true);
    dev_desc_str_result.unwrap()
}

pub fn get_net_ifcs() -> Vec<PcapIfcInfo> {
    debug!("getting network interfaces");
    let mut err_buf: [c_char; 0xff] = [0; 0xff];
    let mut dev_list: *mut pcap_if_t = ptr::null_mut();
    let dev_list_ptr = &mut dev_list as *mut *mut pcap_if_t;
    let result = unsafe { pcap_findalldevs(dev_list_ptr, err_buf.as_mut_ptr()) };
    if result != 0 {
        panic!("failed to get pcap devices");
    }

    let mut curr_dev: *mut pcap_if_t = dev_list;
    let mut out_ifc_info: Vec<PcapIfcInfo> = Vec::new();

    unsafe {
        while !curr_dev.is_null() {
            let mut info = PcapIfcInfo {
                name: extract_dev_name(curr_dev),
                description: extract_dev_desc(curr_dev),
                addresses: Vec::new(),
            };
            debug!("device name: {}", info.name);
            debug!("device description: {}", info.description);

            let mut addresses = (*curr_dev).addresses;
            while !addresses.is_null() {
                let netmask: PcapAddr = extract_addr_netmask(addresses);
                let addr: PcapAddr = extract_addr_addr(addresses);
                let bcast: PcapAddr = extract_addr_bcast(addresses);
                let dest: PcapAddr = extract_addr_dest(addresses);
                let addr_info = PcapIfcAddrInfo {
                    netmask,
                    addr,
                    bcast_addr: bcast,
                    dest_addr: dest,
                };
                info.addresses.push(addr_info);
                // tail
                addresses = (*addresses).next;
            } // end of addresses while loop

            out_ifc_info.push(info);
            // tail
            curr_dev = (*curr_dev).next;
        } // end of interfaces while loop
          // pcap_freealldevs(dev_list);
    }; // end of unsafe block
    debug!("found {} devices", out_ifc_info.len());
    out_ifc_info
}

pub fn pcap_addr_to_ipv4_addr(in_addr: &PcapAddr) -> Ipv4Addr {
    Ipv4Addr::new(
        (*in_addr).data[2],
        (*in_addr).data[3],
        (*in_addr).data[4],
        (*in_addr).data[5],
    )
}

pub fn get_pcap_ifc_by_ip4addr(config: &Config) -> result::Result<PcapIfcInfo, &'static str> {
    // get pcap interface by ip address
    debug!("getting list of adapters");
    let pcap_info: Vec<PcapIfcInfo> = get_net_ifcs();

    // https://doc.rust-lang.org/std/vec/struct.Vec.html
    let mut tgt_pcap_info = PcapIfcInfo {
        name: "not set".to_string(),
        description: "not set".to_string(),
        addresses: Vec::new(),
    };
    let mut found: bool = false;
    for pi in &pcap_info {
        for ai in &pi.addresses {
            if check_addr_family(&ai.addr.family, &AddressFamily::AF_INET) {
                let pcap_addr = pcap_addr_to_ipv4_addr(&ai.addr);
                debug!("pcap address: {}", pcap_addr);
                for net_dev in &config.network_devices {
                    let tgt_addr = net_dev.address.parse::<Ipv4Addr>().unwrap();
                    if tgt_addr == pcap_addr {
                        tgt_pcap_info.name = (*pi).name.clone();
                        tgt_pcap_info.description = (*pi).description.clone();
                        tgt_pcap_info.addresses = (*pi).addresses.clone();
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }
        if found {
            break;
        }
    }

    match found {
        false => Err("target device not found"),
        true => Ok(tgt_pcap_info),
    }
}

pub fn get_cap_handle(ifc_info: &PcapIfcInfo) -> Result<*mut pcap_t, &'static str> {
    debug!("opening cap handle");
    let mut err_buf: [c_char; 0xff] = [0; 0xff];
    let mut cap_handle: *mut pcap_t = ptr::null_mut();
    unsafe { cap_handle = pcap_create(ifc_info.name.as_ptr(), err_buf.as_mut_ptr()) };
    match cap_handle.is_null() {
        true => Err("failed to get pcap device"),
        false => Ok(cap_handle),
    }
}

pub fn set_pcap_timeout(cap_handle: *mut pcap_t, timeout_val: c_int) {
    debug!("setting pcap timeout to : {}", timeout_val);

    let result = unsafe { pcap_set_timeout(cap_handle, timeout_val) };

    if result != 0 {
        error!("failed to set pcap timeout");
    }
}

pub fn close_cap_handle(cap_handle: *mut pcap_t) {
    debug!("closing pcap handle");
    unsafe {
        pcap_close(cap_handle);
    }
}

pub fn activate_pcap_handle(cap_handle: *mut pcap_t) -> bool {
    debug!("activating pcap handle");
    unsafe {
        match pcap_activate(cap_handle) as i32 {
            0 => true,
            PCAP_WARNING_PROMISC_NOTSUP => {
                warn!("promiscuous mode not supported");
                false
            }
            PCAP_WARNING_TSTAMP_TYPE_NOTSUP => {
                warn!("time stamp type not supported");
                false
            }
            PCAP_WARNING => {
                warn!("unspecified warning occurred");
                false
            } // todo: get error msg
            PCAP_ERROR_ACTIVATED => {
                error!("cap handle already activated");
                false
            }
            PCAP_ERROR_NO_SUCH_DEVICE => {
                error!("cap device does not exist");
                false
            }
            PCAP_ERROR_PERM_DENIED => {
                error!("permission denied");
                false
            }
            PCAP_ERROR_PROMISC_PERM_DENIED => {
                error!("promiscuous permission denied");
                false
            }
            PCAP_ERROR_IFACE_NOT_UP => {
                error!("interface offline");
                false
            }
            PCAP_ERROR => {
                error!("unspecified error occurred");
                false
            }
            _ => {
                error!("illegal error/warning code");
                false
            }
        }
    }
}

pub fn get_packet(cap_handle: *mut pcap_t) -> Result<PacketData, &'static str> {
    debug!("getting packet");

    let mut pkt_hdr: *mut pcap_pkthdr = ptr::null_mut();
    let mut pkt_data: *const c_uchar = ptr::null();
    let mut cap_result: c_int = 0;
    unsafe { cap_result = pcap_next_ex(cap_handle, &mut pkt_hdr, &mut pkt_data) };

    let is_err = match cap_result {
        1 => {
            debug!("packet captured");
            false
        }
        0 => {
            warn!("capture timer expired");
            false
        }
        PCAP_ERROR => {
            error!("capture failed");
            true
        }
        PCAP_ERROR_NOT_ACTIVATED => {
            error!("not activiated");
            true
        }
        _ => {
            error!("unhandled return val");
            true
        }
    };

    let mut out_data: PacketData = PacketData::new();

    //let mut out_data: Vec<u8> = Vec::new();
    if !is_err {
        unsafe {
            let element_count: usize = (*pkt_hdr).len as usize;
            out_data.data.reserve(element_count);
            out_data.data.set_len(element_count);
            ptr::copy(pkt_data, out_data.data.as_mut_ptr(), element_count);
        };
    }
    // todo: handle the error message
    match is_err {
        true => Err("failed to get packet"),
        false => Ok(out_data),
    }

}

// END OF FILE
