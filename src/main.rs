extern crate libc;
extern crate libloading as lib;
extern crate winapi;
extern crate user32;
extern crate kernel32;
extern create clap;

use pcap::Device;
use libc::{c_char, c_int, c_uint, c_ushort, c_uchar, c_long, FILE};
use std::ptr;
use std::ffi::CString;

type time_t = c_long;
type suseconds_t = c_long;

#[repr(C)] pub struct pcap_t { _private: [u8; 0] }
#[repr(C)] pub struct pcap_dumper_t { _private: [u8; 0] }
#[repr(C)] pub struct sockaddr {
    sa_family : c_ushort,
    sa_data : [u8; 14],
}
#[repr(C)] pub struct pcap_addr {
    next : *mut pcap_addr,
    addr : *mut sockaddr,
    netmask : *mut sockaddr,
    broadaddr : *mut sockaddr,
    dstaddr : *mut sockaddr,
}

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
#[repr(C)] pub struct pcap_if_t {
    next: *mut pcap_if_t,
    name : *mut c_char,
    description : *mut c_char,
    addresses : *mut pcap_addr,
    flags : c_uint
}

#[repr(C)] pub struct bpf_insn {
    code : c_ushort,
    jt : c_uchar,
    jf : c_uchar,
    k : c_int,
}

#[repr(C)] pub struct bpf_program {
    bf_len : c_uint,
    bf_isns : *mut bpf_insn
}

#[repr(C)] pub struct timeval {
    tv_sec : time_t,
    tv_usec : suseconds_t
}

#[repr(C)] pub struct pcap_pkthdr {
    ts : timeval,
    caplen : u32,
    len : u32
}


enum AddressFamily {
    AF_UNSPEC = 0,
    AF_UNIX = 1, // unix domain socket
    AF_INET = 2, // IP Protocol
    AF_AX25 = 3, // Amateur radio AX.25
    AF_IPX = 4, // Novell IPX
    AF_APPLETALK = 5, // AppleTalk DDP
    AF_NETROM = 6, // Amateur Radio NetROM
    AF_BRIDGE = 7, // Multi-protocol bridge
    AF_AAL25 = 8, // Reserved for Werner's ATM
    AF_X25 = 9, // Reserved for X.25 project
    AF_INET6 = 10, // IP Version 6
    AF_ROSE = 11, // Amateur Radio X.25 PLP
    AF_DECNET = 12, // Reserved for DECnet project
    AF_NETBEUI = 13, // Reserved for 802.2LLC project
    AF_SECURITY = 14, // Security callback pseudo AF
    AF_KEY = 15, // PF_KEY key management API
    AF_NETLINK = 16, // netlink
    AF_ROUTE = AF_NELINK,
    AF_PACKET = 17, // Packet family
    AF_ASH = 18, // Ash
    AF_ECONET = 19, // Acorn Econet
    AF_ATMSVC = 20, // ATM SVCs
    AF_RDS = 21, // RDS Sockets
    AF_SNA = 22, // Linux SNA Project
    AF_IRDA = 23, // IRDA Sockets
    AF_PPPOX = 24, // PPPoX sockets
    AF_WANPIPE = 25, // Wanpipe API sockets
    AF_LLC = 26, // Linux LLC
    AF_IB = 27, // native infiniband address
    AF_MPLS = 28, // MPLS
    AF_CAN = 29, // Controller Area Network
    AF_TIPC = 30, // TIPC sockets
    AF_BLUETOOTH = 31, // Bluetooth sockets
    AF_IUCV = 32, // IUCV sockets
    AF_RXRPC = 33, // RxRPC sockets
    AF_ISDN = 34, // mISDN sockets
    AF_PHONET = 35, // Phonet sockets
    AF_IEEE802154 = 36, // IEEE802154 sockets
    AF_CAIF = 37, // CAIF sockets
    AF_ALG = 38, // Algorithm sockets
    AF_NFC = 39, // NFC sockets
    AF_VSOCK = 40, // vSockets
    AF_KCM = 41, // Kernel Connection Multiplexor
    AF_QIPCRTR = 42, // Qualcomm IPC router
    AF_SMC = 43, // SMC sockets PF_SMC
    AF_XD = 44, // XDP sockets
    AF_MAX = 45, // highest for now
}

// todo: define error codes


#[link(name = "wpcap")]
extern {
    // create a live capture handle 
    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t *pcap_create(const char *source, char *errbuf);
    fn pcap_create(source : *const c_char, errbuf : *mut c_char) -> *mut pcap_t;

    // activate a capture handle
    // int pcap_activate(pcap_t *p);
    fn pcap_activate(p : *mut pcap_t) -> c_int;

    // construct a list of network devices
    // int 	pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
    fn pcap_findalldevs(alldevsp : *mut *mut pcap_if_t, errbuf : *mut c_char) -> c_int;

    // free an interface list
    // void 	pcap_freealldevs (pcap_if_t *alldevsp)
    fn pcap_freealldevs(alldevsp : *mut pcap_if_t);

    // find the default device on which to capture
    // char * 	pcap_lookupdev (char *errbuf)
    // this function is deprecated
    // fn pcap_lookupdev(errbuf : *mut c_char) -> *mut c_char;

    // open a saved capture file for reading
    // pcap_t *pcap_open_offline(const char *fname, char *errbuf);
    // pcap_t *pcap_open_offline_with_tstamp_precision(const char *fname, u_int precision, char *errbuf);
    // pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf);
    // pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *fp, u_int precision, char *errbuf);
    fn pcap_open_offline(fname : *const c_char, errbuf : *mut c_char) -> *mut pcap_t;

    // todo: get linktype enum
    // open a fake pcap_t for compiling filters or opening a capture for output
    // pcap_t *pcap_open_dead(int linktype, int snaplen);
    // pcap_t *pcap_open_dead_with_tstamp_precision(int linktype, int snaplen,     u_int precision);
    fn pcap_open_dead(linktype : c_int, snaplen : c_int) -> *mut pcap_t;
    
    // close a pcap_t
    // void pcap_close(pcap_t *p);
    fn pcap_close(p : *mut pcap_t);

    // set the snapshot length for a not-yet-activated capture handle
    // int pcap_set_snaplen(pcap_t *p, int snaplen);
    fn pcap_set_snaplen(p : *mut pcap_t, snaplen : c_int) -> c_int;

    // get the snapshot len
    // int pcap_snapshot(pcap_t *p);
    fn pcap_snapshot(p : *mut pcap_t) -> c_int;

    // set the promiscuous mode for a not-yet-activated pcap handle
    // int pcap_set_promisc(pcap_t *p, int promisc);
    fn pcap_set_promisc(p : *mut pcap_t, promisc : c_int) -> c_int;

    // set capture protocol for a not-yet-activated capture handle
    // int pcap_set_protocol_linux(pcap_t *p, int protocol);
    
    // set monitor mode for a not-yet-activated capture handle
    // int pcap_set_rfmon(pcap_t *p, int rfmon);

    // check whether monitor mode can be set for a not-yet-activated capture handle
    // int pcap_can_set_rfmon(pcap_t *p);

    // set the packet buffer timeout for a not-yet-activated capture handle
    // int pcap_set_timeout(pcap_t *p, int to_ms);
    fn pcap_set_timeout(p : *mut pcap_t, to_ms : c_int) -> c_int;

    // set the buffer size for a not-yet-activated capture handle
    // int pcap_set_buffer_size(pcap_t *p, int buffer_size);
    fn pcap_set_buffer_size(p : *mut pcap_t, buffer_size: c_int) -> c_int;

    // set the time stamp type to be used by a capture device
    // int pcap_set_tstamp_type(pcap_t *p, int tstamp_type);
    fn pcap_set_tstamp_type(p : *mut pcap_t, tstamp_type : c_int) -> c_int;

    // get list of time stamp types supported by a capture device, and free that list
    // int pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp);
    fn pcap_list_tstamp_types(p : *mut pcap_t, tstamp_typesp : *mut *mut c_int) -> c_int;

    // void pcap_free_tstamp_types(int *tstamp_types);
    fn pcap_free_tstamp_types(tstamp_types : *mut c_int);

    // get a name or description for a time stamp value type
    // const char *pcap_tstamp_type_val_to_name(int tstamp_type);
    fn pcap_tstamp_type_val_to_name(tstamp_type : c_int) -> *const c_char;

    // const char *pcap_tstamp_type_val_to_description(int tstamp_type);
    fn pcap_tstamp_type_val_to_description(tstamp_type : c_int) -> *const c_char;

    // get the time stamp time value corresponding to a time stamp type name
    // int pcap_tstamp_type_name_to_val(const char *name);
    fn pcap_tstamp_type_name_to_val(name : *const c_char) -> c_int;

    // set the time stamp precision returned in captures
    // int pcap_set_tstamp_precision(pcap_t *p, int tstamp_precision);
    fn pcap_set_tstamp_precision(p : *mut pcap_t, tstamp_precision : c_int) -> c_int;

    // get the time stamp precision returned in captures 
    // int pcap_get_tstamp_precision(pcap_t *p);
    fn pcap_get_tstamp_precision(p : *mut pcap_t) -> c_int;

    // get the link-layer header type 
    // int pcap_datalink(pcap_t *p);
    fn pcap_datalink(p : *mut pcap_t) -> c_int;

    //  get the standard I/O stream for a savefile being read 
    // FILE *pcap_file(pcap_t *p);
    fn pcap_file(p : *mut pcap_t) -> *mut FILE;

    // find out whether a savefile has the native byte order 
    // int pcap_is_swapped(pcap_t *p);
    fn pcap_is_swapped(p : *mut pcap_t) -> c_int;

    //  get the version number of a savefile 
    // int pcap_major_version(pcap_t *p);
    fn pcap_major_version(p : *mut pcap_t) -> c_int;

    // int pcap_minor_version(pcap_t *p);
    fn pcap_minor_version(p : *mut pcap_t) -> c_int;

}

fn main() {
    println!("netloom_rs starting!");



    // get pcap interface by ip address
    println!("getting list of adapters")
    unsafe {
        let mut err_buf : [c_char; 0xff] = [0; 0xff];
        let mut dev_list : *mut pcap_if_t = ptr::null_mut();
        let mut dev_list_ptr = &mut dev_list as *mut *mut pcap_if_t;
        // let err_buf_ptr = err_buf as *mut c_char;
        let result = pcap_findalldevs(dev_list_ptr, err_buf.as_mut_ptr());
        let mut curr_dev : *mut pcap_if_t = dev_list;
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

            let mut addresses = (*curr_dev).addresses;
            while !addresses.is_null() {
                let netmask = (*addresses).netmask;
                let addr = (*addresses).address;
                let broadaddr = (*addresses).broadaddr;
                let dstaddr = (*addresses).dstaddr;
                addresses = (*addresses).next;
            }
            curr_dev = (*curr_dev).next;
        }
        pcap_freealldevs(dev_list);

        
    }

    println!("finished!")

    return;
}
