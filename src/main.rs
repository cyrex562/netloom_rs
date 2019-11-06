extern crate libc;
extern crate libloading as lib;
extern crate winapi;
extern crate user32;
extern crate kernel32;

use pcap::Device;
use libc::{c_char, c_int, c_uint, c_ushort, c_uchar, c_long, FILE};

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
    println!("Hello, world!");

    // get pcap interface by ip address


    return;
}
