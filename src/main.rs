extern crate libc;
extern crate libloading as lib;
extern crate winapi;
extern crate user32;
extern crate kernel32;

use pcap::Device;
use libc::{c_char, c_int, c_uint, c_ushort, c_uchar, c_long};

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

    // 

    // open a device for live capture
    // pcap_t * pcap_open_live (const char *device, int snaplen, int promisc, int to_ms, char *ebuf)
    fn pcap_open_live(device : *const c_char, snaplen : c_int, promisc: c_int, to_ms: c_int, ebuf : *mut c_char)-> *const pcap_t;

    // open file and dump captures to it
    // pcap_dumper_t * 	pcap_dump_open (pcap_t *p, const char *fname)
    fn pcap_dump_open(p : *const pcap_t, fname: *const c_char) -> *const pcap_dumper_t;

    // set the non-blocking state of an interface
    // int 	pcap_setnonblock (pcap_t *p, int nonblock, char *errbuf)
    fn pcap_setnonblock(p : *const pcap_t, nonblock : c_int, errbuf : *mut c_char) -> c_int;

    // get the non-blocking state of an interface
    // int 	pcap_getnonblock (pcap_t *p, char *errbuf)
    fn pcap_getnonblock(p : *const pcap_t, errbuf : *mut c_char) -> c_int;

    

    

    // return the subnet adn netmask of an interface
    // int 	pcap_lookupnet (const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
    fn pcap_lookupnet(device : *const c_char, netp : *must c_uint, maskp : *mut c_uint, errbuf : *mut c_char) -> c_int;

    // typedef void(*) pcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) 

    // collect a group of packets
    // int 	pcap_dispatch (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    fn pcap_dispatch(p : *mut pcap_t, cnt : c_int, callback : extern fn(*mut u8, *const pcap_pkthdr, *const c_uchar), user : *mut c_uchar) -> c_int;

    // collect oa group of packets
    // int 	pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    fn pcap_loop(p : *mut pcap_t, cnt : c_int, callback : extern fn(*mut u8, *const pcap_pkthdr, *const c_uchar), user : *mut c_char) -> c_int;

    // return the next available packet
    // u_char * 	pcap_next (pcap_t *p, struct pcap_pkthdr *h)
    fn pcap_next(p : *mut pcap_t, h : *mut pcap_pkthdr) -> *mut c_uchar;

    // read a packet from an interface or an offline capture
    // int 	pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
    fn pcap_next_ex(p : *mut pcap_t, pkt_hdr : *mut *mut pcap_pkthdr, pkt_data : *const *const c_uchar) -> c_int;

    // set a flag that will force pcap_dispatch or pcap_loop to return rather than looping
    // void 	pcap_breakloop (pcap_t *)
    fn pcap_breakloop(p : *mut pcap_t);

    // send a raw packet
    // int 	pcap_sendpacket (pcap_t *p, u_char *buf, int size)
    fn pcap_sendpacket(p : *mut pcap_t, buf : *mut c_uchar, size : c_int) -> c_int;

    // save a packet to disk
    // void 	pcap_dump (u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
    fn pcap_dump(user : *mut c_uchar, h : *const pcap_pkthdr, sp : *const c_uchar);

    // return the file position for a save file
    // long 	pcap_dump_ftell (pcap_dumper_t *)
    fn pcap_dump_ftell(pdt: *mut pcap_dumper_t) -> c_long;

    // compile a packet filter
    // int 	pcap_compile (pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
    fn pcap_compile(p : *mut pcap_t, fp : *mut bpf_program, str : *mut char, optimize : c_int, netmask : u32) -> c_int;

    // compile a packet filter without the need of opening an adapter
    // int 	pcap_compile_nopcap (int snaplen_arg, int linktype_arg, struct bpf_program *program, char *buf, int optimize, bpf_u_int32 mask)
    fn pcap_compile_nopcap(snaplen_arg : c_int, linktype_arg : c_int, program : *mut bpf_program, buf : *mut char, optimize : c_int, mask : u32) -> c_int;

    // associate a filter to a capture
    // int 	pcap_setfilter (pcap_t *p, struct bpf_program *fp)
    fn pcap_setfilter(p : *mut pcap_t, fp : *mut bpf_program) -> c_int;

    // free a filter
    // void 	pcap_freecode (struct bpf_program *fp)
    fn pcap_freecode(fp : *mut bpf_program);

    // return the link layer of an adapter
}

fn main() {
    println!("Hello, world!");

    // get pcap interface by ip address


    return;
}
