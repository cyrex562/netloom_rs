#![allow(non_camel_case_types)]


use libc::{c_char, c_int, c_uint, c_ushort, c_uchar, c_long, FILE};


// #define PCAP_IF_LOOPBACK				0x00000001	/* interface is loopback */
const PCAP_IF_LOOPBACK : u32 = 0x00000001;
// #define PCAP_IF_UP					0x00000002	/* interface is up */
const PCAP_IF_UP : u32 = 0x00000002;
// #define PCAP_IF_RUNNING					0x00000004	/* interface is running */
const PCAP_IF_RUNNING : u32 = 0x00000004;
// #define PCAP_IF_WIRELESS				0x00000008	/* interface is wireless (*NOT* necessarily Wi-Fi!) */
const PCAP_IF_WIRELESS : u32 = 0x00000008;
// #define PCAP_IF_CONNECTION_STATUS			0x00000030	/* connection status: */
const PCAP_IF_CONNECTION_STATUS : u32 = 0x00000030;
// #define PCAP_IF_CONNECTION_STATUS_UNKNOWN		0x00000000	/* unknown */
const PCAP_IF_CONNECTION_STATUS_UNKNOWN : u32 = 0x00000000;
// #define PCAP_IF_CONNECTION_STATUS_CONNECTED		0x00000010	/* connected */
const PCAP_IF_CONNECTION_STATUS_CONNECTED : u32 = 0x00000010;
// #define PCAP_IF_CONNECTION_STATUS_DISCONNECTED		0x00000020	/* disconnected */
const PCAP_IF_CONNECTION_STATUS_DISCONNECTED : u32 = 0x00000020;
// #define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE	0x00000030	/* not applicable */
const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE : u32 = 0x00000030;

// #define PCAP_ERROR			-1	/* generic error code */
const PCAP_ERROR : i32 = -1;
// #define PCAP_ERROR_BREAK		-2	/* loop terminated by pcap_breakloop */
const PCAP_ERROR_BREAK : i32 = -2;
// #define PCAP_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */
const PCAP_ERROR_NOT_ACTIVATED : i32 = -3;
// #define PCAP_ERROR_ACTIVATED		-4	/* the operation can't be performed on already activated captures */
const PCAP_ERROR_ACTIVATED : i32 = -4;
// #define PCAP_ERROR_NO_SUCH_DEVICE	-5	/* no such device exists */
const PCAP_ERROR_NO_SUCH_DEVICE : i32 = -5;
// #define PCAP_ERROR_RFMON_NOTSUP		-6	/* this device doesn't support rfmon (monitor) mode */
const PCAP_ERROR_RFMON_NOTSUP : i32 = -6;
// #define PCAP_ERROR_NOT_RFMON		-7	/* operation supported only in monitor mode */
const PCAP_ERROR_NOT_RFMON : i32 = -7;
// #define PCAP_ERROR_PERM_DENIED		-8	/* no permission to open the device */
const PCAP_ERROR_PERM_DENIED : i32 = -8;
// #define PCAP_ERROR_IFACE_NOT_UP		-9	/* interface isn't up */
const PCAP_ERROR_IFACE_NOT_UP : i32 = -9
// #define PCAP_ERROR_CANTSET_TSTAMP_TYPE	-10	/* this device doesn't support setting the time stamp type */
const PCAP_ERROR_CANTSET_TSTAMP_TYPE : i32 = -10;
// #define PCAP_ERROR_PROMISC_PERM_DENIED	-11	/* you don't have permission to capture in promiscuous mode */
const PCAP_ERROR_PROMISC_PERM_DENIED : i32 = -11;
// #define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP -12  /* the requested time stamp precision is not supported */
const PCAP_ERROR_TSTAMP_PRECISION_NOTSUP : i32 = -12;

// #define PCAP_WARNING			1	/* generic warning code */
const PCAP_WARNING : u32 = 1;
// #define PCAP_WARNING_PROMISC_NOTSUP	2	/* this device doesn't support promiscuous mode */
const PCAP_WARNING_PROMISC_NOTSUP : u32 = 2;
// #define PCAP_WARNING_TSTAMP_TYPE_NOTSUP	3	/* the requested time stamp type is not supported */
const PCAP_WARNING_TSTAMP_TYPE_NOTSUP : u32 = 3;

#[derive(FromPrimitive)]
pub enum AddressFamily {
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
    // AF_ROUTE = AF_NETLINK,
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

type time_t = c_long;
type suseconds_t = c_long;

#[repr(C)] pub struct pcap_t { _private: [u8; 0] }
#[repr(C)] pub struct pcap_dumper_t { _private: [u8; 0] }
#[repr(C)] pub struct sockaddr {
    pub sa_family : c_ushort,
    pub sa_data : [u8; 14],
}

#[repr(C)] pub struct pcap_addr {
    pub next : *mut pcap_addr,
    pub addr : *mut sockaddr,
    pub netmask : *mut sockaddr,
    pub broadaddr : *mut sockaddr,
    pub dstaddr : *mut sockaddr,
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
    pub next: *mut pcap_if_t,
    pub name : *mut c_char,
    pub description : *mut c_char,
    pub addresses : *mut pcap_addr,
    pub flags : c_uint
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
    pub ts : timeval,
    pub caplen : u32,
    pub len : u32
}

#[link(name = "wpcap")]
extern {
    // create a live capture handle 
    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t *pcap_create(const char *source, char *errbuf);
    pub fn pcap_create(source : *const c_char, errbuf : *mut c_char) -> *mut pcap_t;

    // activate a capture handle
    // int pcap_activate(pcap_t *p);
    pub fn pcap_activate(p : *mut pcap_t) -> c_int;

    // construct a list of network devices
    // int 	pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
    pub fn pcap_findalldevs(alldevsp : *mut *mut pcap_if_t, errbuf : *mut c_char) -> c_int;

    // free an interface list
    // void 	pcap_freealldevs (pcap_if_t *alldevsp)
    pub fn pcap_freealldevs(alldevsp : *mut pcap_if_t);

    // find the default device on which to capture
    // char * 	pcap_lookupdev (char *errbuf)
    // this function is deprecated
    // fn pcap_lookupdev(errbuf : *mut c_char) -> *mut c_char;

    // open a saved capture file for reading
    // pcap_t *pcap_open_offline(const char *fname, char *errbuf);
    // pcap_t *pcap_open_offline_with_tstamp_precision(const char *fname, u_int precision, char *errbuf);
    // pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf);
    // pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *fp, u_int precision, char *errbuf);
    pub fn pcap_open_offline(fname : *const c_char, errbuf : *mut c_char) -> *mut pcap_t;

    // todo: get linktype enum
    // open a fake pcap_t for compiling filters or opening a capture for output
    // pcap_t *pcap_open_dead(int linktype, int snaplen);
    // pcap_t *pcap_open_dead_with_tstamp_precision(int linktype, int snaplen,     u_int precision);
    pub fn pcap_open_dead(linktype : c_int, snaplen : c_int) -> *mut pcap_t;
    
    // close a pcap_t
    // void pcap_close(pcap_t *p);
    pub fn pcap_close(p : *mut pcap_t);

    // set the snapshot length for a not-yet-activated capture handle
    // int pcap_set_snaplen(pcap_t *p, int snaplen);
    pub fn pcap_set_snaplen(p : *mut pcap_t, snaplen : c_int) -> c_int;

    // get the snapshot len
    // int pcap_snapshot(pcap_t *p);
    pub fn pcap_snapshot(p : *mut pcap_t) -> c_int;

    // set the promiscuous mode for a not-yet-activated pcap handle
    // int pcap_set_promisc(pcap_t *p, int promisc);
    pub fn pcap_set_promisc(p : *mut pcap_t, promisc : c_int) -> c_int;

    // set capture protocol for a not-yet-activated capture handle
    // int pcap_set_protocol_linux(pcap_t *p, int protocol);
    
    // set monitor mode for a not-yet-activated capture handle
    // int pcap_set_rfmon(pcap_t *p, int rfmon);

    // check whether monitor mode can be set for a not-yet-activated capture handle
    // int pcap_can_set_rfmon(pcap_t *p);

    // set the packet buffer timeout for a not-yet-activated capture handle
    // int pcap_set_timeout(pcap_t *p, int to_ms);
    pub fn pcap_set_timeout(p : *mut pcap_t, to_ms : c_int) -> c_int;

    // set the buffer size for a not-yet-activated capture handle
    // int pcap_set_buffer_size(pcap_t *p, int buffer_size);
    pub fn pcap_set_buffer_size(p : *mut pcap_t, buffer_size: c_int) -> c_int;

    // set the time stamp type to be used by a capture device
    // int pcap_set_tstamp_type(pcap_t *p, int tstamp_type);
    pub fn pcap_set_tstamp_type(p : *mut pcap_t, tstamp_type : c_int) -> c_int;

    // get list of time stamp types supported by a capture device, and free that list
    // int pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp);
    pub fn pcap_list_tstamp_types(p : *mut pcap_t, tstamp_typesp : *mut *mut c_int) -> c_int;

    // void pcap_free_tstamp_types(int *tstamp_types);
    pub fn pcap_free_tstamp_types(tstamp_types : *mut c_int);

    // get a name or description for a time stamp value type
    // const char *pcap_tstamp_type_val_to_name(int tstamp_type);
    pub fn pcap_tstamp_type_val_to_name(tstamp_type : c_int) -> *const c_char;

    // const char *pcap_tstamp_type_val_to_description(int tstamp_type);
    pub fn pcap_tstamp_type_val_to_description(tstamp_type : c_int) -> *const c_char;

    // get the time stamp time value corresponding to a time stamp type name
    // int pcap_tstamp_type_name_to_val(const char *name);
    pub fn pcap_tstamp_type_name_to_val(name : *const c_char) -> c_int;

    // set the time stamp precision returned in captures
    // int pcap_set_tstamp_precision(pcap_t *p, int tstamp_precision);
    pub fn pcap_set_tstamp_precision(p : *mut pcap_t, tstamp_precision : c_int) -> c_int;

    // get the time stamp precision returned in captures 
    // int pcap_get_tstamp_precision(pcap_t *p);
    pub fn pcap_get_tstamp_precision(p : *mut pcap_t) -> c_int;

    // get the link-layer header type 
    // int pcap_datalink(pcap_t *p);
    pub fn pcap_datalink(p : *mut pcap_t) -> c_int;

    //  get the standard I/O stream for a savefile being read 
    // FILE *pcap_file(pcap_t *p);
    pub fn pcap_file(p : *mut pcap_t) -> *mut FILE;

    // find out whether a savefile has the native byte order 
    // int pcap_is_swapped(pcap_t *p);
    pub fn pcap_is_swapped(p : *mut pcap_t) -> c_int;

    //  get the version number of a savefile 
    // int pcap_major_version(pcap_t *p);
    pub fn pcap_major_version(p : *mut pcap_t) -> c_int;

    // int pcap_minor_version(pcap_t *p);
    pub fn pcap_minor_version(p : *mut pcap_t) -> c_int;

}

pub struct PcapAddr {
    pub family : AddressFamily,
    pub data : [u8; 32]
}

pub struct PcapIfcAddrInfo {
    pub addr: PcapAddr,
    pub netmask : PcapAddr,
    pub bcast_addr : PcapAddr,
    pub dest_addr : PcapAddr
}

pub struct PcapIfcInfo {
    pub name : String,
    pub description : String,
    pub addresses : Vec<PcapIfcAddrInfo>
}

pub unsafe fn extract_addr_netmask(addresses: *mut pcap::pcap_addr) -> pcap::PcapAddr {
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

pub unsafe fn extract_addr_addr(addresses: *mut pcap_addr) -> PcapAddr {
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

pub unsafe fn extract_addr_bcast(addresses: *mut pcap::pcap_addr) -> PcapAddr {
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
    return bcast_addr;
}

pub unsafe fn extract_addr_dest(addresses: *mut pcap::pcap_addr) -> PcapAddr {
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

    return dest;
}