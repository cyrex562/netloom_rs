
use log::{error};
use num_derive::{FromPrimitive};
use num_traits::{FromPrimitive};

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(u8)]
pub enum Ipv4Proto {
    HopOpt = 0,           // IPv6 Hop-by-Hop Option RFC8200
    Icmp = 1,             // RFC792
    Igmp = 2,             // RFC1112
    Ggp = 3,              // Gateway To Gateway RFC823
    Ipv4 = 4,             // IPv4 Encapsulation RFC2003
    Stream = 5,           // RFC1190, RFC1819
    Tcp = 6,              // RFC793
    Cbt = 7,              // unk
    Egp = 8,              // RFC888
    Igp = 9,              // Any private interior gateway protocol
    BbnRccMon = 10,       // BBN RCC Monitoring
    Nvp2 = 11,            // Network Voice Protocol RFC741
    Pup = 12,             // PUP
    Argus = 13,           // Deprecated
    Emcon = 14,           // Mystery contact
    Xnet = 15,            // Cross Net Debugger
    Chaos = 16,           // Chaos
    Udp = 17,             // User Datagram RFC768
    Mux = 18,             // Multiplexing Protocol
    DcnMeas = 19,         // DCN Measurement Subsystems
    Hmp = 20,             // RFC869, Host Monitoring
    Prm = 21,             // Packet Radio Measurement
    XnsIdp = 22,          // Xerox NS IDP
    Trunk1 = 23,          // Trunk-1
    Trunk2 = 24,          // Trunk-2
    Leaf1 = 25,           // Leaf-1
    Leaf2 = 26,           // Leaf-2
    Rdp = 27,             // Reliable Data Protocol RFC908
    Irtp = 28,            // Internet Reliable Transaction, RFC938
    IsoTp4 = 29,          // ISO Transport Class 4, RFC905
    NetBlt = 30,          // Bulk Data Transfer Protocol, RFC969
    MfeNsp = 31,          // MFE Network Services Protocol
    MeritInp = 32,        // MERIT Internodal Protocol
    Dccp = 33,            // Datagram Congestion Control Protocol, RFC4340
    ThreePc = 34,         // Third Party Connect Protocol
    Idpr = 35,            // Inter-Domain Policy Routing Protocol
    Xtp = 36,             // XTP
    Ddp = 37,             // Datagram Delivery Protocol
    IdprCmtp = 38,        // IDPR Control Message Transport Protocol
    Tppp = 39,            // TP++ Transport Protocol
    Iltp = 40,            // IL Transport Protocol
    Ipv6 = 41,            // IPv6 Encapsulation, RFC2473
    Sdrp = 42,            // Source Demand Routing Protocol
    Ipv6Route = 43,       // IPv6 Routing Header
    Ipv6Frag = 44,        // Ipv6 Fragment Header
    Idrp = 45,            // INter-Domain Routing Protocol
    Rsvp = 46,            // Reservation Protocol RFC2205 RFC3209
    Gre = 47,             // Generic Routing Encapsulation RFC2784
    Dsr = 48,             // Dynamic Source Routing Protocol RFC4728
    Bna = 49,             // BNA
    Esp = 50,             // Encap Security Payload RFC4303
    Ah = 51,              // Authentication Header, RFC4302
    INlsp = 52,           // Integrated Net Layer Security TUBA
    Swipe = 53,           // Deprecated
    Narp = 54,            // NBMA Address Resolution Protocol, RFC1735
    Mobile = 55,          // IP Mobility
    Tlsp = 56,            // Transport Layer Security Protocol using Kryptonet Key Mgmt
    Skip = 57,            // SKIP
    Ipv6Icmp = 58,        // ICMP for IPv6 RFC8200
    Ipv6NoNxt = 59,       // No Next Header for IPv6 RFC8200
    Ipv6Opts = 60,        // Dest Opts for Ipv6, RFC8200
    AnyHostIntProto = 61, // Any Host Internal Protocol
    Cftp = 62,            // CFTP
    AnyLocalNet = 63,     // Any Local Network
    SatExpak = 64,        // SATNET and Backroom EXPAK
    Kryptolan = 65,       // Kryptolan
    Rvd = 66,             // MIT Remote Virtual Disk Protocol
    Ippc = 67,            // Internet Pluribus Packet Core
    AnyDistFileSys = 68,  // Any Distributed File System
    SatMon = 69,          // SATNET Monitoring
    Visa = 70,            // VISA Protocol
    Ipvc = 71,            // Internet Packet Core Utility
    Cpnx = 72,            // Computer Protocol Network Executive
    Cphb = 73,            // Computer Protocol Heartbeat
    Wsn = 74,             // Wang Span Network
    Pvp = 75,             // Packet Video Protocol
    BrSatMon = 76,        // Backroom SATNET Monitoring
    SunNd = 77,           // Sun ND-Proto Temp
    WbMon = 78,           // Wideband Monitoring
    WbExpak = 79,         // Wideband Expak
    IsoIp = 80,           // ISO IP
    Vmtp = 81,            // VMTP
    SecureVmtp = 82,      // Secure VMTP
    Vines = 83,           // Vines
    Ttp = 84,             // Transaction Transport Protocols, also Internet Protocol Traffic Manager
    NsfnetIgp = 85,       // NSF Net IGP
    Dgp = 86,             // Dissimilar Gateway Protocol
    Tcf = 87,             // TCF
    Eigrp = 88,           // EIGRP RFC7868
    OspfIgp = 89,         // OSPF IGP RFC1583, RFC2328, RFC5340
    SpriteRpc = 90,       // Sprite RPC Protocol
    Larp = 91,            // Locus Address Resolution Protocol
    Mtp = 92,             // Multicast Transport Protocol
    Ax25 = 93,            // AX.25 Frames
    IpIp = 94,            // Ip-within-IP encapsulation
    Micp = 95,            // Deprecated
    SccSp = 96,           // Semaphore Communications Security Protocol
    EtherIp = 97,         // Ethernet-within-IP Encapsulation RFC3378
    Encap = 98,           // Encpasulation Header RFC1241
    AnyPvtCrypto = 99,    // Any Private Encryption Scheme
    Gmtp = 100,           // GMTP
    Ifmp = 101,           // Ipsilon Flow Mgmt Proto
    Pnni = 102,           // PNNI over IP
    Pim = 103,            // Proto Independent Mcast
    Aris = 104,           // ARIS
    Scps = 105,           // SCPS
    Qnx = 106,            // QNX
    ActNet = 107,         // Active Networks
    IpComp = 108,         // IP Compression Protocol
    Snp = 109,            // Sitara Networks Protocol
    CompaqPeer = 110,     // Compaq Peer Protocol
    IpxInIp = 111,        // IPX in IP
    Vrrp = 112,           // Virtual Router Redundancy Protocol RFC5798
    Pgm = 113,            // PGM Reliable Transport Protocol
    AnyZeroHop = 114,     // Any Zero Hop Proto
    L2tp = 115,           // Layer 2 Tunneling Protocol
    Ddx = 116,            // D-II Data Exchange
    Iatp = 117,           // Interactive Agent Transfer Protocol
    Stp = 118,            // Schedule Transfer Protocol
    Srp = 119,            // SpectraLink Radio Protocol
    Uti = 120,            // UTI
    Smp = 121,            // Simple Message Proto
    Sm = 122,             // Deprecated
    Ptp = 123,            // Performance Transparency Protocol
    IsIsIpv4 = 124,       // IS-IS over IPv4
    Fire = 125,           // FIRE
    Crtp = 126,           // Combat Radio Trans Proto
    Crudp = 127,          // Combat Radio UDP
    Sscopmce = 128,       // SSCOPMCE
    IpLt = 129,           // IPLT
    Sps = 130,            // Secure Packet Shield
    Pipe = 131,           // Private IP Encapsulation within IP
    Sctp = 132,           // Stream Control Transmission Protocol
    Fc = 133,             // Fibre Channel, RFC6172
    RsvpE2EIgnore = 134,  // RSVP E2E Ignore RFC3175
    MobilityHeader = 135, // Mobility Header RFC6275
    UdpLite = 136,        // RFC3828
    MplsInIp = 137,       // RFC4023
    Manet = 138,          // MANET Protocols, RFC5498
    Hip = 139,            // Host Identity Protocol, RFC7401
    Shim6 = 140,          // Shim6 Protocol, RFC5533
    Wesp = 141,           // Wrapped Encapsulating Security Payload, RFC5840
    Rohc = 142,           // Robust Header Compression
    // 143-252, // Unassigned
    Exp1 = 253,     // Experimental RFC3692
    Exp2 = 254,     // Experimental RFC3692
    Reserved = 255, // End
}

impl Default for Ipv4Proto {
    fn default() -> Self {
        Self::Reserved
    }
}

impl Ipv4Proto {
    pub fn from_byte(b: u8) -> Self {
        match Self::from_u8(b) {
            Some(val) => val,
            None => {
                error!("invalid/unhandled IPv4 proto: {}", b);
                Self::Reserved
            }
        }
    }
}
