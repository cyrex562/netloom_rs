///
/// ## ipv4.rs
/// IPv4 Protocol Suite
/// 

use crate::util::{mac_to_str, ipv4_to_str, bytes_to_u16, bytes_to_u32, u32_ip4_to_str};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use byteorder::{BigEndian, ReadBytesExt};
use log::{error, debug};


#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(u8)]
pub enum Ipv4Proto {
    HopOpt = 0, // IPv6 Hop-by-Hop Option RFC8200
    Icmp = 1, // RFC792
    Igmp = 2, // RFC1112
    Ggp = 3, // Gateway To Gateway RFC823
    Ipv4 = 4, // IPv4 Encapsulation RFC2003
    Stream = 5, // RFC1190, RFC1819
    Tcp = 6, // RFC793
    Cbt = 7, // unk
    Egp = 8, // RFC888
    Igp = 9, // Any private interior gateway protocol
    BbnRccMon = 10, // BBN RCC Monitoring
    Nvp2 = 11, // Network Voice Protocol RFC741
    Pup = 12, // PUP
    Argus = 13, // Deprecated
    Emcon = 14, // Mystery contact
    Xnet = 15, // Cross Net Debugger
    Chaos = 16, // Chaos
    Udp = 17, // User Datagram RFC768
    Mux = 18, // Multiplexing Protocol
    DcnMeas = 19, // DCN Measurement Subsystems
    Hmp = 20, // RFC869, Host Monitoring
    Prm = 21, // Packet Radio Measurement
    XnsIdp = 22, // Xerox NS IDP
    Trunk1 = 23, // Trunk-1
    Trunk2 = 24, // Trunk-2
    Leaf1 = 25, // Leaf-1
    Leaf2 = 26, // Leaf-2
    Rdp = 27, // Reliable Data Protocol RFC908
    Irtp = 28, // Internet Reliable Transaction, RFC938
    IsoTp4 = 29, // ISO Transport Class 4, RFC905
    NetBlt = 30, // Bulk Data Transfer Protocol, RFC969
    MfeNsp = 31, // MFE Network Services Protocol
    MeritInp = 32, // MERIT Internodal Protocol
    Dccp = 33, // Datagram Congestion Control Protocol, RFC4340
    ThreePc = 34, // Third Party Connect Protocol
    Idpr = 35, // Inter-Domain Policy Routing Protocol
    Xtp = 36, // XTP
    Ddp = 37, // Datagram Delivery Protocol
    IdprCmtp = 38, // IDPR Control Message Transport Protocol
    Tppp = 39, // TP++ Transport Protocol
    Iltp = 40, // IL Transport Protocol
    Ipv6 = 41, // IPv6 Encapsulation, RFC2473
    Sdrp = 42, // Source Demand Routing Protocol
    Ipv6Route = 43, // IPv6 Routing Header
    Ipv6Frag = 44, // Ipv6 Fragment Header
    Idrp = 45, // INter-Domain Routing Protocol
    Rsvp = 46, // Reservation Protocol RFC2205 RFC3209
    Gre = 47, // Generic Routing Encapsulation RFC2784
    Dsr = 48, // Dynamic Source Routing Protocol RFC4728
    Bna = 49, // BNA
    Esp = 50, // Encap Security Payload RFC4303
    Ah = 51, // Authentication Header, RFC4302
    INlsp = 52, // Integrated Net Layer Security TUBA
    Swipe = 53, // Deprecated
    Narp = 54, // NBMA Address Resolution Protocol, RFC1735
    Mobile = 55, // IP Mobility
    Tlsp = 56, // Transport Layer Security Protocol using Kryptonet Key Mgmt
    Skip = 57, // SKIP
    Ipv6Icmp = 58, // ICMP for IPv6 RFC8200
    Ipv6NoNxt = 59, // No Next Header for IPv6 RFC8200
    Ipv6Opts = 60, // Dest Opts for Ipv6, RFC8200
    AnyHostIntProto = 61, // Any Host Internal Protocol
    Cftp = 62, // CFTP
    AnyLocalNet = 63, // Any Local Network
    SatExpak = 64, // SATNET and Backroom EXPAK
    Kryptolan = 65, // Kryptolan
    Rvd = 66, // MIT Remote Virtual Disk Protocol
    Ippc = 67, // Internet Pluribus Packet Core
    AnyDistFileSys = 68, // Any Distributed File System
    SatMon = 69, // SATNET Monitoring
    Visa = 70, // VISA Protocol
    Ipvc = 71, // Internet Packet Core Utility
    Cpnx = 72, // Computer Protocol Network Executive
    Cphb = 73, // Computer Protocol Heartbeat
    Wsn = 74, // Wang Span Network
    Pvp = 75, // Packet Video Protocol
    BrSatMon = 76, // Backroom SATNET Monitoring
    SunNd = 77, // Sun ND-Proto Temp
    WbMon = 78, // Wideband Monitoring
    WbExpak = 79, // Wideband Expak
    IsoIp = 80, // ISO IP
    Vmtp = 81, // VMTP
    SecureVmtp = 82, // Secure VMTP
    Vines = 83, // Vines
    Ttp = 84, // Transaction Transport Protocols, also Internet Protocol Traffic Manager
    NsfnetIgp = 85, // NSF Net IGP
    Dgp = 86, // Dissimilar Gateway Protocol
    Tcf = 87, // TCF
    Eigrp = 88, // EIGRP RFC7868
    OspfIgp = 89, // OSPF IGP RFC1583, RFC2328, RFC5340
    SpriteRpc = 90, // Sprite RPC Protocol
    Larp = 91, // Locus Address Resolution Protocol
    Mtp = 92, // Multicast Transport Protocol
    Ax25 = 93, // AX.25 Frames
    IpIp = 94, // Ip-within-IP encapsulation 
    Micp = 95, // Deprecated
    SccSp = 96, // Semaphore Communications Security Protocol
    EtherIp = 97, // Ethernet-within-IP Encapsulation RFC3378
    Encap = 98, // Encpasulation Header RFC1241
    AnyPvtCrypto = 99, // Any Private Encryption Scheme
    Gmtp = 100, // GMTP
    Ifmp = 101, // Ipsilon Flow Mgmt Proto
    Pnni = 102, // PNNI over IP
    Pim = 103, // Proto Independent Mcast
    Aris = 104, // ARIS
    Scps = 105, // SCPS
    Qnx = 106, // QNX
    ActNet = 107, // Active Networks
    IpComp = 108, // IP Compression Protocol
    Snp = 109, // Sitara Networks Protocol
    CompaqPeer = 110, // Compaq Peer Protocol
    IpxInIp = 111, // IPX in IP
    Vrrp = 112, // Virtual Router Redundancy Protocol RFC5798
    Pgm = 113, // PGM Reliable Transport Protocol
    AnyZeroHop = 114, // Any Zero Hop Proto
    L2tp = 115, // Layer 2 Tunneling Protocol
    Ddx = 116, // D-II Data Exchange
    Iatp = 117, // Interactive Agent Transfer Protocol
    Stp = 118, // Schedule Transfer Protocol
    Srp = 119, // SpectraLink Radio Protocol
    Uti = 120, // UTI
    Smp = 121, // Simple Message Proto
    Sm = 122, // Deprecated
    Ptp = 123, // Performance Transparency Protocol
    IsIsIpv4 = 124, // IS-IS over IPv4
    Fire = 125, // FIRE
    Crtp = 126, // Combat Radio Trans Proto
    Crudp = 127, // Combat Radio UDP
    Sscopmce = 128, // SSCOPMCE
    IpLt = 129, // IPLT
    Sps = 130, // Secure Packet Shield
    Pipe = 131, // Private IP Encapsulation within IP
    Sctp = 132, // Stream Control Transmission Protocol
    Fc = 133, // Fibre Channel, RFC6172
    RsvpE2EIgnore = 134, // RSVP E2E Ignore RFC3175
    MobilityHeader = 135, // Mobility Header RFC6275
    UdpLite = 136, // RFC3828
    MplsInIp = 137, // RFC4023
    Manet = 138, // MANET Protocols, RFC5498
    Hip = 139, // Host Identity Protocol, RFC7401
    Shim6 = 140, // Shim6 Protocol, RFC5533
    Wesp = 141, // Wrapped Encapsulating Security Payload, RFC5840
    Rohc = 142, // Robust Header Compression
    // 143-252, // Unassigned
    Exp1 = 253, // Experimental RFC3692
    Exp2 = 254, // Experimental RFC3692
    Reserved = 255, // End
}

impl Default for Ipv4Proto {
    fn default() -> Self { Ipv4Proto::Reserved}
}

impl Ipv4Proto {
    fn from_byte(b: u8) -> Ipv4Proto {
        let val = match Ipv4Proto::from_u8(b) {
            Some(val) => val,
            None => {
                error!("invalid/unhandled IPv4 proto: {}", b);
                Ipv4Proto::Reserved
            }
        };
        return val;
    }
}

// https://tools.ietf.org/html/rfc791#section-3.1
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub tos : u8,
    pub tot_len : u16,
    pub ip_id : u16,
    pub flags_fragoff : u16,
    pub ttl : u8,
    pub proto : Ipv4Proto,
    pub chksum : u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosPrecedence {
    NetCtrl = 0b111,
    InternetworkControl = 0b110,
    CriticEcp = 0b101,
    FlashOverride = 0b100,
    Flash = 0b011,
    Immediate = 0b010,
    Priority = 0b001,
    Routine = 0
}

impl Default for Ipv4TosPrecedence {
    fn default() -> Self { Ipv4TosPrecedence::Routine }
}

impl Ipv4TosPrecedence {
    fn from_byte(b: u8) -> Ipv4TosPrecedence {

        if b & 0b11100000 == 1 { return Ipv4TosPrecedence::NetCtrl }
        else if b & 0b11100000 == 1 { return Ipv4TosPrecedence::InternetworkControl }
        else if b & 0b10100000 == 1 { return Ipv4TosPrecedence::CriticEcp }
        else if b & 0b10000000 == 1 { return Ipv4TosPrecedence::FlashOverride }
        else if b & 0b01100000 == 1 { return Ipv4TosPrecedence::Flash }
        else if b & 0b01000000 == 1 { return Ipv4TosPrecedence::Immediate }
        else if b & 0b00100000 == 1 { return Ipv4TosPrecedence::Priority }
        else { return Ipv4TosPrecedence::Routine};
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosDelay {
    NormalDelay = 0,
    LowDelay = 1,
}

impl Default for Ipv4TosDelay {
    fn default() -> Self { Ipv4TosDelay::NormalDelay }
}

impl Ipv4TosDelay {
    fn from_byte(b: u8) -> Ipv4TosDelay {
        if b & 0b00010000 == 1 { return Ipv4TosDelay::LowDelay }
        else { return Ipv4TosDelay::NormalDelay };
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosThroughput {
    NormalThroughput = 0,
    HighThroughput = 1,
}

impl Default for Ipv4TosThroughput {
    fn default() -> Self { Ipv4TosThroughput::NormalThroughput }
}


impl Ipv4TosThroughput {
    fn from_byte(b: u8) -> Ipv4TosThroughput {
        if b & 0b000001000 == 1 { return Ipv4TosThroughput::HighThroughput }
        else { return Ipv4TosThroughput::NormalThroughput }
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosReliability {
    NormalReliability = 0,
    HighReliability = 1,
}

impl Default for Ipv4TosReliability {
    fn default() -> Self { Ipv4TosReliability::NormalReliability }
}

impl Ipv4TosReliability {
    fn from_byte(b: u8) -> Ipv4TosReliability {
        if b & 0b000000100 == 1 { return Ipv4TosReliability::HighReliability }
        else { return Ipv4TosReliability::NormalReliability }; 
    }
}

#[derive(Copy,Clone,Default, Debug)] 
pub struct Ipv4Tos {
    pub precedence : Ipv4TosPrecedence,
    pub delay : Ipv4TosDelay,
    pub throughput : Ipv4TosThroughput,
    pub reliability : Ipv4TosReliability,
}

impl Ipv4Tos {
    fn new(b : u8) -> Ipv4Tos {
        let mut x: Ipv4Tos = Default::default();
        x.precedence = Ipv4TosPrecedence::from_byte(b);
        x.delay = Ipv4TosDelay::from_byte(b);
        x.throughput = Ipv4TosThroughput::from_byte(b);
        x.reliability = Ipv4TosReliability::from_byte(b);
        return x;
    }

    fn to_string(self) -> String {
        format!("precedence: {:?}, delay: {:?}, throughput: {:?}, reliability: {:?}", self.precedence, self.delay, self.throughput, self.reliability)
    }
}


#[derive(Copy,Clone, Debug)] 
#[repr(u8)]
enum Ipv4Flags {
    NotSet = 0,
    MayFragment,
    DontFragment,
    LastFragment,
    MoreFragments,
}

impl Default for Ipv4Flags {
    fn default() -> Self { Ipv4Flags::NotSet }
}

impl Ipv4Flags {
    fn from_u16(w : u16) -> [Ipv4Flags;2] {
        let mut out_flags : [Ipv4Flags;2] = [Ipv4Flags::NotSet, Ipv4Flags::NotSet];
        if w & 0b0100000000000000 == 0  { out_flags[0] = Ipv4Flags::MayFragment }
        else if  w & 0b0100000000000000 == 1 { out_flags[0] = Ipv4Flags::DontFragment }
        else if    w & 0b0010000000000000 == 0 { out_flags[1] = Ipv4Flags::LastFragment }
        else if    w & 0b0010000000000000 == 1 { out_flags[1] = Ipv4Flags::LastFragment }
        
        return out_flags;
    }
}

impl Ipv4Header {
    pub fn new(raw_ip4_hdr: &[u8]) -> Ipv4Header {
        let mut x: Ipv4Header = Default::default();
        x.version_ihl = raw_ip4_hdr[0];
        x.tos = raw_ip4_hdr[1];
        x.tot_len = bytes_to_u16(&raw_ip4_hdr[2..]);
        x.ip_id = bytes_to_u16(&raw_ip4_hdr[4..]);
        x.flags_fragoff = bytes_to_u16(&raw_ip4_hdr[6..]);
        x.ttl = raw_ip4_hdr[8];
        x.proto = Ipv4Proto::from_u8(raw_ip4_hdr[9]).unwrap();
        x.chksum = bytes_to_u16(&raw_ip4_hdr[10..]);
        x.src_addr = bytes_to_u32(&raw_ip4_hdr[12..]);
        x.dst_addr = bytes_to_u32(&raw_ip4_hdr[16..]);
        return x;
    }

    pub fn version(self) -> u8 {
        let x = (self.version_ihl & 0b11110000) >> 4;
        return x;
    }

    pub fn ihl(self) -> u8 {
        let x = self.version_ihl & 0b00001111;
        return x;
    }

    pub fn expand_tos(self) -> Ipv4Tos {
        let x = Ipv4Tos::new(self.tos);
        return x;
    }

    pub fn flags(self) -> u16 {
        let x : u16 = self.flags_fragoff >> 13;
        return x;
    }

    pub fn frag_off(self) -> u16 {
        let x = self.flags_fragoff & 0b0001111111111111;
        return x;
    }

    pub fn src_addr_str(self) -> String {
        let x = u32_ip4_to_str(self.src_addr);
        return x;
    }

    pub fn dst_addr_str(self) -> String {
        let x = u32_ip4_to_str(self.dst_addr);
        return x;
    }

    pub fn to_string(self) -> String {
        format!("version: {}, IHL: {}, TOS: {:?}, Tot Len: {}, IP ID: {:02x}, Flags: {:?}, Frag Off: {}, TTL: {}, Proto: {:?}, Checksum: {:02x}, Src Addr: {}, Dst Addr: {}", self.version(), self.ihl(), self.expand_tos(), self.tot_len, self.ip_id, self.flags(), self.frag_off(), self.ttl, self.proto, self.chksum, self.src_addr_str(), self.dst_addr_str())
    }
    
    // todo: calculate checksum
}