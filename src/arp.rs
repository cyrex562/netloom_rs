/// ##arp.rs
/// Functions for parsing and generating ARP protocol messages
///
use crate::util::{ipv4_to_str, mac_to_str};
use log::{error};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt::{Display, Formatter};

// ref: http://www.networksorcery.com/enp/protocol/arp.htm

#[derive(Copy, Clone, PartialEq, FromPrimitive, ToPrimitive, Debug)]
#[repr(u16)]
pub enum ArpHardwareType {
    Reserved = 0,
    Ethernet = 1,
    ExperimentalEthernet = 2,
    Ax25 = 3,
    ProNetTokenRing = 4,
    Chaos = 5,
    Ieee802 = 6,
    Arcnet = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddr = 10,
    LocalTalk = 11,
    LocalNet = 12,
    Ultralink = 13,
    Smds = 14,
    FrameRelay = 15,
    Atm = 16,
    Hdlc = 17,
    FibreChannel = 18,
    Atm2 = 19,
    SerialLine = 20,
    Atm3 = 21,
    MilStd_188_220 = 22,
    Metricom = 23,
    Ieee1394_1995 = 24,
    Mapos = 25,
    Twinaxial = 26,
    Eui64 = 27,
    Hiparp = 28,
    IpArpIso7816_3 = 29,
    ArpSec = 30,
    IpsecTunnel = 31,
    Infiniband = 32,
    CaiTia102P25 = 33,
    WiegandIfc = 34,
    PureIp = 35,
    HwExp1 = 36,
    // 37 - 255 NOT set
    HwExp2 = 256,
    // 257 - 65534
    ReservedEnd = 65535,
}

impl ArpHardwareType {
    pub fn from_bytes(b: &[u8]) -> Self {
        let type_val = u16::to_be((b[1] as u16) << 8 | b[0] as u16);
        match Self::from_u16(type_val) {
            Some(val) => val,
            None => {
                error!("invalid/unhandled hardware type: {:02X}", type_val);
                Self::ReservedEnd
            }
        }
    }
}

impl Default for ArpHardwareType {
    fn default() -> Self {
        Self::ReservedEnd
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(u16)]
pub enum ArpProtoType {
    NotSet = 0,
    Ip = 0x0800,
}

impl ArpProtoType {
    fn from_bytes(b: &[u8]) -> Self {
        let type_val = u16::to_be((b[1] as u16) << 8 | b[0] as u16);
        match Self::from_u16(type_val) {
            Some(val) => val,
            None => {
                error!("invalid/unhandled proto type: {:02X}", type_val);
                Self::NotSet
            }
        }
    }
}

impl Default for ArpProtoType {
    fn default() -> Self {
        Self::NotSet
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(u16)]
pub enum ArpOpcode {
    Reserved = 0,
    Request = 1,
    Reply = 2,
    RequestReverse = 3,
    ReplyReverse = 4,
    DrarpRequest = 5,
    DrarpReply = 6,
    DrarpError = 7,
    InArpRequest = 8,
    InArpReply = 9,
    MarsRequest = 10,
    MarsMulti = 11,
    MarsMserv = 12,
    // 13-65534
    ReservedEnd = 65535,
}

impl Default for ArpOpcode {
    fn default() -> Self {
        Self::Reserved
    }
}

impl ArpOpcode {
    fn from_bytes(b: &[u8]) -> Self {
        let type_val = u16::to_be((b[1] as u16) << 8 | b[0] as u16);
        match Self::from_u16(type_val) {
            Some(val) => val,
            None => {
                error!("invalid/unhandled opcode: {:02X}", type_val);
                Self::Reserved
            }
        }
    }
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct ArpPacket {
    pub hw_type: ArpHardwareType,
    pub proto_type: ArpProtoType,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub opcode: ArpOpcode,
    pub snd_hw_addr: [u8; 6],
    pub snd_proto_addr: [u8; 4],
    pub tgt_hw_addr: [u8; 6],
    pub tgt_proto_addr: [u8; 4],
}

impl ArpPacket {
    pub fn new(raw_arp_hdr: &[u8]) -> Self {
        let mut x: Self = Default::default();
        x.hw_type = ArpHardwareType::from_bytes(&raw_arp_hdr[0..]);
        x.proto_type = ArpProtoType::from_bytes(&raw_arp_hdr[2..]);
        x.hw_addr_len = raw_arp_hdr[4];
        x.proto_addr_len = raw_arp_hdr[5];
        x.opcode = ArpOpcode::from_bytes(&raw_arp_hdr[6..]);
        x.snd_hw_addr.copy_from_slice(&raw_arp_hdr[8..14]);
        x.snd_proto_addr.copy_from_slice(&raw_arp_hdr[14..18]);
        x.tgt_hw_addr.copy_from_slice(&raw_arp_hdr[18..24]);
        x.tgt_proto_addr.copy_from_slice(&raw_arp_hdr[24..28]);
        x
    }
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "hw type: {:?}, proto type: {:?}, hw addr len: {}, proto addr len : {}, opcode: {:?}, snd hw addr: {:?}, snd proto addr: {:?}, tgt hw addr: {:?}, tgt proto addr: {:?}", self.hw_type, self.proto_type, self.hw_addr_len, self.proto_addr_len, self.opcode, mac_to_str(&self.snd_hw_addr), ipv4_to_str(&self.snd_proto_addr), mac_to_str(&self.tgt_hw_addr), ipv4_to_str(&self.tgt_proto_addr))
    }
}
