use crate::ip_proto::Ipv4Proto;
///
/// ## ipv4.rs
/// IPv4 Protocol Suite
///
/// ref: shttps://tools.ietf.org/html/rfc791#section-3.1
///
use crate::util::{bytes_to_u16, bytes_to_u32, ipv4_to_str, mac_to_str, u32_ip4_to_str};
use log::{debug, error};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt::{Display, Formatter};

// https://tools.ietf.org/html/rfc791#section-3.1
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub ip_id: u16,
    pub flags_fragoff: u16,
    pub ttl: u8,
    pub proto: Ipv4Proto,
    pub chksum: u16,
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
    Routine = 0,
}

impl Default for Ipv4TosPrecedence {
    fn default() -> Self {
        Ipv4TosPrecedence::Routine
    }
}

impl Ipv4TosPrecedence {
    fn from_byte(b: u8) -> Ipv4TosPrecedence {
        if b & 0b1110_0000 == 1 {
            return Ipv4TosPrecedence::NetCtrl;
        } else if b & 0b1110_0000 == 1 {
            return Ipv4TosPrecedence::InternetworkControl;
        } else if b & 0b1010_0000 == 1 {
            return Ipv4TosPrecedence::CriticEcp;
        } else if b & 0b1000_0000 == 1 {
            return Ipv4TosPrecedence::FlashOverride;
        } else if b & 0b0110_0000 == 1 {
            return Ipv4TosPrecedence::Flash;
        } else if b & 0b0100_0000 == 1 {
            return Ipv4TosPrecedence::Immediate;
        } else if b & 0b0010_0000 == 1 {
            return Ipv4TosPrecedence::Priority;
        } else {
            return Ipv4TosPrecedence::Routine;
        };
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosDelay {
    NormalDelay = 0,
    LowDelay = 1,
}

impl Default for Ipv4TosDelay {
    fn default() -> Self {
        Ipv4TosDelay::NormalDelay
    }
}

impl Ipv4TosDelay {
    fn from_byte(b: u8) -> Ipv4TosDelay {
        if b & 0b0001_0000 == 1 {
            return Ipv4TosDelay::LowDelay;
        } else {
            return Ipv4TosDelay::NormalDelay;
        };
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosThroughput {
    NormalThroughput = 0,
    HighThroughput = 1,
}

impl Default for Ipv4TosThroughput {
    fn default() -> Self {
        Ipv4TosThroughput::NormalThroughput
    }
}

impl Ipv4TosThroughput {
    fn from_byte(b: u8) -> Ipv4TosThroughput {
        if b & 0b0_0000_1000 == 1 {
            return Ipv4TosThroughput::HighThroughput;
        } else {
            return Ipv4TosThroughput::NormalThroughput;
        }
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosReliability {
    NormalReliability = 0,
    HighReliability = 1,
}

impl Default for Ipv4TosReliability {
    fn default() -> Self {
        Ipv4TosReliability::NormalReliability
    }
}

impl Ipv4TosReliability {
    fn from_byte(b: u8) -> Ipv4TosReliability {
        if b & 0b0_0000_0100 == 1 {
            return Ipv4TosReliability::HighReliability;
        } else {
            return Ipv4TosReliability::NormalReliability;
        };
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct Ipv4Tos {
    pub precedence: Ipv4TosPrecedence,
    pub delay: Ipv4TosDelay,
    pub throughput: Ipv4TosThroughput,
    pub reliability: Ipv4TosReliability,
}

impl Ipv4Tos {
    fn new(b: u8) -> Ipv4Tos {
        let mut x: Ipv4Tos = Default::default();
        x.precedence = Ipv4TosPrecedence::from_byte(b);
        x.delay = Ipv4TosDelay::from_byte(b);
        x.throughput = Ipv4TosThroughput::from_byte(b);
        x.reliability = Ipv4TosReliability::from_byte(b);
        return x;
    }
}

impl Display for Ipv4Tos {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "precedence: {:?}, delay: {:?}, throughput: {:?}, reliability: {:?}",
            self.precedence, self.delay, self.throughput, self.reliability
        )
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum Ipv4Flags {
    NotSet = 0,
    MayFragment,
    DontFragment,
    LastFragment,
    MoreFragments,
}

impl Default for Ipv4Flags {
    fn default() -> Self {
        Ipv4Flags::NotSet
    }
}

impl Ipv4Flags {
    fn from_u16(w: u16) -> [Ipv4Flags; 2] {
        let mut out_flags: [Ipv4Flags; 2] = [Ipv4Flags::NotSet, Ipv4Flags::NotSet];
        if w & 0b0100_0000_0000_0000 == 0 {
            out_flags[0] = Ipv4Flags::MayFragment
        } else if w & 0b0100_0000_0000_0000 == 1 {
            out_flags[0] = Ipv4Flags::DontFragment
        } else if w & 0b0010_0000_0000_0000 == 0 {
            out_flags[1] = Ipv4Flags::LastFragment
        } else if w & 0b0010_0000_0000_0000 == 1 {
            out_flags[1] = Ipv4Flags::LastFragment
        }

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
        let x = (self.version_ihl & 0b1111_0000) >> 4;
        return x;
    }

    pub fn ihl(self) -> u8 {
        let x = self.version_ihl & 0b0000_1111;
        return x;
    }

    pub fn expand_tos(self) -> Ipv4Tos {
        let x = Ipv4Tos::new(self.tos);
        return x;
    }

    pub fn flags(self) -> u16 {
        let x: u16 = self.flags_fragoff >> 13;
        return x;
    }

    pub fn frag_off(self) -> u16 {
        let x = self.flags_fragoff & 0b0001_1111_1111_1111;
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

    // todo: calculate checksum
}

impl Display for Ipv4Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "version: {}, IHL: {}, TOS: {:?}, Tot Len: {}, IP ID: {:02x}, Flags: {:?}, Frag Off: {}, TTL: {}, Proto: {:?}, Checksum: {:02x}, Src Addr: {}, Dst Addr: {}", self.version(), self.ihl(), self.expand_tos(), self.tot_len, self.ip_id, self.flags(), self.frag_off(), self.ttl, self.proto, self.chksum, self.src_addr_str(), self.dst_addr_str())
    }
}
