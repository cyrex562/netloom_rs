///
/// ## ipv4.rs
/// IPv4 Protocol Suite
///
/// ref: shttps://tools.ietf.org/html/rfc791#section-3.1
///

use crate::ip_proto::Ipv4Proto;
use crate::util::{bytes_to_u16, bytes_to_u32, u32_ip4_to_str};
use num_derive::{FromPrimitive};
use num_traits::{FromPrimitive};
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
        Self::Routine
    }
}

impl Ipv4TosPrecedence {
    fn from_byte(b: u8) -> Self {
        if b & 0b1110_0000 == 1 {
            Self::NetCtrl
        } else if b & 0b1110_0000 == 1 {
            Self::InternetworkControl
        } else if b & 0b1010_0000 == 1 {
            Self::CriticEcp
        } else if b & 0b1000_0000 == 1 {
            Self::FlashOverride
        } else if b & 0b0110_0000 == 1 {
            Self::Flash
        } else if b & 0b0100_0000 == 1 {
            Self::Immediate
        } else if b & 0b0010_0000 == 1 {
            Self::Priority
        } else {
            Self::Routine
        }
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosDelay {
    NormalDelay = 0,
    LowDelay = 1,
}

impl Default for Ipv4TosDelay {
    fn default() -> Self {
        Self::NormalDelay
    }
}

impl Ipv4TosDelay {
    fn from_byte(b: u8) -> Self {
        if b & 0b0001_0000 == 1 {
            Self::LowDelay
        } else {
            Self::NormalDelay
        }
    }
}

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
pub enum Ipv4TosThroughput {
    NormalThroughput = 0,
    HighThroughput = 1,
}

impl Default for Ipv4TosThroughput {
    fn default() -> Self {
        Self::NormalThroughput
    }
}

impl Ipv4TosThroughput {
    fn from_byte(b: u8) -> Self {
        if b & 0b0_0000_1000 == 1 {
            Self::HighThroughput
        } else {
            Self::NormalThroughput
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
        Self::NormalReliability
    }
}

impl Ipv4TosReliability {
    fn from_byte(b: u8) -> Self {
        if b & 0b0_0000_0100 == 1 {
            Self::HighReliability
        } else {
            Self::NormalReliability
        }
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
    fn new(b: u8) -> Self {
        Self {
            precedence: Ipv4TosPrecedence::from_byte(b),
            delay: Ipv4TosDelay::from_byte(b),
            throughput: Ipv4TosThroughput::from_byte(b),
            reliability: Ipv4TosReliability::from_byte(b),
        }
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
        Self::NotSet
    }
}

impl Ipv4Flags {
    fn from_u16(w: u16) -> [Self; 2] {
        let mut out_flags: [Self; 2] = [Self::NotSet, Self::NotSet];
        if w & 0b0100_0000_0000_0000 == 0 {
            out_flags[0] = Self::MayFragment
        } else if w & 0b0100_0000_0000_0000 == 1 {
            out_flags[0] = Self::DontFragment
        } else if w & 0b0010_0000_0000_0000 == 0 {
            out_flags[1] = Self::LastFragment
        } else if w & 0b0010_0000_0000_0000 == 1 {
            out_flags[1] = Self::LastFragment
        }

        out_flags
    }
}

impl Ipv4Header {
    pub fn new(raw_ip4_hdr: &[u8]) -> Self {
        Self {
            version_ihl: raw_ip4_hdr[0],
            tos: raw_ip4_hdr[1],
            tot_len: bytes_to_u16(&raw_ip4_hdr[2..]),
            ip_id: bytes_to_u16(&raw_ip4_hdr[4..]),
            flags_fragoff: bytes_to_u16(&raw_ip4_hdr[6..]),
            ttl: raw_ip4_hdr[8],
            proto: Ipv4Proto::from_u8(raw_ip4_hdr[9]).unwrap(),
            chksum: bytes_to_u16(&raw_ip4_hdr[10..]),
            src_addr: bytes_to_u32(&raw_ip4_hdr[12..]),
            dst_addr: bytes_to_u32(&raw_ip4_hdr[16..])
        }
    }

    pub fn version(self) -> u8 {
        (self.version_ihl & 0b1111_0000) >> 4
    }

    pub fn ihl(self) -> u8 {
        self.version_ihl & 0b0000_1111
    }

    pub fn expand_tos(self) -> Ipv4Tos {
        Ipv4Tos::new(self.tos)
    }

    pub fn flags(self) -> u16 {
        self.flags_fragoff >> 13
    }

    pub fn frag_off(self) -> u16 {
        self.flags_fragoff & 0b0001_1111_1111_1111
    }

    pub fn src_addr_str(self) -> String {
        u32_ip4_to_str(self.src_addr)
    }

    pub fn dst_addr_str(self) -> String {
        u32_ip4_to_str(self.dst_addr)
    }

    // pub fn to_string(self) -> String {
    //     format!("version: {}, IHL: {}, TOS: {:?}, Tot Len: {}, IP ID: {:02x}, Flags: {:?}, Frag Off: {}, TTL: {}, Proto: {:?}, Checksum: {:02x}, Src Addr: {}, Dst Addr: {}", self.version(), self.ihl(), self.expand_tos(), self.tot_len, self.ip_id, self.flags(), self.frag_off(), self.ttl, self.proto, self.chksum, self.src_addr_str(), self.dst_addr_str())
    // }

    // todo: calculate checksum
}

impl Display for Ipv4Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "version: {}, IHL: {}, TOS: {:?}, Tot Len: {}, IP ID: {:02x}, Flags: {:?}, Frag Off: {}, TTL: {}, Proto: {:?}, Checksum: {:02x}, Src Addr: {}, Dst Addr: {}", self.version(), self.ihl(), self.expand_tos(), self.tot_len, self.ip_id, self.flags(), self.frag_off(), self.ttl, self.proto, self.chksum, self.src_addr_str(), self.dst_addr_str())
    }
}
