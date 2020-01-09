
///
/// ## ipv6.rs
///
/// ref: https://tools.ietf.org/html/rfc2460
use crate::util::{bytes_to_u16, bytes_to_u32, ipv6_to_str};
use crate::ip_proto::Ipv4Proto;
use log::{debug, error};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt::{Display, Formatter};


// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// version: 4 b: 6
// traffic class: 8 b :
// flow label: 20 b :
// payload len : u16 : len of the payload
// next hdr : u8: IP proto
// hop limit : u8: decremented by each router until zero, then discarded
// src addr : u128
// dst addr : u128

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct Ipv6Header {
    pub ver_class_flow: u32,
    pub payload_len: u16,
    pub next_hdr: Ipv4Proto,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

impl Ipv6Header {
    pub fn new(raw: &[u8]) -> Self {
        let mut x: Self = Default::default();
        x.ver_class_flow = bytes_to_u32(&raw[0..]);
        x.payload_len = bytes_to_u16(&raw[4..]);
        x.next_hdr = Ipv4Proto::from_byte(raw[6]);
        x.hop_limit = raw[7];
        x.src_addr.copy_from_slice(&raw[8..24]);
        x.dst_addr.copy_from_slice(&raw[24..40]);
        x
    }

    // get version
    pub fn version(self) -> u32 {
        (self.ver_class_flow & 0b11_1100_0000_0000_0000_0000_0000_0000) >> 28
    }

    // get class
    pub fn class(self) -> u32 {
        (self.ver_class_flow & 0b0000_1111_1111_0000_0000_0000_0000_0000) >> 20
    }

    // get flow label
    pub fn flow_label(self) -> u32 {
        self.ver_class_flow & 0b0000_0000_0000_1111_1111_1111_1111_1111
    }

    // get src addr as str
    pub fn src_addr_str(self) -> String {
        ipv6_to_str(&self.src_addr)
    }

    // get dst addr as str
    pub fn dst_addr_str(self) -> String {
        ipv6_to_str(&self.dst_addr)
    }
}

impl Display for Ipv6Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Version: {}, Traffic Class: {}, Flow Label: {:X}, Payload Len: {}, Next Header: {:?}, Hop Limit: {}, Src Addr: {}, Dst Addr: {}", self.version(), self.class(), self.flow_label(), self.payload_len, self.next_hdr, self.hop_limit, self.src_addr_str(), self.dst_addr_str())
    }
}
