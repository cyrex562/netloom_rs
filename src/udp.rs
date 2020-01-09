///
/// ## udp.rs
/// UDP Protocol Suite
/// ref: https://tools.ietf.org/html/rfc768
///
///  0      7 8     15 16    23 24    31
/// +--------+--------+--------+--------+
/// |     Source      |   Destination   |
/// |      Port       |      Port       |
/// +--------+--------+--------+--------+
/// |                 |                 |
/// |     Length      |    Checksum     |
/// +--------+--------+--------+--------+
/// |
/// |          data octets ...
/// +---------------- ...
///

use crate::util::bytes_to_u16;
use std::fmt::{Display, Formatter};

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub chksum: u16,
}

impl UdpHeader {

    pub fn new(raw_udp_hdr: &[u8]) -> Self {
        Self {
            src_port: bytes_to_u16(&raw_udp_hdr[0..]),
            dst_port: bytes_to_u16(&raw_udp_hdr[2..]),
            len: bytes_to_u16(&raw_udp_hdr[4..]),
            chksum: bytes_to_u16(&raw_udp_hdr[6..]),
        }

    }
}

impl Display for UdpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Src Port: {}, Dst Port: {}, Len: {}, Checksum: {:X}",
            self.src_port, self.dst_port, self.len, self.chksum)
    }
}

// END OF FILE

