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

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub chksum: u16,
}

impl UdpHeader {
    pub fn new(raw_udp_hdr: &[u8]) -> UdpHeader {
        let mut x: UdpHeader = Default::default();
        x.src_port = bytes_to_u16(&raw_udp_hdr[0..]);
        x.dst_port = bytes_to_u16(&raw_udp_hdr[2..]);
        x.len = bytes_to_u16(&raw_udp_hdr[4..]);
        x.chksum = bytes_to_u16(&raw_udp_hdr[6..]);
        x
    }

    pub fn to_string(self) -> String {
        format!(
            "Src Port: {}, Dst Port: {}, Len: {}, Checksum: {:X}",
            self.src_port, self.dst_port, self.len, self.chksum
        )
    }
}
