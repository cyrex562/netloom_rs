///
/// ## packet_headers.rs
///
use crate::arp::ArpPacket;
use crate::ethernet::{EtherSnapPacket, EthernetFrame, LlcPacket};
use crate::ipv4::Ipv4Header;
use crate::ipv6::Ipv6Header;
use crate::tcp::TcpHeader;
use crate::udp::UdpHeader;

pub enum PacketHeader {
    Ethernet(EthernetFrame),
    Snap(EtherSnapPacket),
    Llc(LlcPacket),
    Arp(ArpPacket),
    Ipv4(Ipv4Header),
    Udp(UdpHeader),
    Ipv6(Ipv6Header),
    Tcp(TcpHeader),
}

// END OF FILE
