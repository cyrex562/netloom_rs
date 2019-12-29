use crate::ethernet::{EthernetFrame,EtherSnapPacket,LlcPacket};
use crate::arp::{ArpPacket};
use crate::ipv4::{Ipv4Header};
use crate::udp::{UdpHeader};
use crate::ipv6::{Ipv6Header};

pub enum PacketHeader {
    Ethernet(EthernetFrame),
    Snap(EtherSnapPacket),
    Llc(LlcPacket),
    Arp(ArpPacket),
    Ipv4(Ipv4Header),
    Udp(UdpHeader),
    Ipv6(Ipv6Header),
}