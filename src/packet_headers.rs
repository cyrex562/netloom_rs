use crate::ethernet::{EthernetFrame,EtherSnapPacket,LlcPacket};
use crate::arp::{ArpPacket};
use crate::ipv4::{Ipv4Header};
use crate::udp::{UdpHeader};

pub enum PacketHeader {
    Ethernet(EthernetFrame),
    Snap(EtherSnapPacket),
    Llc(LlcPacket),
    Arp(ArpPacket),
    Ipv4(Ipv4Header),
    Udp(UdpHeader)
}