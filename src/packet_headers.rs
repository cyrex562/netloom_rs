use crate::ethernet::{EthernetFrame,EtherSnapPacket,LlcPacket};
use crate::arp::{ArpPacket};

pub enum PacketHeader {
    Ethernet(EthernetFrame),
    Snap(EtherSnapPacket),
    Llc(LlcPacket),
    Arp(ArpPacket)
}