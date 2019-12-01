use crate::ethernet;

pub enum PacketHeader {
    Ethernet: ethernet::EthernetFrame,
    EthernetSnap: ethernet::EtherSnapPacket,
    EthernetLlc: ethernet::LlcPacket,
}