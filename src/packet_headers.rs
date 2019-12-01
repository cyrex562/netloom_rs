use crate::ethernet::{EthernetFrame,EtherSnapPacket,LlcPacket};

pub enum PacketHeader {
    EthernetFrame,
    EtherSnapPacket,
    LlcPacket,
}