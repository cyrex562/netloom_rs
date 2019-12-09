use crate::ethernet::{EthernetFrame,EtherSnapPacket,LlcPacket};

pub enum PacketHeader {
    Ethernet(EthernetFrame),
    Snap(EtherSnapPacket),
    Llc(LlcPacket),
}