use crate::packet_data::PacketData;
use crate::packet_headers::PacketHeader;

pub enum Layer2Type {
    NotSet = 0,
    Ipv4,
    Ipv6,
    Arp,
}

pub struct PacketInfo {
    pub headers: Vec<PacketHeader>,
    pub packet_data: PacketData,
}

impl PacketInfo {
    pub fn new() -> Self {
        Self {
            packet_data: PacketData::new(),
            headers: vec![],
        }
    }

    pub fn add_header() {}

    pub fn store_packet_data() {}
}
