pub struct PacketData {
    pub cap_len: usize,
    pub wire_len: usize,
    pub data: Vec<u8>,
}

impl PacketData {
    pub fn new() -> Self {
        Self {
            cap_len: 0,
            wire_len: 0,
            data: vec![],
        }
    }
}
