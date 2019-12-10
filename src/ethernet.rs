
use num_derive::FromPrimitive;
use std::mem::transmute;

#[derive(FromPrimitive, Copy, Clone)]
pub enum EtherType {
    NotSet = 0,
    // length 0x0000-0x05DC
    // experimental 0x0101-0x01FF
    IPv4 = 0x0800,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    AudioVideoTransProto = 0x22f0,
    IetfTrillProto = 0x22f3,
    StreamReservProto = 0x22ea,
    DecMopRc = 0x6002,
    DecnetPhase4 = 0x6003,
    DecLat = 0x6004,
    Rarp = 0x8035,
    AppleTalk = 0x809b,
    AppleTalkArp = 0x80f3,
    VlanTag = 0x8100,
    SimpleLoopPreventProto = 0x8102,
    Ipx = 0x8137,
    QnxQnet = 0x8204,
    Ipv6 = 0x86dd,
    EtherFlowCtrl = 0x8808,
    EtherSlowProto = 0x8809,
    CobraNet = 0x8819,
    MplsUnicast = 0x8847,
    MplsMulticast = 0x8848,
    PppoeDiscovery = 0x8863,
    PppoeSession = 0x8864,
    IntelAdvNetSvc = 0x886d,
    HomePlug1Mme = 0x887b,
    EapOLan8021x = 0x888e,
    ProfinetProto = 0x8892,
    HyperScsi = 0x889a,
    AtaOverEther = 0x88a2,
    EtherCatProto = 0x88a4,
    ProviderBridging = 0x88a8,
    EthernetPowerlink = 0x88ab,
    Goose = 0x88b7,
    GseMgmtSvc = 0x88b9,
    SampledValXmit = 0x88ba,
    Lldp = 0x88cc,
    Sercos3 = 0x88cd,
    WaveShortMsgProto = 0x88dc, 
    HomePlugAvMme = 0x88e1,
    MediaRedundancyProto = 0x88e3,
    MacSec = 0x88e5,
    ProviderBackboneBridges = 0x88e7,
    PrecisionTimeProto = 0x88f7,
    NcSi = 0x88f8,
    ParallelRedundancyProto = 0x88fb,
    ConnectivityFaultMgmt = 0x8902,
    FiberChanOverEther = 0x8906,
    FcoeInitProto = 0x8914,
    RdmaOverConvergedEther = 0x8915,
    TTEtherProtoCtrlFrame = 0x891d,
    HighAvailSeamlessRedundancy = 0x892f,
    EtherConfigTestingProto = 0x9000,
    VlanDoubleTagging = 0x9100,
    VeritasTechLowLatencyTrans = 0xcafe
}

// todo: write a function that converts the ethertype to a string.

impl EtherType {
    pub const ShortesPathBridging88a8: EtherType = EtherType::ProviderBridging;
    pub const DnaRouting: EtherType = EtherType::DecnetPhase4;
    pub const ShortestPathBridging: EtherType = EtherType::VlanTag;

    pub fn bytesToEtherType(b : &[u8]) -> EtherType {
        let mut ether_type_value : u16 = 0;
        ether_type_value = u16::to_be(
            (b[1] as u16) << 8 |
            b[0] as u16
        );

        let etype : EtherType = unsafe { transmute(ether_type_value as u16)};
        return etype;
    }
}

pub fn mac_to_str(addr : &[u8; 6]) -> String {
    return format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

#[derive(Copy, Clone)]
pub struct EthernetFrame {
    dest_addr: [u8;6],
    src_addr: [u8;6],
    ether_type: EtherType
}

impl EthernetFrame {
    pub fn new(raw_packet_data : &Vec<u8>) ->  EthernetFrame {
        let mut x = EthernetFrame {
            dest_addr: [0;6],
            src_addr: [0;6],
            ether_type: EtherType::NotSet
        };
        x.dest_addr.copy_from_slice(&raw_packet_data[0..6]);
        x.src_addr.copy_from_slice(&raw_packet_data[6..12]);
        x.ether_type = EtherType::bytesToEtherType(&raw_packet_data[12..14]);
        return x;
    }

    pub fn parse(packet_data : &Vec<u8>) -> EthernetFrame {
        let frame: EthernetFrame = EthernetFrame::new(packet_data);
        return frame;
    }

    pub fn to_string(self) -> String {
        return format!("dst: {}, src: {}, type: {:04X}", mac_to_str(&self.dest_addr), mac_to_str(&self.src_addr), self.ether_type as u16);
    }
}


pub struct LlcPacket {
    dsap: u8, // dest svc access point, dest net layer proto type
    ssap: u8, // src svc access point, src net layer proto type
    control: u8
}

pub struct EtherSnapPacket {
    org_code: [u8;3], // org code, which org assigned ether type field,
    ether_type: [u8;2], // which upper layer proto will use the ether frame
}

// pub fn parse_ether_frame(packet_data : &Vec<u8>) -> EthernetFrame {
//     let frame: EthernetFrame = EthernetFrame::new(packet_data);
//     return frame;
// } 