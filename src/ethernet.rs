///
/// ## ethernet.rs
/// 
/// Data structures and functions for handling the Ethernet protocol
/// 

use crate::util::mac_to_str;
use log::error;

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt::{Display, Formatter};


#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug)]
#[repr(u16)]
pub enum EtherType {
    NotSet = 0,
    // length 0x0000-0x05DC
    // experimental 0x0101-0x01FF
    Ipv4 = 0x0800,
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
    VeritasTechLowLatencyTrans = 0xcafe,
}

impl Default for EtherType {
    fn default() -> Self {
        Self::NotSet
    }
}

impl EtherType {
    pub const SHORTEST_PATH_BRIDGING88A8: Self = Self::ProviderBridging;
    pub const DNA_ROUTING: Self = Self::DecnetPhase4;
    pub const SHORTEST_PATH_BRIDGING: Self = Self::VlanTag;

    pub fn from_bytes(b: &[u8]) -> Self {
        let type_val = u16::to_be((b[1] as u16) << 8 | b[0] as u16);

        match Self::from_u16(type_val) {

            Some(val) => val,
            None => {
                error!("invalid/unhandled Ether Type: {:02X}", type_val);
                Self::NotSet
            }
        }
    }
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct EthernetFrame {
    pub dest_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: EtherType,
}

impl EthernetFrame {
    pub fn new(raw_packet_data: &[u8]) -> Self {
        let mut x: Self = Default::default();
        x.dest_addr.copy_from_slice(&raw_packet_data[0..6]);
        x.src_addr.copy_from_slice(&raw_packet_data[6..12]);
        x.ether_type = EtherType::from_bytes(&raw_packet_data[12..14]);
        x
    }
}

impl Display for EthernetFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src: {}, dst: {}, type: {:?}",
            mac_to_str(&self.src_addr),
            mac_to_str(&self.dest_addr),
            self.ether_type
        )
    }
}

#[repr(C)]
pub struct LlcPacket {
    dsap: u8, // dest svc access point, dest net layer proto type
    ssap: u8, // src svc access point, src net layer proto type
    control: u8,
}

#[repr(C)]
pub struct EtherSnapPacket {
    org_code: [u8; 3],   // org code, which org assigned ether type field,
    ether_type: [u8; 2], // which upper layer proto will use the ether frame
}

// end of file