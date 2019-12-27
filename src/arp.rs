use num_derive::from_primitive;
use std::mem::transmute;

// ref: http://www.networksorcery.com/enp/protocol/arp.htm

#[derive(FromPrimitive, Copy, Clone, PartialEq)]
pub enum ArpHardwareType {
    Reserved = 0,
    Ethernet = 1,
    ExperimentalEthernet = 2,
    Ax25 = 3,
    ProNetTokenRing = 4,
    Chaos = 5,
    Ieee802 = 6,
    Arcnet = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddr = 10,
    LocalTalk = 11, 
    LocalNet = 12,
    Ultralink = 13,
    Smds = 14,
    FrameRelay = 15,
    Atm = 16,
    Hdlc = 17,
    FibreChannel = 18,
    Atm2 = 19,
    SerialLine = 20,
    Atm3 = 21,
    MilStd_188_220 = 22,
    Metricom = 23,
    Ieee1394_1995 = 24,
    Mapos = 25,
    Twinaxial = 26,
    Eui64 = 27,
    Hiparp = 28,
    IpArpIso7816_3 = 29,
    ArpSec = 30,
    IpsecTunnel = 31,
    Infiniband = 32,
    CaiTia102P25 = 33,
    WiegandIfc = 34,
    PureIp = 35,
    HwExp1 = 36,
    // 37 - 255 NOT set
    HwExp2 = 256,
    // 257 - 65534
    ReservedEnd = 65535
}

#[derive(FromPrimitive, Copy, Clone, PartialEq)]
pub enum ArpProtoType {
    NotSet = 0,
    Ip = 0x0800
}

#[derive(FromPrimitive, Copy, Clone, PartialEq)]
pub enum ArpOpcode {
    Reserved = 0,
    Request = 1,
    Reply = 2,
    RequestReverse = 3,
    ReplyReverse = 4,
    DrarpRequest = 5,
    DrarpReply = 6,
    DrarpError = 7,
    InArpRequest = 8,
    InArpReply = 9,
    MarsRequest = 10,
    MarsMulti = 11,
    MarsMserv = 12,

}