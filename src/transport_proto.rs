use crate::util::{bytes_to_u16, bytes_to_u32};
use log::{debug, warn};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::collections::HashMap;

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(C)]
pub enum TransProto {
    NotSet,
    Tcp,
    Udp,
    Sctp,
}

#[derive(Clone, PartialEq, Debug, Default)]
#[repr(C)]
pub struct TransSvcProtoInfo {
    pub port: u16,
    pub trans_proto: Vec<TransProto>,
}

impl TransSvcProtoInfo {
    pub fn new(port: u16, trans_proto: Vec<TransProto>) -> Self {
        Self {
            port,
            trans_proto: Vec::new()
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
#[repr(C)]
pub enum TransSvcProto {
    NotSet,
    FtpData = 20,
    Ftp = 21,
    Ssh = 22,
    Telnet = 23,
    Smtp = 25,
    Domain = 53,
    Bootps = 67,           // tcp, udp
    Bootpc = 68,           // tcp, udp
    Tftp = 69,             // tcp, udp
    Finger = 79,           // tcp, udp
    Http = 80,             // tcp, udp, sctp
    Kerberos = 88,         // tcp, udp
    Pop3 = 110,            // tcp, udp
    Sunrpc = 111,          // tcp, udp
    Ident = 113,           // tcp, udp
    Ntp = 123,             // tcp, udp
    NetbiosNs = 137,       // tcp, udp
    NetbiosDgm = 138,      // tcp, udp
    NetbiosSsn = 139,      // tcp, udp
    Imap = 143,            // tcp, udp
    Bgp = 179,             // tcp, udp, sctp
    Irc = 194,             // tcp, udp
    Ldap = 389,            // tcp, udp
    Https = 443,           // tcp, udp, sctp
    MicrosoftDs = 445,     // tcp, udp
    Isakmp = 500,          // tcp, udp
    Syslog = 514,          // tcp, udp
    Ripng = 521,           // tcp, udp
    IrcServ = 529,         // tcp, udp
    Dhcp6Client = 546,     // tcp, udp
    Dhcp6Server = 547,     // tcp, udp
    Rtsp = 554,            // tcp, udp
    MsShuttle = 568,       // tcp, udp
    MsRome = 569,          // tcp, udp
    SntpHeartbeat = 580,   // tcp, udp
    Ipp = 631,             // tcp, udp internet printing protocol (over TLS)
    Ldaps = 636,           // tcp, udp,
    Iscsi = 860,           // tcp, udp
    Rsync = 873,           // tcp, udp
    FtpsData = 989,        // tcp, udp
    Ftps = 990,            // tcp, udp
    Telnets = 992,         // tcp, udp
    Imaps = 993,           // tcp, udp
    Pop3s = 995,           // tcp, udp
    BoincClient = 1043,    // tcp, udp
    Socks = 1080,          // tcp, udp
    LtpDeepspace = 1113,   // tcp, udp, dccp
    OpenVpn = 1194,        // tcp, udp
    Kazaa = 1214,          // tcp, udp
    Nessus = 1241,         // tcp, udp
    H323HostCallSc = 1300, // tcp, udp
    JtagServer = 1309,     // tcp, udp
    MsSqlSrv = 1433,       // tcp, udp
    MsSqlMon = 1434,       // tcp, udp
    MsWins = 1512,         // tcp, udp
    L2tp = 1701,           // tcp, udp
    Pptp = 1723,           // tcp, udp
    Ssdp = 1900,           // tcp, udp
    Hsrp = 1985,           // tcp, udp
    Hsrpv6 = 2029,         // tcp, udp
    Isis = 2042,           // tcp, udp
    IsisBcast = 2043,      // tcp, udp
    Nfs = 2049,            // tcp, udp
    AhEspEncap = 2070,     // tcp, udp
    Docker = 2375,         // tcp, udp
    DockerSsl = 2376,      // tcp, udp
    DockerSwarm = 2378,    // tcp, udp
    EtcdClient = 2379,     // tcp, udp
    EtcdServer = 2380,     // tcp, udp
    Vcmp = 2427,           // tcp, udp, Velocloud Multipath Protocol
}

impl From<TransSvcProto> for TransSvcProtoInfo {
    fn from(f: TransSvcProto) -> Self {
        match f {
            TransSvcProto::NotSet => Self {
                port: 0,
                trans_proto: vec![TransProto::NotSet],
            },
            TransSvcProto::FtpData => Self {
                port: 20,
                trans_proto: vec![TransProto::Tcp, TransProto::Udp, TransProto::Sctp],
            },
            TransSvcProto::Ftp => Self {
                port: 21,
                trans_proto: vec![TransProto::Tcp, TransProto::Udp, TransProto::Sctp],
            },
            TransSvcProto::Ssh => Self {
                port: 22,
                trans_proto: vec![TransProto::Tcp, TransProto::Udp, TransProto::Sctp],
            },
            TransSvcProto::Telnet => Self {
                port: 23,
                trans_proto: vec![TransProto::Tcp, TransProto::Udp, TransProto::Sctp],
            },
            TransSvcProto::Smtp => Self {
                port: 25,
                trans_proto: vec![TransProto::Tcp, TransProto::Udp],
            },
            TransSvcProto::Domain => Self {
                port: 53,
                trans_proto: vec![TransProto::Tcp, TransProto::Udp, TransProto::Sctp],
            },
            _ => Self {
                port: 0,
                trans_proto: vec![],
            }
        }
    }
}

// END OF FILE