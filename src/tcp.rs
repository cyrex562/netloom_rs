///
/// ## tcp.rs
///
/// ref: https://tools.ietf.org/html/rfc793
/// ref: https://tools.ietf.org/html/rfc7323
/// ref: https://tools.ietf.org/html/rfc2018
use crate::util::{bytes_to_u16, bytes_to_u32};
use log::{debug, warn};
use num_derive::{FromPrimitive};
use num_traits::{FromPrimitive};

// options
// https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(u8)]
pub enum TcpOptKind {
    EndOfList = 0,
    Nop = 1,
    MaxSegSz = 2,
    WinScale = 3,
    SackOk = 4,
    Sack = 5,
    Timestamp = 8,
    Skeeter = 16,
    Bubba = 17,
    TrailerChecksum = 18,
    ScpsCaps = 20,
    SelNegAck = 21,
    RecordBoundaries = 22,
    CorruptionExperienced = 23,
    Snap = 24,
    TcpCompFilter = 26,
    QuickStartResp = 27,
    UserTimeout = 28,
    TcpAuth = 29,
    MultipathTcp = 30,
    TcpFastOpenCookie = 34,
    Rfc3692Exp1 = 253,
    Rfc3692Exp2 = 254,
    Reserved = 255,
}

// kind : length : meaning
// 0 : 1 : end of option list: RFC793
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptEndOfList {
    pub kind: TcpOptKind,
}

impl TcpOptEndOfList {
    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::EndOfList
        }
    }
}

// 1 : 1 : nop: RFC793
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptNop {
    pub kind: TcpOptKind,
}

impl TcpOptNop {
    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::Nop
        }
    }
}

// 2 : 4 : max seg sz: RFC793
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptMaxSegSz {
    pub kind: TcpOptKind,
    pub length: u8,
    pub max_seg_sz: u16,
}

impl TcpOptMaxSegSz {
    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::MaxSegSz,
            length: 4,
            max_seg_sz: 0
        }
    }
}

// 3 : 3 : win scale: RFC7323
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptWinScale {
    pub kind: TcpOptKind,
    pub length: u8,
    pub shift_cnt: u8,
}

impl TcpOptWinScale {
    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::WinScale,
            length: 3,
            shift_cnt: 0
        }
    }
}

// 4 : 2 : SACK permitted: RFC2018
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptSackOk {
    pub kind: TcpOptKind,
    pub length: u8,
}

impl TcpOptSackOk {
    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::SackOk,
            length: 2
        }
    }
}

// 5 : N : SACK: RFC2018
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptSack {
    pub kind: TcpOptKind,
    pub length: u8,
    pub blocks: [u32; 4],
}

impl TcpOptSack {

    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::Sack,
            length: 0,
            blocks: [0, 0, 0, 0]
        }
    }
}

// 8 : 10 : Timestamps: RFC7323
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TcpOptTimestamp {
    pub kind: TcpOptKind,
    pub length: u8,
    pub ts_val: u32,
    pub ts_echo_reply: u32,
}

impl TcpOptTimestamp {
    pub fn new() -> Self {
        Self {
            kind: TcpOptKind::Timestamp,
            length: 10,
            ts_val: 0,
            ts_echo_reply: 0
        }
    }
}

// 16 : 1 : Skeeter: NA
// 17 : 1 : Bubba: NA
// 18 : 3 : Trailer Checksum option: NA
// 20 : 1 : SCPS caps
// 21 : 1 : Selective Neg ACK
// 22 : 1 : Record Boundaries
// 23 : 1 : Corruption Experienced
// 24 : 1 : SNAP
// 26 : 1 : TCP Compression Filter

// 27 : 8 : Quick Start Response : RFC4782
// 28 : 4 : User Timeout Opiton : RFC5482
// 29 : 1 : TCP Auth Opt : RFC5925
// 30 : N : Multi-path TCP : RFC6824
// 34 : N : TCP Fast Open Cookie : RFC7413
// 69 : N : Encryption Negotiation : RFC8547

// 253 : N : RFC3692 Experiment 1
// 254 : N : RFC3692 Experiment 2
// 255 : Reserved

impl Default for TcpOptKind {
    fn default() -> Self {
        Self::Reserved
    }
}

#[derive(Debug)]
pub enum TcpOptions {
    EndOfList(TcpOptEndOfList),
    Nop(TcpOptNop),
    MaxSegSz(TcpOptMaxSegSz),
    WinScale(TcpOptWinScale),
    SackOk(TcpOptSackOk),
    Sack(TcpOptSack),
    Timestamp(TcpOptTimestamp),
}

// Alternate Checksum Numbers
// 0 : TCP Checksum : RFC1146
// 1 : 8-bit Fltecher's Algorithm : RFC1146
// 2 : 16-bit Fletcher's Algorithm : RFC1146
// 3 : Redundant Checksum Avoidance : NA

// Crypto Algorithms for TCP-AO Registration
// RFC5926
// SHA1: RFC5926
// AES128: RFC5926

// Multi-Path TCP Option Subtypes, RFC6824
// 0 : MP_CAPABLE : Multipath Capable
// 1 : MP_JOIN : Join Connection
// 2 : DSS : Data Sequence Signal (Data ACK and data sequence mapping)
// 3 : ADD_ADDR : Add Address
// 4 : REMOVE_ADDR : Remove Address
// 5 : MP_PRIO : Change Subflow Priority
// 6 : MP_FAIL : Fallback
// 7 : MP_FASTCLOSE : Fast Close
// 8 : MP_TCPRST : Subflow Reset
// 0x9-0xe : Unahttps://github.com/cyrex562/netloom_rs/pull/4/conflict?name=src%252Ftcp.rs&ancestor_oid=dabc55d2459b788d487b1347385a2eb92203ca95&base_oid=9a8039d3f9f049614b0f5261f8a9edefb712b930&head_oid=f658f991aa7f29051dc5dfeb220ec463205a612cssigned
// 0xf : Reserved

// MPTCP Handshake Algorithms : RFC6284
// A: Checksum required
// B: Extensibility
// C: Do not attempt to establish subflows to the source address
// D-G: Unassigned
// H: HMAC-SHA256

// TCP Encryption Protocol Identifers: RFC8547
// 0x20 : Experimental
// 0x21 : TCPCRYPT_ECDHE_P256
// 0x22 : TCPCRYPT_ECDHE_P521
// 0x23 : TCPCRYPT_ECDHE_Curve25519
// 0x24 : TCPCRYPT_ECDHE_Curve448
// 0x25 - 0x6f : Unassigned
// 0x70 - 0x7f : Reserved for extended Values

// TCP Crypt AEAD Algorithms
// 0 : Reserved
// 1 : AEAD_AES_128_GCM
// 2 : AEAD_AES_256_GCM
// 3 - 0xf : Unassigned
// 0x10 : AEAD_CHACHA20_POLY1305
// 0x11 - 0xffff : Unassigned

// MPTCP MP_TCPRST Reason Codes
// 0: Unspecified TCP Error
// 1: MPTCP specific Error
// 2: Lack of Resources
// 3: Administratively Prohibited
// 4: Too much outstanding Data
// 5: Unacceptable performance
// 6: Middlebox interference
// 7-0xff: Unassigned

//  0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Copy, Clone, PartialEq, FromPrimitive, Debug)]
#[repr(C)]
pub enum TcpControlBits {
    None,
    Urg,
    Ack,
    Psh,
    Rst,
    Syn,
    Fin,
}

// src port : u16
// dst port : u16
// seq num : u32
// ack num : u32
// data off : 4 b : num of 32-bit words in header
// reserved : 6 b
// control bits: 6 bits:
//  URG: Urgent Pointer field significant
//  ACK: Acknowledgement field significant
//  PSH: Push Function
//  RST: Reset the connection
//  SYN: Synchronize sequence numbers
//  FIN: No more data from sender
// window: u16: number of bytes the sender can accept
// checksum: u16
// urg ptr: u16
#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
pub struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_off_reserved_control_bits: u16,
    window: u16,
    checksum: u16,
    urg_ptr: u16,
}

impl TcpHeader {

    pub fn new(raw: &[u8]) -> Self {
        Self {
            src_port: bytes_to_u16(&raw[0..]),
            dst_port: bytes_to_u16(&raw[2..]),
            seq_num: bytes_to_u32(&raw[4..]),
            ack_num: bytes_to_u32(&raw[8..]),
            data_off_reserved_control_bits: bytes_to_u16(&raw[12..]),
            window: bytes_to_u16(&raw[14..]),
            checksum: bytes_to_u16(&raw[16..]),
            urg_ptr: bytes_to_u16(&raw[18..])
        }

    }

    // decode data_off
    pub fn data_off(self) -> u16 {
        let x = (self.data_off_reserved_control_bits & 0b1111_0000_0000_0000) >> 12;
        debug!(
            "raw: {:X}, data offset: {}",
            self.data_off_reserved_control_bits, x
        );
        x
    }

    // decode control_bits
    pub fn control_bits(self) -> Vec<TcpControlBits> {
        // let mut out_bits : [TcpControlBits;6] = [TcpControlBits::None,TcpControlBits::None,TcpControlBits::None,TcpControlBits::None,TcpControlBits::None,TcpControlBits::None];
        let mut out_bits: Vec<TcpControlBits> = Vec::new();
        let ctrl_field: u16 = self.data_off_reserved_control_bits & 0x3f;
        // debug!("field: 0b{:016b} (0x{:02X})", ctrl_field, ctrl_field);
        if ctrl_field & 0x20 > 0 {
            out_bits.push(TcpControlBits::Urg);
        }
        if ctrl_field & 0x10 > 0 {
            out_bits.push(TcpControlBits::Ack);
        }
        if ctrl_field & 0x08 > 0 {
            out_bits.push(TcpControlBits::Psh);
        }
        if ctrl_field & 0x04 > 0 {
            out_bits.push(TcpControlBits::Rst);
        }
        if ctrl_field & 0x02 > 0 {
            out_bits.push(TcpControlBits::Syn);
        }
        if ctrl_field & 0x01 > 0 {
            out_bits.push(TcpControlBits::Fin);
        }
        out_bits
    }

    // decode options;
    pub fn decode_options(self, opts: &[u8]) -> Vec<TcpOptions> {
        let mut options: Vec<TcpOptions> = Vec::new();
        let doff: usize = (self.data_off() * 4) as usize;
        if (doff) > 20 {
            let mut ptr: usize = 0;
            loop {
                if ptr >= (doff - 20) {
                    break;
                }
                let kind: TcpOptKind = TcpOptKind::from_u8(opts[ptr]).unwrap();
                match kind {
                    TcpOptKind::EndOfList => break,
                    TcpOptKind::Nop => {
                        let x = TcpOptNop::new();
                        options.push(TcpOptions::Nop(x));
                        ptr += std::mem::size_of::<TcpOptNop>()
                    }
                    TcpOptKind::MaxSegSz => {
                        let mut x = TcpOptMaxSegSz::new();
                        x.max_seg_sz = bytes_to_u16(&opts[ptr + 2..]);
                        options.push(TcpOptions::MaxSegSz(x));
                        ptr += std::mem::size_of::<TcpOptMaxSegSz>()
                    }
                    TcpOptKind::WinScale => {
                        let mut x = TcpOptWinScale::new();
                        x.shift_cnt = opts[ptr + 2];
                        options.push(TcpOptions::WinScale(x));
                        ptr += std::mem::size_of::<TcpOptWinScale>()
                    }
                    TcpOptKind::SackOk => {
                        let x = TcpOptSackOk::new();
                        options.push(TcpOptions::SackOk(x));
                        ptr += std::mem::size_of::<TcpOptSackOk>()
                    }
                    TcpOptKind::Sack => {
                        let mut x = TcpOptSack::new();
                        x.length = opts[ptr + 1];
                        let num_dw: usize = ((x.length - 2) / 32) as usize;
                        let mut curr_dw: usize = 0;
                        loop {
                            if curr_dw == num_dw {
                                break;
                            }
                            let dw_ptr = ptr + 2 + (curr_dw as usize) * 4;
                            x.blocks[curr_dw] = bytes_to_u32(&opts[dw_ptr..]);
                            curr_dw += 1;
                        }
                        options.push(TcpOptions::Sack(x));
                        ptr += x.length as usize
                    }
                    TcpOptKind::Timestamp => {
                        let mut x = TcpOptTimestamp::new();
                        x.ts_val = bytes_to_u32(&opts[ptr + 2..]);
                        x.ts_echo_reply = bytes_to_u32(&opts[ptr + 2 + 4..]);
                        options.push(TcpOptions::Timestamp(x));
                        ptr += x.length as usize
                    }
                    _ => warn!("unprocessed tcp opt kind: {:?}", kind),
                };
            }
        }
        options
    }

    // string
    pub fn to_string(self, opts_raw: &[u8]) -> String {
        format!("Src Port: {}, Dst Port: {}, Seq #: {:X}, Ack #: {:X}, Data Off: {}, Control Bits: {:?}, Window: {}, Checksum: {:X}, Urg Ptr: {:X}, Options: {:?}", self.src_port, self.dst_port, self.seq_num, self.ack_num, self.data_off(), self.control_bits(), self.window, self.checksum, self.urg_ptr, self.decode_options(opts_raw))
    }
}