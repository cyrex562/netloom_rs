use chrono;
use log;

pub fn setup_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

pub fn bytes_to_u16(data: &[u8]) -> u16 {
    u16::to_le((data[0] as u16) << 8 | data[1] as u16)
}

pub fn bytes_to_u32(data: &[u8]) -> u32 {
    u32::to_le(
        (data[0] as u32) << 24 | (data[1] as u32) << 16 | (data[2] as u32) << 8 | (data[3] as u32),
    )
}

pub fn u32_ip4_to_str(d: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (d & 0xff00_0000) >> 24,
        (d & 0x00ff_0000) >> 16,
        (d & 0x0000_ff00) >> 8,
        d & 0x0000_00ff
    )
}

pub fn ipv6_to_str(b: &[u8]) -> String {
    format!(
        "{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}{:x}{:x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

pub fn mac_to_str(addr: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}

pub fn ipv4_to_str(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}
