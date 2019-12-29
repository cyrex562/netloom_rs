use chrono;
use log::{debug, error, info, trace, warn};

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


pub fn bytes_to_u16(data : &[u8]) -> u16 {
    u16::to_le(
        (data[0] as u16) << 8 |
        data[1] as u16
    )
}

pub fn bytes_to_u32(data : &[u8]) -> u32 {
    u32::to_le(
        (data[0] as u32) << 24 |
        (data[1] as u32) << 16 |
        (data[2] as u32) << 8 |
        (data[3] as u32)
    )
}

pub fn u32_ip4_to_str(d : u32) -> String {
    format!("{}.{}.{}.{}", 
(d & 0xff000000) >> 24,
        (d & 0x00ff0000) >> 16,
        (d & 0x0000ff00) >> 8,
        d & 0x000000ff)
}

pub fn mac_to_str(addr : &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
}

pub fn ipv4_to_str(addr : &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}