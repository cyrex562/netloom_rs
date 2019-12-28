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


pub fn bytes_to_u16(data : &[u8], big_endian: bool) -> u16 {

    if big_endian == true {
        u16::to_be(
            (data[1] as u16) << 8 |
            data[0] as u16
        )
    } else {
        u16::to_be(
            (data[0] as u16) << 8 |
            data[1] as u16
        )
    } 
}

pub fn mac_to_str(addr : &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
}

pub fn ipv4_to_str(addr : &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}