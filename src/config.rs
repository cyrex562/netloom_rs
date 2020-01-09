///
/// ## config.rs
/// 
/// Data structures that serde uses for parsing the configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub name: String,
    pub address: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub max_loop: u32,
    pub network_devices: Vec<NetworkDevice>,
}
