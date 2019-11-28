use serde::{Deserialize, Serialize};
    
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub name: String,
    pub address: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub network_devices: Vec<NetworkDevice>,
}
