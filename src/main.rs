use pcap::Device;

fn main() {
    let mut cap = Device::lookup().unwrap().open().unwrap();

    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }

    println!("Hello, world!");
}
