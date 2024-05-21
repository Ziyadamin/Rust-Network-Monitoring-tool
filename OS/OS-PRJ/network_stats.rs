use std::fs::File;
use std::io::{BufRead, BufReader};
//use std::thread;


 
fn get_network_stats(interface: &str) -> Option<(u64, u64)> {
    let path = format!("/sys/class/net/{}/statistics/", interface);
    let rx_file = File::open(path.clone() + "rx_bytes").ok()?;
    let tx_file = File::open(path.clone() + "tx_bytes").ok()?;
    let rx_bytes: u64 = BufReader::new(rx_file)
        .lines()
        .next()?
        .unwrap()
        .parse()
        .ok()?;
    let tx_bytes: u64 = BufReader::new(tx_file)
        .lines()
        .next()?
        .unwrap()
        .parse()
        .ok()?;
    Some((rx_bytes, tx_bytes))
}
