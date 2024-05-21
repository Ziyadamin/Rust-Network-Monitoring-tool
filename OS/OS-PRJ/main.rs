include!("byte_multiple.rs");
include!("network_stats.rs");


use eframe::egui;
use egui::{color, mutex, SidePanel};
use std::sync::{Arc, Mutex};
//use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

mod measurements; // Import the measurements module

use measurements::MeasurementWindow; // Import MeasurementWindow from the measurements module
use rand::Rng; // Import the Rng trait from the rand crate
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};


pub struct MonitorApp {
    include_y: Vec<f64>,
    measurements: Arc<Mutex<MeasurementWindow>>,
    upload_measurements: Arc<Mutex<MeasurementWindow>>,
    show_interface_window: u16,
}

impl MonitorApp {
    fn new(look_behind: usize) -> Self {
        Self {
            measurements: Arc::new(Mutex::new(MeasurementWindow::new_with_look_behind(
                look_behind,
            ))),
            upload_measurements: Arc::new(Mutex::new(MeasurementWindow::new_with_look_behind(
                look_behind,
            ))),
            include_y: Vec::new(),
          /* table_data: vec![
                vec!["Column1".to_string(), "Column2".to_string()], // Example headers
                vec!["Data1".to_string(), "Data2".to_string()],     // Example row 1
                vec!["Data3".to_string(), "Data4".to_string()],     // Example row 2
            ],*/
            show_interface_window: 1,
        }
    }
    
}

impl eframe::App for MonitorApp {
    

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {

        if self.show_interface_window==1 {
            egui::Window::new("Network Interfaces").show(ctx, |ui| {
                let NetInterface = datalink::interfaces();
                for ih in NetInterface {
                    if ui.button(ih.name).clicked() {
                        // Do something when a button is clicked, like opening the second window
                        // Or any other action you want to perform
                        
                        self.show_interface_window=2;
                    }
                }
            });
        }
       if self.show_interface_window==2{
        egui::SidePanel::left("Main").show(ctx, |ui| {
            let mut plot = egui::plot::Plot::new("measurements");
            for y in self.include_y.iter() {
                plot = plot.include_y(*y);
            }

            plot.show(ui, |plot_ui| {
                let download_values = self.measurements.lock().unwrap().plot_values();
                let upload_values = self.upload_measurements.lock().unwrap().plot_values();
                 
                  plot_ui.line(egui::plot::Line::new(download_values).name("Download Speed"));
                  plot_ui.line(egui::plot::Line::new(upload_values).name("Upload Speed"));
            });
         
        });
        egui::SidePanel::right("Table").show(ctx, |ui| {
            // Display the table
            egui::Grid::new("my_table").show(ui, |ui| {
                // Iterate through rows
                let data = self.measurements.lock().unwrap();
             
                for (i,n) in data.lim_vec.vec.iter().zip(data.sec.vec.iter()){
                    ui.label(format!("Sec: {}, Host:{}",n,i));
                    ui.end_row();
                   
                }
                if ui.button("Total stats").clicked() {
                    // Do something when a button is clicked, like opening the second window
                    // Or any other action you want to perform
                    
                    self.show_interface_window=3;
                }
              
            });
        });
        
        // make it always repaint. TODO: can we slow down here?
        ctx.request_repaint();
      }
      else if self.show_interface_window==3{
        egui::SidePanel::left("Main").show(ctx, |ui| {
            egui::Grid::new("my_table").show(ui, |ui| {
                // Iterate through rows
                let data = self.measurements.lock().unwrap();
                // Iterate through rows
                for (key, stats) in &data.table_data {
                    let mut k:&str;
                    let mut f:&str;
                    let mut n: f64;
                    let mut l:f64;
                   
                       (n,k)= get_packet_multiple(stats.download);
                       (l,f)= get_packet_multiple(stats.upload);
                       ui.label(format!("Key: {}, Download: {:.5} {} , Upload: {:.5} {} ", key,n,k, l,f));
                       ui.end_row();
                }
               
                
            });
            
        });
        egui::SidePanel::right("Table").show(ctx, |ui| {
            // Display the table
            egui::Grid::new("my_table").show(ui, |ui| {
                // Iterate through rows
                let data = self.measurements.lock().unwrap();
                // Iterate through rows
                let mut pid_ipv4s: HashMap<u32, HashSet<String>> = HashMap::new();

    match fs::read_dir("/proc") {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        match entry.file_type() {
                            Ok(file_type) => {
                                if file_type.is_dir() {
                                    if let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                                        let pid_fd_dir = entry.path().join("fd");
                                        if pid_fd_dir.exists() {
                                            let mut ipv4_addresses = HashSet::new();
                                            match fs::read_dir(pid_fd_dir) {
                                                Ok(fd_entries) => {
                                                    for fd_entry in fd_entries {
                                                        match fd_entry {
                                                            Ok(fd_entry) => {
                                                                if let Some(ip) = get_ip_from_fd(&fd_entry.path()) {
                                                                    ipv4_addresses.insert(ip);
                                                                }
                                                            },
                                                            Err(e) => eprintln!("Error reading fd entry: {}", e),
                                                        }
                                                    }
                                                    pid_ipv4s.insert(pid, ipv4_addresses);
                                                },
                                                Err(e) => eprintln!("Error reading fd directory: {}", e),
                                            }
                                        }
                                    }
                                }
                            },
                            Err(e) => eprintln!("Error getting file type: {}", e),
                        }
                    },
                    Err(e) => eprintln!("Error reading entry: {}", e),
                }
            }
        },
        Err(e) => eprintln!("Error reading /proc directory: {}", e),
    }
                
                remove_duplicates(&mut pid_ipv4s);
                // Print IPv4 addresses for each PID
                for (pid, ips) in &pid_ipv4s {
                    //println!("PID {} usr: {:?}", pid, get_process_owner(pid));
                    for ip in ips{
                      
                    ui.label(format!("PID {} usr: {:?}", pid, hex_to_ipv4(ip as &str)));
                    ui.end_row();
                    }
                }
             
               
               
            });
        });
        
        ctx.request_repaint();
      }
    }
}





fn get_host_table( rx: &mut Box<dyn DataLinkReceiver>,  interface:&mut NetworkInterface,my_ip:Ipv4Addr,mut traffic_map:   HashMap<String, measurements::TrafficStats>){
    
       
    } 


use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{Packet, PacketSize};
use pnet::util::MacAddr;
use pnet::packet::ethernet::EtherTypes;
use std::thread;
struct TrafficData {
    upload_bytes: u64,
    download_bytes: u64,
}

impl TrafficData {
    fn new() -> Self {
        TrafficData {
            upload_bytes: 0,
            download_bytes: 0,
        }
    }

    fn add_upload(&mut self, bytes: u64) {
        self.upload_bytes += bytes;
    }

    fn add_download(&mut self, bytes: u64) {
        self.download_bytes += bytes;
    }

    fn reset(&mut self) {
        self.upload_bytes = 0;
        self.download_bytes = 0;
    }
}

fn throttle(upload_threshold: u64, download_threshold: u64, traffic_data: Arc<Mutex<TrafficData>>) {
    thread::spawn(move || {
        loop {
            let mut rng = rand::thread_rng();
            let mut x = 0.0;

            let mut traffic_data = traffic_data.lock().unwrap();
            while traffic_data.upload_bytes > upload_threshold || traffic_data.download_bytes > download_threshold {
                let start_time = Instant::now();

                if traffic_data.upload_bytes > upload_threshold {
                    let excess_upload = traffic_data.upload_bytes - upload_threshold;
                    let delay_duration = Duration::from_secs(1);
                    println!("Upload threshold exceeded by {} bytes. Throttling...", excess_upload);
                    thread::sleep(delay_duration);
                    traffic_data.upload_bytes -= upload_threshold;
                }

                if traffic_data.download_bytes > download_threshold {
                    let excess_download = traffic_data.download_bytes - download_threshold;
                    let delay_duration = Duration::from_secs(1);
                    println!("Download threshold exceeded by {} bytes. Throttling...", excess_download);
                    thread::sleep(delay_duration);
                    traffic_data.download_bytes -= download_threshold;
                }

                // Calculate the elapsed time and sleep for the remainder of the second if necessary
                let elapsed = start_time.elapsed();
                if elapsed < Duration::from_secs(1) {
                    thread::sleep(Duration::from_secs(1) - elapsed);
                }
            }

            x += 1.0;
            traffic_data.reset(); // Reset for the next period
        }
    });
}

fn handle_packet(interface: &NetworkInterface, packet: &EthernetPacket, traffic_data: Arc<Mutex<TrafficData>>) {
    if let Some(ip_packet) = Ipv4Packet::new(packet.payload()) {
        let size = ip_packet.packet_size() as u64;

        let mut traffic_data = traffic_data.lock().unwrap();
        if is_upload(interface, &ip_packet) {
            traffic_data.add_upload(size);
        } else {
            traffic_data.add_download(size);
        }
    }
}

fn is_upload(interface: &NetworkInterface, packet: &Ipv4Packet) -> bool {
    
    packet.get_source() == interface.ips[0].ip()
}
/* 
fn main() {
    let interface_name = "enp0s3"; // Replace with your network interface name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.name == interface_name).unwrap();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    let traffic_data = Arc::new(Mutex::new(TrafficData::new()));
    let upload_threshold = 1000; // in bytes per second
    let download_threshold = 1000; // in bytes per second

    throttle(upload_threshold, download_threshold, Arc::clone(&traffic_data));

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                handle_packet(&interface, &packet, Arc::clone(&traffic_data));
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}*/




fn main() {
  // let args = Args::parse();

  
  let window_size:usize =100;
  //  let mut app = MonitorApp::new(args.window_size);
  let  app = MonitorApp::new(window_size);
   // app.
   // app.include_y = args.include_y;
   
    let  native_options = eframe::NativeOptions::default();
   

    let monitor_ref = app.measurements.clone();
    let upl_mon=app.upload_measurements.clone();
    use pnet::datalink::Channel::Ethernet; //new
    let mut my_ip:Ipv4Addr=Ipv4Addr::new(0, 0, 0, 0);
    let mut traffic_map: HashMap<String, measurements::TrafficStats>=Default::default();
    let mut lim_vec=LimitedVec::new(22);
    let mut lim_sec=LimitedVec::new(22);
  
        let iface_name = "enp0s3";
        let NetInterface =datalink::interfaces();
        for ih in NetInterface{
            println!("{}",ih.name);
        }
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name);

        // If the interface is found, print its IP addresses
        if let Some(interface) = interface {
            println!("Interface: {}", interface.name);

            // Iterate over the IP addresses associated with the interface
            for ip in interface.ips {
                match ip.ip() {
                    IpAddr::V4(v4) =>{ println!("    IPv4 Address: {}", v4); my_ip=v4;},
                    IpAddr::V6(v6) => println!("    IPv6 Address: {}", v6),
                    
                }
            }
        } else {
            println!("Interface not found.");
        }
        println!("MY IP ADDR: {}",my_ip);
    
        let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

        // Find the network interface with the provided name
        
        let interfaces = datalink::interfaces();
        let mut interface = interfaces
            .into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

        // Create a channel to receive on
    // let mut rx:&mut Box<dyn DataLinkReceiver>;
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("packetdump: unhandled channel type"),
            Err(e) => panic!("packetdump: unable to create channel: {}", e),
        };

        let interface_name = "enp0s3"; // Replace with your network interface name
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter().find(|iface| iface.name == interface_name).unwrap();
    
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("Error creating datalink channel: {}", e),
        };
       //thread here
       let traffic_data2 = Arc::new(Mutex::new(TrafficData::new()));
       let upload_threshold = 100; // in bytes per second
       let download_threshold = 100; // in bytes per second
   
      
        throttle(upload_threshold, download_threshold, Arc::clone(&traffic_data2));
        thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut x = 0.0;
            //let  y:f64=0.0;
            loop {
                // Simulate some processing time
                thread::sleep(std::time::Duration::from_millis(500));

                // Generate random measurement values
                let y:f64;
                let z:f64;
            let (y,z) = getdw();
            
                monitor_ref.lock().unwrap().add(measurements::Measurement::new(x, y)); // Corrected to use the measurements module prefix
                upl_mon.lock().unwrap().add(measurements::Measurement::new(x, z));
             
                let mut data= monitor_ref.lock().unwrap();
                let mut buf: [u8; 1600] = [0u8; 1600];
                let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
                match rx.next() {
                    Ok(packet) => {
                      
                            let packet2 = EthernetPacket::new(packet).unwrap();
                            handle_packet(&interface, &packet2, Arc::clone(&traffic_data2));
                       
                      
                        let payload_offset;
                        if cfg!(any(target_os = "macos", target_os = "ios"))
                            && interface.is_up()
                            && !interface.is_broadcast()
                            && ((!interface.is_loopback() && interface.is_point_to_point())
                                || interface.is_loopback())
                        {
                            if interface.is_loopback() {
                                // The pnet code for BPF loopback adds a zero'd out Ethernet header
                                payload_offset = 14;
                            } else {
                                // Maybe is TUN interface
                                payload_offset = 0;
                            }
                            if packet.len() > payload_offset {
                                let version = Ipv4Packet::new(&packet[payload_offset..])
                                    .unwrap()
                                    .get_version();
                                if version == 4 {
                                    fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                                    fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                                    handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(),my_ip.to_string().as_str(),&mut traffic_map,&mut lim_vec);
                                //   continue;
                                } else if version == 6 {
                                    fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                                    fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                                    handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(),my_ip.to_string().as_str(),&mut traffic_map,&mut lim_vec);
                                //  continue;
                                }
                            }
                        }
                        handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap(),my_ip.to_string().as_str(),&mut traffic_map,&mut lim_vec);
                    }
                    Err(e) => panic!("packetdump: unable to receive packet: {}", e),
                }

                data.set_data(traffic_map.clone());
                lim_sec.push(x.to_string());
                data.set_lim(lim_vec.clone(),lim_sec.clone());
                
                // Increment x
                x += 1.0;
            }
        });
    

        info!("Main thread started");
        eframe::run_native("Download Bits / Sec", native_options, Box::new(|_| Box::new(app)));
}


use pnet::datalink::{ DataLinkReceiver};
//use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
//use std::time::Duration;
use pnet::packet::arp::ArpPacket;
//use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::gre::U16BE;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
//use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
//use pnet::packet::Packet;
//use pnet::util::MacAddr;
use ::str::Str;
use std::collections::HashMap;
use std::env;
use std::hash::Hash;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Add;
use std::process;
struct TrafficStats {
    download: f64,
    upload: f64,
}

impl TrafficStats {
    fn new() -> Self {
        TrafficStats { download: 0.0, upload: 0.0 }
    }
}

fn update_traffic_stats(
    src_ip: &str,
    dst_ip: &str,
    my_ip:&str,
    data: f64,
    traffic_map: &mut HashMap<String, measurements::TrafficStats>,
    lim:&mut LimitedVec,
) {
   
    // Update download for source IP
  if(dst_ip.contains(my_ip)){
    if let Some(value) = traffic_map.get_mut(src_ip) {
        // If the key exists, update dow and up values
       
        value.upload += data*8.0;//isit8
        lim.push(src_ip.to_string() );
      //  println!("Updated value for {}: {:?}", key_to_check, value);
    } else {
        // If the key does not exist, print a message
        traffic_map.insert(String::from(src_ip), measurements::TrafficStats { download:0.0,upload:data });
        lim.push(src_ip.to_string() );
       // println!("Key {} not found in the hashmap.", key_to_check);
    }
   }

    else if(src_ip.contains(my_ip)){
        if let Some(value) = traffic_map.get_mut(dst_ip) {
            // If the key exists, update dow and up values
           
            value.download += data*8.0;//isit8
            lim.push(dst_ip.to_string() );
          //  println!("Updated value for {}: {:?}", key_to_check, value);
        } else {
            // If the key does not exist, print a message
            traffic_map.insert(String::from(dst_ip), measurements::TrafficStats { download:data,upload:0.0 });
            lim.push(dst_ip.to_string() );
           // println!("Key {} not found in the hashmap.", key_to_check);
        }
    }
}
 

fn handle_udp_packet(interface_name: &str, source: &IpAddr, destination: &IpAddr, packet: &[u8],//traffic_map: &mut HashMap<String,TrafficStats>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
      // let ip_address = format!("{}",udp.get_source()); // ADD
       //let ip: IpAddr = ip_address.parse().expect("Invalid IP address");//ADD
      //  match reverse_dns_lookup(ip) {
        //    Some(domain) => println!("The domain name for IP address {} is: {}", ip_address, domain),
          //  None => println!("Unable to retrieve domain name for IP address {}", ip_address),
        //}
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),  //add
            destination,
            udp.get_destination(),//add
            udp.get_length(),
        );
      
        
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_icmp_packet(interface_name: &str, source: &IpAddr, destination: &IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: &IpAddr, destination: &IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_tcp_packet(interface_name: &str, source: &IpAddr, destination: &IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    my_ip:&str,
    traffic_map: &mut HashMap<String, measurements::TrafficStats>,
    lim:&mut LimitedVec,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, &source, &destination, &packet);
            update_traffic_stats(source.to_string().as_str(),
             destination.to_string().as_str(), my_ip,packet.len() as f64, traffic_map,lim);
             //download see > notif_DW , if upl> nitf_upl
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, &source, &destination, &packet);
            update_traffic_stats(source.to_string().as_str(),
             destination.to_string().as_str(), my_ip,packet.len() as f64, traffic_map,lim);
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, &source, &destination, &packet);
            update_traffic_stats(source.to_string().as_str(),
             destination.to_string().as_str(), my_ip,packet.len() as f64, traffic_map,lim);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, &source, &destination, &packet);
            update_traffic_stats(source.to_string().as_str(),
             destination.to_string().as_str(), my_ip,packet.len() as f64, traffic_map,lim);
        }
        _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket,my_ip:&str,traffic_map: &mut HashMap<String, measurements::TrafficStats>,lim:&mut LimitedVec) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
             my_ip,
             traffic_map, lim,
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket,my_ip:&str,traffic_map: &mut HashMap<String, measurements::TrafficStats>,lim:&mut LimitedVec) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
               my_ip,
             traffic_map,lim,
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
    } else {
        println!("[{}]: Malformed ARP Packet", interface_name);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket,my_ip:&str,traffic_map: &mut HashMap<String, measurements::TrafficStats>,lim:&mut LimitedVec) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet,my_ip,traffic_map,lim),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet,my_ip,traffic_map,lim),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
      
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

struct AddressPair{
    src_ip:String,
    src_port:u16,
    dst_ip:String,
    dst_port:u16,
}
struct TS{
    outp:u64,
    incp:u64,
}
impl TS{
    fn new()->Self{
            TS { outp:0, incp: 0,}
    }
}

use std::collections:: HashSet;
use std::fs;

use std::path::{Path, PathBuf};


// Function to read the owner of a process from its status file
fn get_process_owner(pid: &u32) -> Option<String> {
    if let Ok(status_content) = fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "Uid:" {
                if let Ok(uid) = parts[1].parse::<u32>() {
                    if let Some(username) = user_from_uid(uid) {
                        return Some(username);
                    }
                }
            }
        }
    }
    None
}

// Function to map UID to username
fn user_from_uid(uid: u32) -> Option<String> {
    if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
        for line in passwd_content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                if let Ok(found_uid) = fields[2].parse::<u32>() {
                    if found_uid == uid {
                        return Some(fields[0].to_string());
                    }
                }
            }
        }
    }
    None
}


fn hex_to_ipv4(input: &str) -> Option<String> {
    // Split the input string on the colon to separate IP and port parts
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let hex_ip = parts[0];

    // Ensure the IP part is 8 characters long
    if hex_ip.len() != 8 {
        return None;
    }

    // Convert the IP part from hexadecimal to a list of integers
    let mut ip_parts = Vec::new();
    for i in 0..4 {
        let byte_str = &hex_ip[i * 2..i * 2 + 2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => ip_parts.push(byte),
            Err(_) => return None,
        }
    }

    // Join the integers with dots to form the IPv4 address
    Some(format!("{}.{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]))
}
fn strip_port(ip_with_port: &str) -> Result<String, &str> {
    ip_with_port.split(':')
        .next()
        .map(|ip| ip.to_string())
        .ok_or("Invalid IP format")
}

// Function to remove duplicate IPs within the same PID
fn remove_duplicates(map: &mut HashMap<u32, HashSet<String>>) {
    for hashset in map.values_mut() {
        let mut seen_ips = HashSet::new();
        let mut ips_to_remove = Vec::new();

        for ip_with_port in hashset.iter() {
            if let Ok(ip) = strip_port(ip_with_port) {
                if !seen_ips.insert(ip) {
                    ips_to_remove.push(ip_with_port.clone());
                }
            }
        }

        for ip_to_remove in ips_to_remove {
            hashset.remove(&ip_to_remove);
        }
    }
}/*
fn main() -> io::Result<()> {
    let mut pid_ipv4s: HashMap<u32, HashSet<String>> = HashMap::new();

    // Iterate over /proc directory to get PIDs
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            // Check if entry is a directory representing a PID
            if let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                let pid_fd_dir = entry.path().join("fd");
                if pid_fd_dir.exists() {
                    let mut ipv4_addresses = HashSet::new();
                    // Iterate over file descriptors for the current PID
                    for fd_entry in fs::read_dir(pid_fd_dir)? {
                        let fd_entry = fd_entry?;
                        if let Some(ip) = get_ip_from_fd(&fd_entry.path()) {
                            ipv4_addresses.insert(ip);
                        }
                    }
                    pid_ipv4s.insert(pid, ipv4_addresses);
                }
            }
        }
    }
    
    remove_duplicates(&mut pid_ipv4s);
    // Print IPv4 addresses for each PID
    for (pid, ips) in &pid_ipv4s {
        //println!("PID {} usr: {:?}", pid, get_process_owner(pid));
        for ip in ips{
        println!("PID {} usr: {:?}", pid, hex_to_ipv4(ip as &str));
        }
    }

    Ok(())
}*/

fn get_ip_from_fd(fd_path: &Path) -> Option<String> {
    // Read the symbolic link to determine the target of the file descriptor
    if let Ok(target) = fs::read_link(fd_path) {
        if let Some(target_str) = target.to_str() {
            // Parse the target path to extract socket information
            if let Some(inode) = parse_socket_inode_from_target(target_str) {
                if let Some(ip) = get_ip_from_inode(inode) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

fn parse_socket_inode_from_target(target: &str) -> Option<u32> {
    // Example target format: "socket:[12345]"
    if let Some(start) = target.find("[") {
        if let Some(end) = target.find("]") {
            if let Ok(inode) = target[start + 1..end].parse::<u32>() {
                return Some(inode);
            }
        }
    }
    None
}

fn get_ip_from_inode(inode: u32) -> Option<String> {
    // Iterate over /proc/net/tcp and /proc/net/udp to find the IP associated with the given inode
    for &net_path in &["tcp", "udp"] {
        let path = PathBuf::from("/proc/net").join(net_path);
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 10 {
                    if let Ok(inode_from_line) = cols[9].parse::<u32>() {
                        if inode_from_line == inode {
                            return Some(cols[1].to_string());
                        }
                    }
                }
            }
        }
    }
    None
}





fn display_traffic_map(traffic_map: &HashMap<String, measurements::TrafficStats>) {
    println!("Traffic Map:");
    let mut k:&str;
    let mut f:&str;
    let mut n: f64;
    let mut l:f64;
    for (key, value) in traffic_map {
       (n,k)= get_packet_multiple(value.download);
       (l,f)= get_packet_multiple(value.upload);

        println!("Key: {}, Download: {:.5} {} , Upload: {:.5} {} ", key,n,k, l,f);
    }
}

/* 
fn main() {
    use pnet::datalink::Channel::Ethernet;
    let mut my_ip:Ipv4Addr=Ipv4Addr::new(0, 0, 0, 0);
    let mut traffic_map: HashMap<String, TrafficStats>=Default::default();
    let iface_name = "enp0s3";
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name);

    // If the interface is found, print its IP addresses
    if let Some(interface) = interface {
        println!("Interface: {}", interface.name);

        // Iterate over the IP addresses associated with the interface
        for ip in interface.ips {
            match ip.ip() {
                IpAddr::V4(v4) =>{ println!("    IPv4 Address: {}", v4); my_ip=v4;},
                IpAddr::V6(v6) => println!("    IPv6 Address: {}", v6),
                
            }
        }
    } else {
        println!("Interface 'enp0s3' not found.");
    }
    println!("MY IP ADDR: {}",my_ip);
   // let mut TM:HashMap<AddressPair,TS>=HashMap::new();
   // let mut traffic_map: HashMap<String, TrafficStats> = HashMap::new();

    // your existing code goes here...

    // Within your handling logic, update the traffic map for each packet processed
    // For example, within handle_udp_packet, handle_tcp_packet, etc.

    // Example for handling UDP packet
   

    // Similar functions for other packet types

    // Function to update traffic statistics for an IP pair
  
    /*match env::args().nth(3) {
        
        Some(n) => n,
        None => {

            
            writeln!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
           
            process::exit(1);
        }
    };*/
   
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(),my_ip.to_string().as_str(),&mut traffic_map);
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(),my_ip.to_string().as_str(),&mut traffic_map);
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap(),my_ip.to_string().as_str(),&mut traffic_map);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
        display_traffic_map(&traffic_map);
    } 
}*/






   // extern crate dns_lookup;
  /* 
  use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
   use std::process::Command;
   use std::str;
   
   // Function to perform a reverse DNS lookup
   fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
       let output = match ip {
           IpAddr::V4(ipv4) => Command::new("host")
               .arg(ipv4.to_string())
               .output()
               .ok(),
           IpAddr::V6(ipv6) => Command::new("host")
               .arg(ipv6.to_string())
               .output()
               .ok(),
       };
   
       if let Some(output) = output {
           if output.status.success() {
               let output_str = String::from_utf8(output.stdout).unwrap();
               let parts: Vec<&str> = output_str.split_whitespace().collect();
               if parts.len() >= 5 {
                   let domain = parts[4].trim_matches('.');
                   return Some(domain.to_string());
               }
           }
       }
       None
   }
   
   fn main() {
       let ip_address = "142.251.37.162"; // Replace this with the IP address you want to look up
       let ip: IpAddr = ip_address.parse().expect("Invalid IP address");
   
       match reverse_dns_lookup(ip) {
           Some(domain) => println!("The domain name for IP address {} is: {}", ip_address, domain),
           None => println!("Unable to retrieve domain name for IP address {}", ip_address),
       }
   }*/
 


  
   


use pcap::Device;

use crate::measurements::LimitedVec;



fn  getdw() ->(f64,f64){
   // let interfaces_list = Device::list().unwrap();
    
    // Loop through each interface and print its name
   // for interface_l in interfaces_list {
     //   println!("Interface: {}", interface_l.name);
    //}
    
    let interface = "enp0s3"; // Change this to your network interface name
    let duration = Duration::from_secs(60); // Set the duration for monitoring (in seconds)

    let mut last_stats = get_network_stats(interface).unwrap_or((0, 0));
    let mut last_time = Instant::now();

    loop {
        thread::sleep(Duration::from_secs(1));
        let elapsed_time = Instant::now().duration_since(last_time);
        if elapsed_time >= duration {
           //return 0.0;
           // break;
        }

        if let Some((rx_bytes, tx_bytes)) = get_network_stats(interface) {
            let  sr: &str;
            let  tr: &str;
            let elapsed_time_secs = elapsed_time.as_secs_f64();
           /* let rx_speed_mbps = ((rx_bytes - last_stats.0) as f64 * 8.0 / 1_000_000.0) / elapsed_time_secs;
            let tx_speed_mbps = ((tx_bytes - last_stats.1) as f64 * 8.0 / 1_000_000.0) / elapsed_time_secs;*/
            let mut rx_speed_mbps = ((rx_bytes - last_stats.0) as f64 * 8.0 ) / elapsed_time_secs;
         
           
          
          
            let mut tx_speed_mbps = ((tx_bytes - last_stats.1) as f64 * 8.0 ) / elapsed_time_secs;
            let   y: f64=(rx_speed_mbps);
            let   z: f64=(tx_speed_mbps);

            last_stats = (rx_bytes, tx_bytes);
           last_time += elapsed_time;
            return (y,z);
            //graph_download(rx_....)
            // ins
            //
            (rx_speed_mbps,sr)=get_packet_multiple(rx_speed_mbps);
            (tx_speed_mbps,tr)=get_packet_multiple(tx_speed_mbps);
            println!("Download Speed: {:.5} {}/s, Upload Speed: {:.5} {}/s", rx_speed_mbps,sr, tx_speed_mbps,tr);
            
           // last_stats = (rx_bytes, tx_bytes);
           // last_time += elapsed_time;
        }
    }
}
