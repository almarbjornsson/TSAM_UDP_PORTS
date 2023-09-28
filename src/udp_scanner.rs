use rayon::prelude::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

pub fn parse_arguments(args: Vec<String>) -> Option<(String, u16, u16)> {
    if args.len() != 4 {
        println!("Usage: ./scanner <IP address> <low port> <high port>");
        return None;
    }

    let ip_address = &args[1];
    let low_port: u16 = args[2].parse().expect("Invalid low port");
    let high_port: u16 = args[3].parse().expect("Invalid high port");

    if low_port == 0 || low_port > high_port || ip_address.parse::<IpAddr>().is_err() {
        return None;
    }

    Some((ip_address.clone(), low_port, high_port))
}

/// Scans ports in the given range on the given IP address in parallel
pub fn find_open_ports(ip_address: &str, low_port: u16, high_port: u16) -> Vec<u16> {
    let ports: Vec<u16> = (low_port..=high_port).collect();
    let results: Vec<u16> = ports
        .par_iter()
        .filter_map(|&port| {
            if is_port_open(ip_address, port) {
                Some(port)
            } else {
                None
            }
        })
        .collect();
    results
}

/// Checks if a UDP port is open on a given IP address
/// Retries 5 times before giving up with a 1 second timeout
fn is_port_open(ip_address: &str, port: u16) -> bool {
    let local_socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to address");
    local_socket
        .set_read_timeout(Some(Duration::new(1, 0)))
        .expect("Failed to set read timeout");

    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(ip_address.parse().unwrap()), port);

    for _ in 0..5 {
        let payload = b"Hello, world!";
        local_socket.send_to(payload, &addr).unwrap();

        let mut buf = [0; 1024];
        match local_socket.recv_from(&mut buf) {
            Ok(_) => return true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
    false
}
