use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::transport::TransportSender;

pub fn get_port_responses(ip_addr: IpAddr, open_ports: &[u16]) -> Vec<(u16, String)> {
    let mut port_responses: Vec<(u16, String)> = Vec::new();
    const MAX_RETRIES: usize = 5;

    const MESSAGE: &[u8] = b"Hello, world!";

    for &port in open_ports {
        let socket = open_socket().unwrap();
        let addr = SocketAddr::from((ip_addr, port));
        let mut retries = 0;

        loop {
            let send_result = send_message(&socket, MESSAGE, &addr);
            match send_result {
                Ok(_) => {
                    let receive_result = receive_message(&socket);
                    match receive_result {
                        Ok(response) => {
                            let response_str = String::from_utf8_lossy(&response).to_string();
                            port_responses.push((port, response_str));
                            break; // Exit the loop if everything is successful
                        }
                        Err(e) => {
                            println!("Error receiving from port {}: {}", port, e);
                            retries += 1;
                        }
                    }
                }
                Err(e) => {
                    println!("Error sending to port {}: {}", port, e);
                    retries += 1;
                }
            }

            if retries >= MAX_RETRIES {
                println!("Max retries reached for port {}", port);
                break;
            }
        }
    }

    port_responses
}

/// Creates and returns a Result containing a UDP socket with a timeout of 1 second or an error
pub fn open_socket() -> io::Result<UdpSocket> {
    let local_socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
        eprintln!("Error binding to address for {}: {}", "0.0.0.0", e);
        e
    })?;

    local_socket
        .set_read_timeout(Some(std::time::Duration::new(1, 0)))
        .map_err(|e| {
            eprintln!("Error setting read timeout for {}: {}", "addr", e);
            e
        })?;

    Ok(local_socket)
}

pub fn send_and_receive_l3<T: Packet>(
    tx: &mut TransportSender,
    packet: T,
    socket: &UdpSocket,
    dest_ip: IpAddr,
    max_retries: usize,
) -> Result<Vec<u8>, String> {
    let mut retries = 0;
    let mut buf = [0u8; 4096];

    while retries < max_retries {
        // Send the packet using L3 channel
        match tx.send_to(&packet, dest_ip) {
            Ok(_) => println!("Packet sent successfully"),
            Err(e) => {
                println!("Failed to send packet: {}", e);
                retries += 1;
                continue;
            }
        }

        // Receive the packet using UDP socket
        match socket.recv_from(&mut buf) {
            Ok((amt, _src)) => {
                println!("Received {} bytes from the Dark Side", amt);
                return Ok(buf[0..amt].to_vec());
            }
            Err(e) => {
                println!("Failed to receive packet: {}", e);
                retries += 1;
            }
        }
    }

    Err(format!("Failed after {} retries", max_retries))
}

/// Handles sending and receiving a message to/from the given socket. The benefit of this function is that it will retry sending/receiving if it times out
pub fn send_and_receive(
    socket: &UdpSocket,
    message: &[u8],
    addr: &SocketAddr,
) -> io::Result<[u8; 1024]> {
    const MAX_RETRIES: usize = 5;
    let mut retries = 0;

    loop {
        match socket.send_to(message, addr) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error sending to {}: {}", addr, e);
                retries += 1;
                if retries >= MAX_RETRIES {
                    return Err(e);
                }
                continue;
            }
        }

        let mut buf = [0; 1024];

        match socket.recv_from(&mut buf) {
            Ok((amt, _)) => {
                // If we received data, break out of the loop
                if amt > 0 {
                    return Ok(buf);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // If we timed out and haven't exceeded max retries, retry
                if retries < MAX_RETRIES {
                    retries += 1;
                    continue;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Max retries reached",
                    ));
                }
            }
            Err(e) => {
                // For other errors, propagate the error up
                return Err(e);
            }
        }
    }
}

/// Sends a message to the given socket, with a maximum of 5 retries
pub fn send_message(socket: &UdpSocket, message: &[u8], addr: &SocketAddr) -> io::Result<()> {
    const MAX_RETRIES: u32 = 5;
    let mut retries = 0;

    loop {
        match socket.send_to(message, addr) {
            Ok(_) => return Ok(()),
            Err(e) if retries < MAX_RETRIES => {
                eprintln!("Error sending to {}: {}. Retrying...", addr, e);
                retries += 1;
            }
            Err(e) => {
                eprintln!(
                    "Error sending to {}: {}. Giving up after {} retries.",
                    addr, e, retries
                );
                return Err(e);
            }
        }
    }
}

/// Receives a message from the given socket, with a maximum of 10 retries
pub fn receive_message(socket: &UdpSocket) -> io::Result<[u8; 1024]> {
    let mut buf = [0; 1024];
    const MAX_RETRIES: usize = 3;
    let mut retries = 0;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, _)) => {
                // If we received data, break out of the loop
                if amt > 0 {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // If we timed out and haven't exceeded max retries, retry
                if retries < MAX_RETRIES {
                    retries += 1;
                    continue;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Max retries reached",
                    ));
                }
            }
            Err(e) => {
                // For other errors, propagate the error up
                return Err(e);
            }
        }
    }

    Ok(buf)
}
