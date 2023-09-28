// main.rs
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
mod port_handler_utils;
use pnet::packet::MutablePacket;
use port_handler_utils::{open_socket, send_and_receive, send_message};

use crate::port_handler_utils::{get_port_responses, receive_message, send_and_receive_l3};
mod udp_scanner;
extern crate pnet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::transport::{self, TransportChannelType::Layer3};
use pnet::util::checksum;

#[derive(PartialEq)]
enum HandlerType {
    DarkSide,
    Expstn,
    Secret,
    Signature,
}

fn handle_dark_side(socket_addr: SocketAddr, signature: &[u8; 4]) -> u16 {
    println!("Handling Dark Side...");
    // Create a new UDP socket to listen for the response and to provide a known source port
    // The source port will be manually set in the UDP packet
    let socket = open_socket().unwrap();

    // Create a new raw IPv4 transport channel
    let (mut tx, _) = transport::transport_channel(4096, Layer3(IpNextHeaderProtocols::Udp))
        .expect("Failed to create transport channel");

    // UDP packet

    let source_port = socket.local_addr().unwrap().port(); // Random source port given by OS/Socket
    let dest_port = socket_addr.port(); // Dark Side port
                                        // Print the source port and destination port
    println!("Source Port: {}", source_port);
    println!("Destination Port: {}", dest_port);

    let mut udp_buffer = [0u8; 12]; // 8-byte header + 4-byte payload
    let mut udp_packet =
        MutableUdpPacket::new(&mut udp_buffer).expect("Failed to create UDP packet");
    udp_packet.set_source(source_port);
    udp_packet.set_destination(dest_port);
    // Signature is the payload (4 bytes)
    udp_packet.set_payload(signature);
    udp_packet.set_length(12); // 8-byte header + 1-byte payload
    let csum = checksum(udp_packet.packet_mut(), 1);
    udp_packet.set_checksum(csum);

    // IPV4 packet
    let source_ip = Ipv4Addr::from([130, 208, 29, 23]); // Replace with your source IP
    let dest_ip = Ipv4Addr::from([164, 92, 223, 132]); // Replace with your destination IP

    let mut ipv4_buffer = [0u8; 32]; // 20-byte header + 12-byte UDP packet
    let mut ipv4_packet =
        MutableIpv4Packet::new(&mut ipv4_buffer).expect("Failed to create IPv4 packet");
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_version(4); // IPv4
    ipv4_packet.set_ttl(64); // Default value
    ipv4_packet.set_header_length(5); // 5 * 4 bytes = 20 bytes
    ipv4_packet.set_flags(0b100); // With Evil-Bit set
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(dest_ip);

    ipv4_packet.set_total_length(20 + 12); // 20-byte header + 9-byte UDP packet
    ipv4_packet.set_payload(udp_packet.packet_mut());
    let checksum = checksum(ipv4_packet.packet_mut(), 1);
    ipv4_packet.set_checksum(checksum);
    // Make udp tranport channel and send raw packet using raw_socket

    let dest_ip_addr: IpAddr = dest_ip.into();
    // Sanity checks

    // Source and destination ips
    println!("Source IP: {}", ipv4_packet.get_source());
    println!("Destination IP: {}", ipv4_packet.get_destination());

    // Source and destination ports
    println!("Source Port: {}", udp_packet.get_source());
    println!("Destination Port: {}", udp_packet.get_destination());

    // Print UDP packet
    println!("UDP Packet: {:?}", udp_packet);
    // Print IPV4 packet
    println!("IPV4 Packet: {:?}", ipv4_packet);

    // // Send the packet
    // tx.send_to(ipv4_packet, dest_ip_addr)
    //     .expect("Failed to send the packet");

    // let raw_buf = receive_message(&socket).expect("To receive packet from Dark Side");
    let raw_buf = send_and_receive_l3(&mut tx, ipv4_packet, &socket, dest_ip_addr, 5)
        .expect("To receive packet from Dark Side");
    //Extract and return port in response message
    // Example: Yes, strong in the dark side you are group 32 . Here is my secret port: 4070
    let response = String::from_utf8_lossy(
        &raw_buf[..raw_buf
            .iter()
            .position(|&x| x == 0)
            .unwrap_or(raw_buf.len())],
    )
    .to_string();

    // Extract port number from string
    let port = response
        .split_whitespace()
        .last()
        .unwrap()
        .trim_matches(|c: char| !c.is_numeric())
        .parse::<u16>()
        .unwrap();
    println!("Dark Side Step 1: {}", response);
    println!("Dark Side Step 2: Secret port is {}", port);
    port
}

fn handle_expstn(
    socket_addr: SocketAddr,
    secret_ports: Vec<u16>,
    secret_phrase: String,
    signature: &[u8; 4],
) {
    println!("Handling Expstn...");
    //     Greetings! I am E.X.P.S.T.N, which stands for "Enhanced X-link Port Storage Transaction Node".

    // What can I do for you?
    // - If you provide me with a list of secret ports (comma-separated), I can guide you on the exact sequence of "knocks" to ensure you score full marks.

    // How to use E.X.P.S.T.N?
    // 1. Each "knock" must be paired with both a secret phrase and your unique S.E.C.R.E.T signature.
    // 2. The correct format to send a knock: First, 4 bytes containing your S.E.C.R.E.T signature, followed by the secret phrase.

    // Format secret ports in a comma-separated string
    let secret_ports_string = secret_ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<String>>()
        .join(",");
    println!("Secret ports: {}", secret_ports_string);
    // Send secret ports to E.X.P.S.T.N
    let socket = open_socket().unwrap();
    let raw_buf = send_and_receive(&socket, secret_ports_string.as_bytes(), &socket_addr).unwrap();

    // Get string response from E.X.P.S.T.N, up to the first null byte
    let null_index = raw_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw_buf.len());
    let valid_data = &raw_buf[0..null_index];

    let response = String::from_utf8_lossy(valid_data).to_string();

    // Parse comma seperated list of ports in response
    let ports_to_knock: Vec<u16> = response
        .split(",")
        .filter_map(|port| port.trim().parse::<u16>().ok())
        .collect();

    println!("Expstn Step 1: {:?}", response);

    println!("Ports to knock: {:?}", ports_to_knock);

    // Signature and secret phrase are already in the correct format
    println!("Signature: {:?}", signature);
    println!("Secret phrase: {}", secret_phrase);

    // Send knocks to E.X.P.S.T.N
    for port in ports_to_knock {
        let socket = open_socket().unwrap();
        let socket_addr = SocketAddr::from((Ipv4Addr::from([164, 92, 223, 132]), port));
        let mut knock = signature.to_vec();
        knock.extend_from_slice(secret_phrase.as_bytes());
        println!("Knock: {:?}", knock);
        let result = send_message(&socket, &knock, &socket_addr);
    }
    let raw_buf = receive_message(&socket).unwrap();
}

fn handle_signature(socket_addr: SocketAddr, signature: &[u8; 4]) -> String {
    println!("Handling Signature...");

    let socket = open_socket().unwrap();

    // Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order).

    let result = send_message(&socket, signature, &socket_addr);

    println!("Signature Step 1: {:?}", result);

    let mut buf = [0; 1024];
    let (amt, _) = socket.recv_from(&mut buf).unwrap();

    let response = String::from_utf8_lossy(&buf[0..amt]).to_string();
    println!("Signature Step 2: {}", response);

    // Extract the last 6 bytes
    let last_six_bytes: [u8; 6] = buf[amt - 6..amt].try_into().unwrap();

    // First 2 bytes of the last 6 bytes are the checksum
    let checksum_bytes: [u8; 2] = last_six_bytes[0..2].try_into().unwrap();

    // Last 4 bytes are the source IP address
    let source_ip_bytes: [u8; 4] = last_six_bytes[2..6].try_into().unwrap();

    let source_ip = Ipv4Addr::from(source_ip_bytes);
    let dest_ip = Ipv4Addr::from([164, 92, 223, 132]); // Replace with your destination IP

    // Create socket to get the source port

    // get port from socket
    let source_socket_addr = socket.local_addr().unwrap();
    let source_port = source_socket_addr.port();
    // Get port from Socket Address passed in to function. This is the port of the server.
    let dest_port = socket_addr.port();

    // UDP packet
    let mut udp_buffer = [0u8; 10]; // 8-byte header + 2-byte payload
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_packet.set_source(source_port);
    udp_packet.set_destination(dest_port);
    udp_packet.set_checksum(0);
    udp_packet.set_payload(&[0, 0]); // 2-byte payload
    udp_packet.set_length(8 + 2 as u16);

    println!("UDP Packet before checksum: {:?}", udp_packet);

    // Create pseudo-header
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&source_ip.octets());
    pseudo_header.extend_from_slice(&dest_ip.octets());
    pseudo_header.push(0); // Zeroes
    pseudo_header.push(17); // Protocol (UDP)
                            // Update the length in the pseudo-header
    pseudo_header.extend_from_slice(&(udp_packet.packet_mut().len() as u16).to_be_bytes());

    println!("Pseudo-header: {:?}", pseudo_header);

    let desired_checksum: u16 = u16::from_be_bytes(checksum_bytes);
    let mut actual_checksum = 0u16;
    let mut brute_force: u16 = 0;
    println!(
        "Payload before brute force: {:?}",
        brute_force.to_be_bytes()
    );
    while actual_checksum != desired_checksum {
        // The payload is 4 bytes, increment a u32 and convert to bytes
        let payload = brute_force.to_be_bytes();
        udp_packet.set_payload(&payload);

        // Create a buffer that includes the pseudo-header, UDP header, and payload
        let mut checksum_buffer = Vec::new();
        checksum_buffer.extend_from_slice(&pseudo_header);
        checksum_buffer.extend_from_slice(udp_packet.packet_mut());
        udp_packet.set_checksum(actual_checksum);

        // Checksum starts at the 19th byte
        // Checksum has skipword * 2 bytes so we set it to 9 to skip the 19th and 20th bytes
        actual_checksum = checksum(&checksum_buffer, 9);

        brute_force += 1;
    }

    println!("Found checksum: {:x}", actual_checksum);
    println!("Payload: {:?}", brute_force.to_be_bytes());
    println!("Payload after brute force: {:?}", udp_packet.payload_mut());
    udp_packet.set_checksum(actual_checksum);

    // Print UDP packet
    println!("UDP Packet after checksum: {:?}", udp_packet);
    // let csum = checksum(udp_packet.packet_mut(), 1);

    let mut ipv4_buffer = [0u8; 30]; // 20-byte header + 8-byte UDP header + 4-byte payload
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_version(4); // IPv4
    ipv4_packet.set_ttl(64); // Default value
    ipv4_packet.set_header_length(5); // 5 * 4 bytes = 20 bytes
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(dest_ip);
    ipv4_packet.set_total_length(20 + 8 + 2); // Header length + UDP length
                                              // ipv4_packet.set_checksum(checksum_uint16);
    ipv4_packet.set_payload(udp_packet.packet_mut());
    let csum = checksum(ipv4_packet.packet_mut(), 1);
    ipv4_packet.set_checksum(csum);
    println!("Actual ipv4 packet: {:?}", ipv4_packet);

    socket
        .send_to(ipv4_packet.packet_mut(), socket_addr)
        .unwrap();

    let raw_buffer = send_and_receive(&socket, &udp_packet.packet_mut(), &socket_addr).unwrap();

    let response = String::from_utf8_lossy(&raw_buffer).to_string();
    println!("Signature Step 3: {}", response);

    // Extract secret phrase from response
    // Example: Congratulations group 32! Here is the secret phrase: "Ennyn Durin Aran Moria. Pedo Mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion teithant i thiw hin."
    let start_index = response.find('"').unwrap_or(0);
    let end_index = response.rfind('"').unwrap_or(0);

    if start_index < end_index {
        let secret_phrase = &response[start_index + 1..end_index];
        println!("Signature Step 4: {}", secret_phrase);
        return secret_phrase.to_string();
    } else {
        println!("Signature Step 4: No secret phrase found");
        return String::new();
    }
}

fn main() {
    const GROUP_NUMBER: u8 = 32;
    const GROUP_SECRET: u32 = 0xfe8d9ecf;
    const IP_ADDR: [u8; 4] = [164, 92, 223, 132];

    // // START OF SCANNER
    // let args: Vec<String> = std::env::args().collect();
    // let (ip_address, low_port, high_port) = match udp_scanner::parse_arguments(args) {
    //     Some(args) => args,
    //     None => return,
    // };

    // println!("Scanning {} from {} to {}", ip_address, low_port, high_port);

    // let open_ports = udp_scanner::find_open_ports(&ip_address, low_port, high_port);
    // println!("Open ports: {:?}", open_ports);

    // // END OF SCANNER
    let open_ports = vec![4001, 4010, 4021, 4052]; // Replace with scanner for dynamic ports. This is just for faster testing.

    let mut port_and_associated_handler: Vec<(u16, HandlerType)> = Vec::new();

    let ip_addr = IpAddr::from(IP_ADDR);
    let port_reponses = get_port_responses(ip_addr, open_ports.as_slice());

    for (port, response) in port_reponses {
        println!("Port: {}, Response: {}", port, response);
        match associate_port_with_handler(&response, port) {
            Ok(handler) => {
                port_and_associated_handler.push(handler);
            }
            Err(e) => {
                println!("Error getting handler for response: {}", e);
            }
        }
    }

    // Execute the handlers

    //Here we define shared variables that will be used by multiple handlers.
    //(To be accessible by multiple handlers, they must be defined outside of the scope of the handlers.)

    // Initialize signature as an empty Vec<u8>
    let mut signature: Vec<u8> = Vec::new();
    let mut secret_phrase: String = String::new();
    let mut secret_ports: Vec<u16> = Vec::new();

    // Find the port for the S.E.C.R.E.T handler
    if let Some(secret_port) = port_and_associated_handler
        .iter()
        .find(|(_, handler_type)| *handler_type == HandlerType::Secret)
        .map(|(port, _)| *port)
    {
        let socket_addr = SocketAddr::from((IP_ADDR, secret_port));
        let (sig, port) = handle_secret(socket_addr, GROUP_NUMBER, GROUP_SECRET);
        println!("Secret port: {}", port);
        println!("Signature: {:?}", signature);
        secret_ports.push(port);
        signature = sig;
    }

    // Find the port for the Dark Side handler
    if let Some(dark_side_port) = port_and_associated_handler
        .iter()
        .find(|(_, handler_type)| *handler_type == HandlerType::DarkSide)
        .map(|(port, _)| *port)
    {
        let socket_addr = SocketAddr::from((IP_ADDR, dark_side_port));

        let sig_slice = signature[0..4].try_into().unwrap();

        let secret_port = handle_dark_side(socket_addr, sig_slice);
        secret_ports.push(secret_port);
    }

    // Find the port for the Signature handler
    if let Some(signature_port) = port_and_associated_handler
        .iter()
        .find(|(_, handler_type)| *handler_type == HandlerType::Signature)
        .map(|(port, _)| *port)
    {
        let socket_addr = SocketAddr::from((IP_ADDR, signature_port));

        // Slice of the first 4 bytes of the signature
        let sig_slice = signature[0..4].try_into().unwrap();

        secret_phrase = handle_signature(socket_addr, &sig_slice);
    }

    // Find the port for the Expstn handler
    if let Some(expstn_port) = port_and_associated_handler
        .iter()
        .find(|(_, handler_type)| *handler_type == HandlerType::Expstn)
        .map(|(port, _)| *port)
    {
        let socket_addr = SocketAddr::from((IP_ADDR, expstn_port));
        // Slice of the first 4 bytes of the signature
        let sig_slice = signature[0..4].try_into().unwrap();
        handle_expstn(socket_addr, secret_ports, secret_phrase, &sig_slice);
    }
}

/// Factory function to get the correct handler for the given response
/// This is used to handle the different puzzles
fn associate_port_with_handler(
    response: &str,
    port: u16,
) -> Result<(u16, HandlerType), &'static str> {
    let handler_type = match response {
        _ if response.contains("The dark side of network programming") => HandlerType::DarkSide,
        _ if response.contains("Enhanced X-link Port Storage Transaction Node") => {
            HandlerType::Expstn
        }
        _ if response.contains("Greetings from S.E.C.R.E.T") => HandlerType::Secret,
        _ if response.contains("Send me a 4-byte message containing the signature") => {
            HandlerType::Signature
        }
        _ => return Err("Unknown response type"),
    };
    Ok((port, handler_type))
}

/// Returns the signature and the secret port number
pub fn handle_secret(
    socket_addr: SocketAddr,
    group_number: u8,
    group_secret: u32,
) -> (Vec<u8>, u16) {
    // Handle the S.E.C.R.E.T response
    println!("Handling S.E.C.R.E.T response");

    let socket = open_socket().unwrap();

    // 1. Send me your group number as a single unsigned byte.
    // 2. I'll reply with a 4-byte challenge (in network byte order) unique to your group.

    let raw_buffer = send_and_receive(&socket, &[group_number], &socket_addr).unwrap();

    let challenge = u32::from_be_bytes(raw_buffer[0..4].try_into().unwrap());

    println!("S.E.C.R.E.T Step 1,2: {}", challenge);

    // 3. Sign this challenge using the XOR operation with your group's secret (get that from your TA).
    let signed_challenge = group_secret ^ challenge;
    println!("S.E.C.R.E.T Step 3: {}", signed_challenge);

    // 4. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signed challenge (in network byte order).
    // 5. If your signature is correct, I'll grant you access to the port. Good luck!
    let mut reply = Vec::new();
    reply.push(group_number);
    reply.extend_from_slice(&signed_challenge.to_be_bytes());

    let raw_buffer = send_and_receive(&socket, &reply, &socket_addr).unwrap();

    // Print as text up to the first null byte
    let response = String::from_utf8_lossy(
        &raw_buffer[..raw_buffer
            .iter()
            .position(|&x| x == 0)
            .unwrap_or(raw_buffer.len())],
    )
    .to_string();
    println!("S.E.C.R.E.T Step 5: {:?}", response);

    // Extract the secret port number from the response
    // Example: "Well done group 32. You have earned the right to know the port: 4066!"
    let secret_port = response
        .split_whitespace()
        .last()
        .unwrap()
        .trim_matches(|c: char| !c.is_numeric())
        .parse::<u16>()
        .unwrap();

    // signed_challenge is a u32, which is 4 bytes, so we can convert it to a byte array
    let signature = signed_challenge.to_be_bytes().to_vec();

    (signature, secret_port)
}
