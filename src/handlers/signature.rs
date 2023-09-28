use std::net::{Ipv4Addr, SocketAddr};

use crate::port_handler_utils::{open_socket, send_and_receive, send_message};
use pnet::packet::MutablePacket;
use pnet::{
    packet::{ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, udp::MutableUdpPacket},
    util::checksum,
};

pub fn handle_signature(socket_addr: SocketAddr, signature: &[u8; 4]) -> String {
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

    // Create pseudo-header
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&source_ip.octets());
    pseudo_header.extend_from_slice(&dest_ip.octets());
    pseudo_header.push(0); // Zeroes
    pseudo_header.push(17); // Protocol (UDP)
                            // Update the length in the pseudo-header
    pseudo_header.extend_from_slice(&(udp_packet.packet_mut().len() as u16).to_be_bytes());

    let desired_checksum: u16 = u16::from_be_bytes(checksum_bytes);
    let mut actual_checksum = 0u16;
    let mut brute_force: u16 = 0;

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
    udp_packet.set_checksum(actual_checksum);

    let mut ipv4_buffer = [0u8; 30]; // 20-byte header + 8-byte UDP header + 2-byte payload
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_version(4); // IPv4
    ipv4_packet.set_ttl(64); // Default value
    ipv4_packet.set_header_length(5); // 5 * 4 bytes = 20 bytes
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(dest_ip);
    ipv4_packet.set_total_length(20 + 8 + 2); // Header length + UDP length
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
