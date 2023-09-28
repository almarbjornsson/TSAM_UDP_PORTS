use crate::port_handler_utils::open_socket;
use crate::port_handler_utils::send_and_receive_l3;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use pnet::transport;
use pnet::transport::TransportChannelType::Layer3;
use pnet::util::checksum;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

pub fn handle_dark_side(socket_addr: SocketAddr, signature: &[u8; 4]) -> u16 {
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
    let source_ip = Ipv4Addr::from([0, 0, 0, 0]); // Set to all zeroes to let OS choose
    let dest_ip_addr: IpAddr = socket_addr.ip(); // Dark Side IP
    let dest_ip = match dest_ip_addr {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Only IPv4 is supported"),
    };
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

    let dest_ip_addr: IpAddr = dest_ip.into();

    // Send the packet using L3 channel, receive the response using UDP socket
    let raw_buf = send_and_receive_l3(&mut tx, ipv4_packet, &socket, dest_ip_addr, 5)
        .expect("To receive packet from Dark Side");

    // Extract and return port in response message
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
