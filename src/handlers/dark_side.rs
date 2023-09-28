// pub struct DarkSideHandler {
//     pub port: u16,
// }
// const IPV4_HEADER_LEN: usize = 20;
// const UDP_HEADER_LEN: usize = 8;

// impl DarkSideHandler {
//     pub fn send_evil_packet(
//         &self,
//         src_ip: Ipv4Addr,
//         dest_ip: Ipv4Addr,
//         dest_port: u16,
//         payload: &[u8],
//     ) -> Result<(), std::io::Error> {
//         // Calculate the total packet size
//         let packet_size = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
//         let mut packet = vec![0u8; packet_size];

//         // Create a mutable IPv4 packet
//         let mut ipv4_packet = MutableIpv4Packet::new(&mut packet[..IPV4_HEADER_LEN]).unwrap();

//         // Set the IPv4 fields
//         ipv4_packet.set_version(4);
//         ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8 / 4); // Header length is in words
//         ipv4_packet.set_total_length(packet_size as u16);
//         ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
//         ipv4_packet.set_source(src_ip);
//         ipv4_packet.set_destination(dest_ip);

//         // Set the "evil bit"
//         let mut flags = ipv4_packet.get_flags();
//         flags |= 0b100;
//         ipv4_packet.set_flags(flags);

//         // Create a mutable UDP packet
//         let mut udp_packet = MutableUdpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();

//         // Set the UDP fields
//         udp_packet.set_source(0); // Use a random source port or a specific one if needed
//         udp_packet.set_destination(dest_port);
//         udp_packet.set_length((UDP_HEADER_LEN + payload.len()) as u16);
//         udp_packet.set_payload(payload);

//         // Open a transport channel to send the packet
//         let (mut tx, _) = transport_channel(
//             packet_size,
//             TransportChannelType::Layer3(IpNextHeaderProtocols::Udp),
//         )?;
//         let dest = SocketAddrV4::new(dest_ip, dest_port);
//         let ip_addr: IpAddr = dest.ip().clone().into();
//         tx.send_to(&ipv4_packet, ip_addr)?;

//         Ok(())
//     }

//     pub fn handle_response(&self, dest_port: u16) -> Vec<u8> {
//         // Handle the dark side response
//         println!("Handling dark side response: {}", self.port);

//         // Send the evil packet 130.208.29.23
//         let source_ip = Ipv4Addr::new(130, 208, 29, 23);
//         let dest_ip = Ipv4Addr::new(IP_ADDR[0], IP_ADDR[1], IP_ADDR[2], IP_ADDR[3]);
//         let payload = b"Hello, world!";
//         self.send_evil_packet(source_ip, dest_ip, dest_port, payload)
//             .expect("Failed to send evil packet");

//         let response = Vec::new();
//         response
//     }
// }

// impl PortResponseHandler for DarkSideHandler {
//     fn get_port(&self) -> u16 {
//         self.port
//     }
// }
