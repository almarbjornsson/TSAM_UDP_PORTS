use crate::port_handler_utils::{open_socket, receive_message, send_and_receive, send_message};

use std::net::Ipv4Addr;
use std::net::SocketAddr;

pub fn handle_expstn(
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
    // Send knocks to E.X.P.S.T.N
    let socket = open_socket().unwrap();
    for port in ports_to_knock {
        let socket_addr = SocketAddr::from((Ipv4Addr::from([164, 92, 223, 132]), port));
        let mut knock = signature.to_vec();
        knock.extend_from_slice(secret_phrase.as_bytes());
        let _ = send_message(&socket, &knock, &socket_addr);
        let raw_buf = receive_message(&socket).unwrap();
        let response = String::from_utf8_lossy(&raw_buf).to_string();
        println!("Expstn Step 2: {}", response);
    }
}
