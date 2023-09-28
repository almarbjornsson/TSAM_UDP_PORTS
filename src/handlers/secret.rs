use crate::port_handler_utils::{open_socket, send_and_receive};
use std::net::SocketAddr;

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
