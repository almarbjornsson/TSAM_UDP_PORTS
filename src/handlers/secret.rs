// secret.rs

use super::common::PortResponseHandler;
use std::convert::TryInto;
use std::io;
use std::net::{SocketAddr, UdpSocket}; // Importing the shared trait

/// Returns the byte reply and the secret port number
pub fn handle_response(group_number: u8, group_secret: u32) -> (Vec<u8>, u16) {
    // Handle the S.E.C.R.E.T response
    println!("Handling S.E.C.R.E.T response: {}", self.port);

    let socket = self.open_socket().unwrap();

    // socket addr
    let addr: SocketAddr = SocketAddr::from((super::IP_ADDR, self.port));

    // 1. Send me your group number as a single unsigned byte.
    let result = self.send_message(&socket, &[group_number], &addr);

    println!("S.E.C.R.E.T Step 1: {:?}", result);

    // 2. I'll reply with a 4-byte challenge (in network byte order) unique to your group.

    let raw_buffer = self.receive_message(&socket).unwrap();

    let challenge = u32::from_be_bytes(raw_buffer[0..4].try_into().unwrap());

    println!("S.E.C.R.E.T Step 2: {}", challenge);

    // 3. Sign this challenge using the XOR operation with your group's secret (get that from your TA).

    let signed_challenge = group_secret ^ challenge;
    println!("S.E.C.R.E.T Step 3: {}", signed_challenge);

    // 4. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signed challenge (in network byte order).

    let mut reply = Vec::new();

    reply.push(group_number);
    reply.extend_from_slice(&signed_challenge.to_be_bytes());

    let result = self.send_message(&socket, &reply, &addr);

    println!("S.E.C.R.E.T Step 4: {:?}", result);

    // 5. If your signature is correct, I'll grant you access to the port. Good luck!

    let raw_buffer = self.receive_message(&socket).unwrap();
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

    (reply, secret_port)
}
