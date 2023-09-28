// main.rs
use std::net::{IpAddr, SocketAddr};
mod port_handler_utils;

use crate::port_handler_utils::get_port_responses;
mod udp_scanner;

mod handlers {
    pub mod dark_side;
    pub mod exptn;
    pub mod secret;
    pub mod signature;
}

use handlers::dark_side::handle_dark_side;
use handlers::exptn::handle_expstn;
use handlers::secret::handle_secret;
use handlers::signature::handle_signature;

extern crate pnet;

#[derive(PartialEq)]
enum HandlerType {
    DarkSide,
    Expstn,
    Secret,
    Signature,
}

fn main() {
    const GROUP_NUMBER: u8 = 32;
    const GROUP_SECRET: u32 = 0xfe8d9ecf;
    const IP_ADDR: [u8; 4] = [164, 92, 223, 132];

    // // START OF SCANNER
    let args: Vec<String> = std::env::args().collect();
    let (ip_address, low_port, high_port) = match udp_scanner::parse_arguments(args) {
        Some(args) => args,
        None => return,
    };

    println!("Scanning {} from {} to {}", ip_address, low_port, high_port);

    let open_ports = udp_scanner::find_open_ports(&ip_address, low_port, high_port);
    println!("Open ports: {:?}", open_ports);

    // // END OF SCANNER

    // let open_ports = vec![4001, 4010, 4021, 4052]; // Replace with scanner for dynamic ports. This is just for faster testing.

    // START OF ASSOCIATING PORTS WITH HANDLERS

    // At this stage we have a list of open ports
    // Now we have to find out which port is associated with which handler
    let mut port_and_associated_handler: Vec<(u16, HandlerType)> = Vec::new();

    let ip_addr = IpAddr::from(IP_ADDR);
    let port_reponses = get_port_responses(ip_addr, open_ports.as_slice());

    for (port, response) in port_reponses {
        // println!("Port: {}, Response: {}", port, response);
        match associate_port_with_handler(&response, port) {
            Ok(handler) => {
                port_and_associated_handler.push(handler);
            }
            Err(e) => {
                println!("Error getting handler for response: {}", e);
            }
        }
    }
    // END OF ASSOCIATING PORTS WITH HANDLERS

    // START OF EXECUTING HANDLERS

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

    // END OF EXECUTING HANDLERS
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
