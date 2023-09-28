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

struct SharedState {
    signature: Vec<u8>,
    secret_phrase: String,
    secret_ports: Vec<u16>,
    ip_addr: [u8; 4],
    group_number: u8,
    group_secret: u32,
    port_and_associated_handler: Vec<(u16, HandlerType)>,
}

impl SharedState {
    fn execute_secret(&mut self) {
        self.execute_handler(HandlerType::Secret);
    }

    fn execute_dark_side(&mut self) {
        self.execute_handler(HandlerType::DarkSide);
    }

    fn execute_signature(&mut self) {
        self.execute_handler(HandlerType::Signature);
    }

    fn execute_expstn(&mut self) {
        self.execute_handler(HandlerType::Expstn);
    }

    fn execute_handler(&mut self, handler_type: HandlerType) {
        if let Some(port) = self
            .port_and_associated_handler
            .iter()
            .find(|(_, h_type)| *h_type == handler_type)
            .map(|(port, _)| *port)
        {
            let socket_addr = SocketAddr::from((self.ip_addr, port));
            let sig_slice = self.signature[0..4].try_into().unwrap();
            match handler_type {
                HandlerType::Secret => {
                    let (sig, port) =
                        handle_secret(socket_addr, self.group_number, self.group_secret);
                    self.signature = sig;
                    self.secret_ports.push(port);
                }
                HandlerType::DarkSide => {
                    let secret_port = handle_dark_side(socket_addr, sig_slice);
                    self.secret_ports.push(secret_port);
                }
                HandlerType::Signature => {
                    self.secret_phrase = handle_signature(socket_addr, sig_slice);
                }
                HandlerType::Expstn => {
                    handle_expstn(
                        socket_addr,
                        self.secret_ports.clone(),
                        self.secret_phrase.clone(),
                        sig_slice,
                    );
                }
            }
        }
    }
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

    let ip_addr = IpAddr::from(IP_ADDR);
    // First we get the responses from each port
    let port_reponses = get_port_responses(ip_addr, open_ports.as_slice());
    // Then we associate the ports with the correct handler, based on the response
    let port_and_associated_handler = associate_ports_with_handlers(port_reponses);
    // END OF ASSOCIATING PORTS WITH HANDLERS

    // START OF EXECUTING HANDLERS
    let mut shared_state = SharedState {
        signature: vec![0; 4],
        secret_phrase: String::new(),
        secret_ports: Vec::new(),
        ip_addr: IP_ADDR,
        group_number: GROUP_NUMBER,
        group_secret: GROUP_SECRET,
        port_and_associated_handler,
    };

    shared_state.execute_secret();
    shared_state.execute_dark_side();
    shared_state.execute_signature();
    shared_state.execute_expstn();

    // END OF EXECUTING HANDLERS
}

// Iterate over all the ports and their responses and associate them with the correct handler
// Returns a vector of tuples containing the port and the associated handler
fn associate_ports_with_handlers(port_reponses: Vec<(u16, String)>) -> Vec<(u16, HandlerType)> {
    let mut port_and_associated_handler: Vec<(u16, HandlerType)> = Vec::new();

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
    port_and_associated_handler
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
