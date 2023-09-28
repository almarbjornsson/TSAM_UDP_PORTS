// common.rs

use std::io;
use std::net::{SocketAddr, UdpSocket};

pub trait PortResponseHandler {
    fn get_port(&self) -> u16;

    fn open_socket(&self) -> io::Result<UdpSocket> {
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

    fn send_message(
        &self,
        socket: &UdpSocket,
        message: &[u8],
        addr: &SocketAddr,
    ) -> io::Result<usize> {
        const MAX_RETRIES: u32 = 5;
        let mut retries = 0;

        loop {
            match socket.send_to(message, addr) {
                Ok(result) => return Ok(result),
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

    fn receive_message(&self, socket: &UdpSocket) -> io::Result<[u8; 1024]> {
        let mut buf = [0; 1024];
        const MAX_RETRIES: usize = 10;
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
}
