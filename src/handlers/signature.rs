// pub struct SignatureHandler {
//     pub port: u16,
// }

// impl SignatureHandler {
//     fn handle_response(&self, _message: &[u8]) -> Vec<u8> {
//         // Handle the signature response
//         println!("Handling signature response: {}", self.port);

//         // &[u8] is a slice of bytes,
//         let response = Vec::new();

//         response
//     }
// }

// impl PortResponseHandler for SignatureHandler {
//     // Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order).
//     fn get_port(&self) -> u16 {
//         self.port
//     }
// }
