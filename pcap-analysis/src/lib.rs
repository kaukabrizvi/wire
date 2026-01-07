use brass_aphid_wire_messages::codec::DecodeValue;
use brass_aphid_wire_messages::protocol::{ClientHello, HandshakeMessageHeader, RecordHeader, ServerHello, extensions::{Extension, ClientHelloExtensionData, ExtensionType}};
use etherparse::{SlicedPacket, TransportSlice};
use pcap_parser::{Capture, Linktype, PcapCapture};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

/// A struct to track a TCP connection
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TcpFlow {
    source: SocketAddr,
    destination: SocketAddr,
}

impl TcpFlow {
    fn reversed(&self) -> TcpFlow {
        TcpFlow {
            source: self.destination,
            destination: self.source,
        }
    }
}

/// A struct to store TCP packet data
///
/// This generic lifetime parameter will generally be the lifetime of the
/// PcapCapture object which owns the actual packet content.
struct TcpContent<'a> {
    seq_number: u32,
    data: &'a [u8],
}

pub fn reassemble_tcp_streams<'a>(
    capture: PcapCapture<'a>,
) -> HashMap<TcpFlow, Vec<TcpContent<'a>>> {
    // LINUX_SLL is the type of header format that is used in the pcap.
    assert_eq!(capture.get_datalink(), Linktype::LINUX_SLL);

    let _total_blocks = capture.blocks.len();

    let header_parsed = capture
        .blocks
        .iter()
        .map(|block| SlicedPacket::from_linux_sll(block.data).unwrap())
        .filter(|block| block.net.is_some()) // should be IP packets
        .filter(|block| matches!(block.transport, Some(TransportSlice::Tcp(_)))) // should be TCP
        .map(|block| {
            let network_data = block.net.unwrap();
            let (destination_ip, source_ip) = {
                let ipv4 = network_data.ipv4_ref().map(|ipv4_packet| {
                    let header = ipv4_packet.header();
                    let destination = IpAddr::V4(header.destination_addr());
                    let source = IpAddr::V4(header.source_addr());
                    (destination, source)
                });

                let ipv6 = network_data.ipv6_ref().map(|ipv4_packet| {
                    let header = ipv4_packet.header();
                    let destination = IpAddr::V6(header.destination_addr());
                    let source = IpAddr::V6(header.source_addr());
                    (destination, source)
                });

                match (ipv4, ipv6) {
                    (None, None) => panic!("network packet type was not IP"),
                    (None, Some(routing)) => routing,
                    (Some(routing), None) => routing,
                    (Some(_), Some(_)) => unreachable!("packet can not be both ipv4 and ipv6"),
                }
            };

            let tcp_data = match block.transport.unwrap() {
                TransportSlice::Tcp(tcp_slice) => tcp_slice,
                _ => {
                    unreachable!("we already filtered on this");
                }
            };
            let source_port = tcp_data.source_port();
            let destination_port = tcp_data.destination_port();

            let destination: SocketAddr = (destination_ip, destination_port).into();
            let source: SocketAddr = (source_ip, source_port).into();
            let flow = TcpFlow {
                destination,
                source,
            };

            let content = TcpContent {
                seq_number: tcp_data.sequence_number(),
                data: tcp_data.payload(),
            };

            (flow, content)
        });
    
    let mut connections: HashMap<TcpFlow, Vec<TcpContent>> = HashMap::new();
    for (flow, content) in header_parsed {
        connections.entry(flow).or_default().push(content);
    }

    for contents in connections.values_mut() {
        contents.sort_by_key(|content| content.seq_number);
    }

    println!("{} TCP flows reconstructed", connections.len());

    let double_counted: usize = connections
        .values()
        .filter(|tcp_contents| {
            let unique_packet_numbers: HashSet<u32> = tcp_contents
                .iter()
                .map(|content| content.seq_number)
                .collect();
            let double_counted = tcp_contents.len() != unique_packet_numbers.len();
            double_counted
        })
        .count();
    println!("double counter: {double_counted}");

    // todo: double check that if the seq number 0 (1?) is the same, then the contents
    // should also be the same.

    // actually, I don't think that's true

    // also I think we _only_ need sequence number one (for the initial stuff).
    // actually, I think we also want to look at the server hellos?
    // although I don't think that the PSK is gonna be visible in that.

    connections
}

// /// Given the path to some pcap, this will read in the pcap file and reassemble all
// /// of the various TCP streams that were presented.
// ///
// /// Returns a vector of tuples, where each tuple contains:
// /// - The destination IP address
// /// - The reassembled TCP data stream as a vector of bytes
// pub fn reassemble_tcp_streams(pcap_path: &str) {
//     // Read the pcap file
//     let pcap_data = std::fs::read(pcap_path).unwrap();

//     // Parse the pcap file
//     let (remaining, capture) = parse_pcap(&pcap_data).unwrap();
//     assert!(remaining.is_empty());

//     // Track TCP connections and their packets
//     let mut connections: HashMap<TcpFlow, Vec<TcpContent>> = HashMap::new();

//     // filter down to IP packets
//     // filter down to TCP packets

//     // Process each packet in the capture
//     for block in capture.blocks.iter() {
//         // Extract the packet data
//         let packet_data = block.data;
//         let sliced_packet = SlicedPacket::from_linux_sll(block.data).unwrap();

//         // ip address information is contained in the network header (IP)
//         let network_data = sliced_packet.net.unwrap();
//         assert!(network_data.is_ip());
//         let (destination_ip, source_ip) = {
//             let ipv4 = network_data.ipv4_ref().map(|ipv4_packet| {
//                 let header = ipv4_packet.header();
//                 let destination = IpAddr::V4(header.destination_addr());
//                 let source = IpAddr::V4(header.source_addr());
//                 (destination, source)
//             });

//             let ipv6 = network_data.ipv6_ref().map(|ipv4_packet| {
//                 let header = ipv4_packet.header();
//                 let destination = IpAddr::V6(header.destination_addr());
//                 let source = IpAddr::V6(header.source_addr());
//                 (destination, source)
//             });

//             match (ipv4, ipv6) {
//                 (None, None) => panic!("network packet type was not IP"),
//                 (None, Some(routing)) => routing,
//                 (Some(routing), None) => routing,
//                 (Some(_), Some(_)) => unreachable!("packet can not be both ipv4 and ipv6"),
//             }
//         };

//         // port information is contained in the transport header (TCP)
//         let tcp_data = match sliced_packet.transport.unwrap() {
//             TransportSlice::Tcp(tcp_slice) => tcp_slice,
//             _ => {
//                 println!("not a recognized packet type, skipping");
//                 continue;
//             }
//         };
//         let source_port = tcp_data.source_port();
//         let destination_port = tcp_data.destination_port();

//         let destination: SocketAddr = (destination_ip, destination_port).into();
//         let source: SocketAddr = (source_ip, source_port).into();
//         let flow = TcpFlow {
//             destination,
//             source,
//         };

//         let content = TcpContent {
//             seq_number: tcp_data.sequence_number(),
//             data: tcp_data.payload().to_vec(),
//         };

//         // TODO: a TCP Flow may be reused after some duration.
//         connections.entry(flow).or_default().push(content);
//     }

//     println!("observed {} flows", connections.len());
// }


#[cfg(test)]
mod tests {
    use brass_aphid_wire_messages::{codec::EncodeValue, protocol::extensions::ClientHelloExtensionData};
    use pcap_parser::{parse_pcap, Linktype};

    use super::*;

    const PCAP_PATH: &str = "pcap/jlbrelay_traffic_capture_30_min.pcap";
    fn try_client_hello(data: &[u8]) -> Option<ClientHello> {
        let (_record_header, data) = RecordHeader::decode_from(data).ok()?;
        let (_message_header, data) = HandshakeMessageHeader::decode_from(data).ok()?;
        ClientHello::decode_from_exact(data).ok()
    }
    fn try_server_hello(data: &[u8]) -> Option<ServerHello> {
    let (_record_header, data) = RecordHeader::decode_from(data).ok()?;
    let (message_header, data) = HandshakeMessageHeader::decode_from(data).ok()?;
    ServerHello::decode_from_exact(data).ok()
}

    #[test]
    fn read_pcap() {
        let pcap = std::fs::read(PCAP_PATH).unwrap();
        let (_remaining, captures) = parse_pcap(&pcap).unwrap();
        println!("header: {:?}", captures.header);
        let link = captures.get_datalink();
        println!("link type: {link:?}");
        assert_eq!(link, Linktype::LINUX_SLL);
        let _frames = captures.blocks.iter().next().unwrap();
    }

    #[test]
    fn reassemble() {
        use std::collections::HashMap;

        let pcap = std::fs::read(PCAP_PATH).unwrap();
        let (_remaining, captures) = parse_pcap(&pcap).unwrap();
        println!("header: {:?}", captures.header);

        let streams = reassemble_tcp_streams(captures);

        let mut pairs = Vec::new();

        for (flow, contents) in &streams {
            let ch = contents
                .iter()
                .find_map(|c| try_client_hello(c.data))
                .map(|ch| (flow.clone(), ch));

            let Some((flow, ch)) = ch else { continue };

            let sh = streams
                .get(&flow.reversed())
                .and_then(|rev_contents| rev_contents.iter().find_map(|c| try_server_hello(c.data)));

            pairs.push((flow, ch, sh));
        }

        // Create distinct client hellos from pairs
        let mut distinct: HashMap<Vec<u8>, ClientHello> = HashMap::new();
        for (_flow, ch, _sh) in &pairs {
                let bytes = ch.encode_to_vec().unwrap();
                distinct.entry(bytes).or_insert(ch.clone());
            }

            let mut no_resumption_support = 0usize;
            let mut resumption_attempted = 0usize;
            let mut resumption_supported_but_not_attempted = 0usize;
            let mut successful_handshakes = 0usize;
            let mut missing_server_hello = 0usize;

            for (_flow, ch, sh_opt) in &pairs {
                let Some(sh) = sh_opt else {
                    missing_server_hello += 1;
                    continue;
                };

                // --- Signals from ClientHello ---
                let ticket_len: Option<usize> = ch.extensions.as_ref().and_then(|exts| {
                    exts.list().iter().find_map(|ext| match &ext.extension_data {
                        ClientHelloExtensionData::SessionTicket(st) => Some(st.ticket.len()),
                        _ => None,
                    })
                });

                let psk_identities = ch.extensions.as_ref().and_then(|exts| {
                    exts.list().iter().find_map(|ext| match &ext.extension_data {
                        ClientHelloExtensionData::PreSharedKey(psk) => Some(psk.identities.list().len()),
                        _ => None,
                    })
                }).unwrap_or(0);

                let has_psk_ke_modes = ch.extensions.as_ref().map(|exts| {
                    exts.list().iter().any(|ext| matches!(
                        ext.extension_data,
                        ClientHelloExtensionData::PskKeyExchangeModes(_)
                    ))
                }).unwrap_or(false);

                // Support = either ticket support OR PSK support (NOT both)
                let supports_resumption = ticket_len.is_some() || has_psk_ke_modes;

                // Attempt = actual ticket bytes OR actual PSK identities
                let attempted_resumption =
                    matches!(ticket_len, Some(n) if n > 0) || psk_identities > 0;

                // --- Success from ServerHello ---
                let server_selected_psk = sh.extensions.list().iter().any(|ext| {
                    ext.extension_type
                        == brass_aphid_wire_messages::protocol::extensions::ExtensionType::PreSharedKey
                });

                // IMPORTANT: session_id_echo matching is NOT resumption in TLS 1.3.
                // Only use this if you *know* it's TLS 1.2. If you don't know, drop it for now.
                let session_ids_match_tls12 = false; // safest: disable until you add TLS version gating

                let successful_resumption =
                    server_selected_psk || session_ids_match_tls12;

                // --- Categorize ---
                if !supports_resumption {
                    no_resumption_support += 1;
                } else if !attempted_resumption {
                    resumption_supported_but_not_attempted += 1;
                } else {
                    resumption_attempted += 1;
                }

                if successful_resumption {
                    successful_handshakes += 1;
                }
            }

        println!("handshake_pairs: {}", pairs.len());
        println!("missing_server_hello: {missing_server_hello}");
        println!("no_resumption_support: {no_resumption_support}");
        println!("resumption_attempted: {resumption_attempted}");
        println!("resumption_supported_but_not_attempted: {resumption_supported_but_not_attempted}");
        println!("successful_handshakes: {successful_handshakes}");
    }
}
