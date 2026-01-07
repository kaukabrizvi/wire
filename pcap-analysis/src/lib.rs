use brass_aphid_wire_messages::codec::DecodeValue;
use brass_aphid_wire_messages::protocol::{ClientHello, HandshakeMessageHeader, RecordHeader, ServerHello, extensions::{ClientHelloExtensionData, ExtensionType}};
use brass_aphid_wire_messages::iana::Protocol;
use etherparse::{SlicedPacket, TransportSlice};
use pcap_parser::{Capture, Linktype, PcapCapture};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

/// A struct to track a TCP connection
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TcpFlow {
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
pub struct TcpContent<'a> {
    seq_number: u32,
    data: &'a [u8],
}

/// TLS version derived from ClientHello
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

/// Normalized record per flow
#[derive(Debug, Clone)]
pub struct FlowObs {
    pub flow: TcpFlow,
    pub ch: ClientHello,
    pub sh: Option<ServerHello>,
    pub version: TlsVersion,
    pub supports: bool,
    pub attempts: bool,
    pub succeeds: bool,
    // Additional debug fields
    pub src_dst: String,
    pub session_id_len: usize,
    pub psk_identities: usize,
    pub has_psk_ke_modes: bool,
    pub has_server_hello: bool,
    pub ticket_len: Option<usize>,
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

/// Determine TLS version from ClientHello
fn tls_version_from_client_hello(ch: &ClientHello) -> TlsVersion {
    // Check for SupportedVersions extension (ext 43) first
    if let Some(extensions) = &ch.extensions {
        for ext in extensions.list() {
            if let ClientHelloExtensionData::SupportedVersions(sv) = &ext.extension_data {
                let versions = sv.versions.list();
                // If it includes TLS 1.3 (0x0304), it's TLS 1.3
                if versions.contains(&Protocol::TLSv1_3) {
                    return TlsVersion::Tls13;
                }
                // Otherwise take the highest listed version
                if versions.contains(&Protocol::TLSv1_2) {
                    return TlsVersion::Tls12;
                }
                if versions.contains(&Protocol::TLSv1_1) {
                    return TlsVersion::Tls11;
                }
                if versions.contains(&Protocol::TLSv1_0) {
                    return TlsVersion::Tls10;
                }
            }
        }
    }
    
    // Fall back to legacy client_version field
    match ch.protocol_version {
        Protocol::TLSv1_0 => TlsVersion::Tls10,
        Protocol::TLSv1_1 => TlsVersion::Tls11,
        Protocol::TLSv1_2 => TlsVersion::Tls12,
        Protocol::TLSv1_3 => TlsVersion::Tls13,
        _ => TlsVersion::Unknown,
    }
}

/// Get session ticket length from ClientHello
fn ticket_len(ch: &ClientHello) -> Option<usize> {
    ch.extensions.as_ref()?.list().iter().find_map(|ext| {
        match &ext.extension_data {
            ClientHelloExtensionData::SessionTicket(st) => Some(st.ticket.len()),
            _ => None,
        }
    })
}

/// Get number of PSK identities from ClientHello
fn psk_identities(ch: &ClientHello) -> usize {
    ch.extensions.as_ref()
        .and_then(|exts| exts.list().iter().find_map(|ext| {
            match &ext.extension_data {
                ClientHelloExtensionData::PreSharedKey(psk) => Some(psk.identities.list().len()),
                _ => None,
            }
        }))
        .unwrap_or(0)
}

/// Check if ClientHello has PSK key exchange modes
fn has_psk_ke_modes(ch: &ClientHello) -> bool {
    ch.extensions.as_ref()
        .map(|exts| exts.list().iter().any(|ext| {
            matches!(ext.extension_data, ClientHelloExtensionData::PskKeyExchangeModes(_))
        }))
        .unwrap_or(false)
}

/// Get session ID length from ClientHello
fn session_id_len(ch: &ClientHello) -> usize {
    ch.session_id.blob().len()
}

/// Check if ServerHello selected a PSK
fn server_selected_psk(sh: &ServerHello) -> bool {
    sh.extensions.list().iter().any(|ext| {
        ext.extension_type == ExtensionType::PreSharedKey
    })
}

/// Determine if client supports resumption for given TLS version
fn supports_resumption(ch: &ClientHello, version: TlsVersion) -> bool {
    match version {
        TlsVersion::Tls13 => has_psk_ke_modes(ch),
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 => {
            ticket_len(ch).is_some()
        } 
        TlsVersion::Unknown => false,
    }
}

/// Determine if client attempts resumption for given TLS version
fn attempts_resumption(ch: &ClientHello, version: TlsVersion) -> bool {
    match version {
        TlsVersion::Tls13 => psk_identities(ch) > 0,
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 => {
            // Attempts if there is a ticket with non-empty bytes
            matches!(ticket_len(ch), Some(n) if n > 0)
        }
        TlsVersion::Unknown => false,
    }
}

/// Determine if resumption succeeded for given TLS version
fn succeeds_resumption(ch: &ClientHello, sh: &ServerHello, version: TlsVersion) -> bool {
    match version {
        TlsVersion::Tls13 => server_selected_psk(sh),
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 => {
            // Success if client attempted via session ID and server echoed same session ID
            if session_id_len(ch) > 0 {
                ch.session_id.blob() == sh.session_id_echo.blob()
            } else {
                false
            }
        }
        TlsVersion::Unknown => false,
    }
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
    use pcap_parser::{parse_pcap, Linktype};

    use super::*;

    const PCAP_PATH: &str = "pcap/INSERT";
    fn try_client_hello(data: &[u8]) -> Option<ClientHello> {
        let (_record_header, data) = RecordHeader::decode_from(data).ok()?;
        let (_message_header, data) = HandshakeMessageHeader::decode_from(data).ok()?;
        ClientHello::decode_from_exact(data).ok()
    }
    fn try_server_hello(data: &[u8]) -> Option<ServerHello> {
        let (_record_header, data) = RecordHeader::decode_from(data).ok()?;
    let (_message_header, data) = HandshakeMessageHeader::decode_from(data).ok()?;
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

        // Build FlowObs from pairs
        let mut obs = Vec::new();
        for (flow, ch, sh) in pairs {
            let version = tls_version_from_client_hello(&ch);
            let supports = supports_resumption(&ch, version);
            let attempts = attempts_resumption(&ch, version);
            let succeeds = sh.as_ref().map(|sh| succeeds_resumption(&ch, sh, version)).unwrap_or(false);
            
            let flow_obs = FlowObs {
                src_dst: format!("{}→{}", flow.source, flow.destination),
                session_id_len: session_id_len(&ch),
                psk_identities: psk_identities(&ch),
                has_psk_ke_modes: has_psk_ke_modes(&ch),
                has_server_hello: sh.is_some(),
                ticket_len: ticket_len(&ch),
                flow,
                ch,
                sh,
                version,
                supports,
                attempts,
                succeeds,
            };
            
            obs.push(flow_obs);
        }

        // Count by version
        let mut counts_by_version: HashMap<TlsVersion, usize> = HashMap::new();
        let mut supports_by_version: HashMap<TlsVersion, usize> = HashMap::new();
        let mut attempts_by_version: HashMap<TlsVersion, usize> = HashMap::new();
        let mut succeeds_by_version: HashMap<TlsVersion, usize> = HashMap::new();
        let mut supports_no_attempt_by_version: HashMap<TlsVersion, usize> = HashMap::new();

        for flow_obs in &obs {
            *counts_by_version.entry(flow_obs.version).or_insert(0) += 1;
            
            if flow_obs.supports {
                *supports_by_version.entry(flow_obs.version).or_insert(0) += 1;
                
                if flow_obs.attempts {
                    *attempts_by_version.entry(flow_obs.version).or_insert(0) += 1;
                    
                    if flow_obs.succeeds {
                        *succeeds_by_version.entry(flow_obs.version).or_insert(0) += 1;
                    }
                } else {
                    *supports_no_attempt_by_version.entry(flow_obs.version).or_insert(0) += 1;
                }
            }
        }

        println!("\n=== TLS Resumption Analysis ===");
        println!("Total handshake pairs: {}", obs.len());
        
        println!("\n--- ClientHellos by Version ---");
        for version in [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13, TlsVersion::Unknown] {
            if let Some(count) = counts_by_version.get(&version) {
                println!("{:?}: {}", version, count);
            }
        }
        
        println!("\n--- Resumption Support by Version ---");
        for version in [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13, TlsVersion::Unknown] {
            let total = counts_by_version.get(&version).unwrap_or(&0);
            let supports = supports_by_version.get(&version).unwrap_or(&0);
            let no_support = total - supports;
            if *total > 0 {
                println!("{:?}: supports={}, no_support={}", version, supports, no_support);
            }
        }
        
        println!("\n--- Resumption Attempts by Version ---");
        for version in [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13, TlsVersion::Unknown] {
            let supports = supports_by_version.get(&version).unwrap_or(&0);
            let attempts = attempts_by_version.get(&version).unwrap_or(&0);
            let supports_no_attempt = supports_no_attempt_by_version.get(&version).unwrap_or(&0);
            if *supports > 0 {
                println!("{:?}: attempts={}, supports_no_attempt={}", version, attempts, supports_no_attempt);
            }
        }
        
        println!("\n--- Resumption Success by Version ---");
        for version in [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13, TlsVersion::Unknown] {
            let attempts = attempts_by_version.get(&version).unwrap_or(&0);
            let succeeds = succeeds_by_version.get(&version).unwrap_or(&0);
            if *attempts > 0 {
                let success_rate = (*succeeds as f64 / *attempts as f64) * 100.0;
                println!("{:?}: successes={}/{} ({:.1}%)", version, succeeds, attempts, success_rate);
            }
        }
    }
}
