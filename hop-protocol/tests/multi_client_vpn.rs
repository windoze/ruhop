//! Multi-client VPN integration test
//!
//! This test simulates a complete VPN scenario with:
//! - Multiple clients connecting to a single server
//! - Large request/response messages requiring fragmentation
//! - Full protocol flow: encapsulation → fragmentation → transmission → reassembly → decapsulation
//! - Bidirectional communication with payload verification

use std::collections::HashMap;
use std::sync::Arc;

use hop_protocol::transport::mock::{IpAddr, IpPacketBuilder, IpPacketInfo, MockTunDevice};
use hop_protocol::transport::TunTransport;
use hop_protocol::{fragment_packet, Cipher, FragmentAssembler, Packet, Session, HOP_HDR_LEN};

/// Maximum fragment payload size (small to force fragmentation)
const MAX_FRAGMENT_SIZE: usize = HOP_HDR_LEN + 100;

/// Client state containing session and crypto info
struct VpnClient {
    id: u32,
    session: Session,
    cipher: Cipher,
    fragment_assembler: FragmentAssembler,
    tun: Arc<MockTunDevice>,
    assigned_ip: [u8; 4],
}

impl VpnClient {
    fn new(id: u32, key: &[u8], assigned_ip: [u8; 4]) -> Self {
        let mut session = Session::new_client();
        // Fast-forward to Working state for this test
        session.start_handshake().unwrap();
        session.complete_handshake(assigned_ip, 24).unwrap();

        Self {
            id,
            session,
            cipher: Cipher::new(key),
            fragment_assembler: FragmentAssembler::new(),
            tun: Arc::new(MockTunDevice::new(&format!("tun-client-{}", id), 65535)),
            assigned_ip,
        }
    }

    fn session_id(&self) -> u32 {
        self.session.id.value()
    }

    /// Create a large request packet that requires fragmentation
    fn create_request(&self, request_data: &[u8]) -> Vec<u8> {
        IpPacketBuilder::ipv4()
            .src_v4(
                self.assigned_ip[0],
                self.assigned_ip[1],
                self.assigned_ip[2],
                self.assigned_ip[3],
            )
            .dst_v4(10, 0, 0, 1) // Server's TUN IP
            .with_udp(
                10000 + self.id as u16, // Client-specific source port
                8080,                   // Server application port
                request_data,
            )
            .build()
    }

    /// Encapsulate and fragment an IP packet for transmission
    fn encapsulate_and_fragment(&mut self, ip_packet: &[u8]) -> Vec<Vec<u8>> {
        let seq = self.session.next_sequence();
        let hop_packet = Packet::data(seq, self.session_id(), ip_packet.to_vec());

        // Fragment the packet
        let fragments = fragment_packet(&hop_packet, MAX_FRAGMENT_SIZE)
            .expect("Fragmentation should succeed");

        // Encrypt each fragment
        fragments
            .iter()
            .map(|frag| {
                self.cipher
                    .encrypt(frag, 50)
                    .expect("Encryption should succeed")
            })
            .collect()
    }

    /// Process received encrypted fragments and return reassembled IP packet if complete
    fn receive_and_reassemble(&mut self, encrypted_data: &[u8]) -> Option<Vec<u8>> {
        let decrypted = self
            .cipher
            .decrypt(encrypted_data)
            .expect("Decryption should succeed");

        if let Ok(Some(reassembled)) = self.fragment_assembler.process(decrypted) {
            Some(reassembled.payload)
        } else {
            None
        }
    }
}

/// Server state managing multiple client sessions
struct VpnServer {
    cipher: Cipher,
    /// Fragment assemblers per session ID
    fragment_assemblers: HashMap<u32, FragmentAssembler>,
    /// Session tracking (session_id -> client info)
    sessions: HashMap<u32, ServerClientInfo>,
    /// Server's TUN device (simulates the protected network)
    tun: Arc<MockTunDevice>,
    /// Sequence counters per session
    sequences: HashMap<u32, u32>,
}

struct ServerClientInfo {
    #[allow(dead_code)]
    assigned_ip: [u8; 4],
}

impl VpnServer {
    fn new(key: &[u8]) -> Self {
        Self {
            cipher: Cipher::new(key),
            fragment_assemblers: HashMap::new(),
            sessions: HashMap::new(),
            tun: Arc::new(MockTunDevice::new("tun-server", 65535)),
            sequences: HashMap::new(),
        }
    }

    /// Register a client session
    fn register_client(&mut self, session_id: u32, assigned_ip: [u8; 4]) {
        self.sessions
            .insert(session_id, ServerClientInfo { assigned_ip });
        self.fragment_assemblers
            .insert(session_id, FragmentAssembler::new());
        self.sequences.insert(session_id, 0);
    }

    /// Process received encrypted fragment from a client
    /// Returns (session_id, reassembled_ip_packet) if reassembly is complete
    fn receive_fragment(&mut self, encrypted_data: &[u8]) -> Option<(u32, Vec<u8>)> {
        let decrypted = self
            .cipher
            .decrypt(encrypted_data)
            .expect("Decryption should succeed");

        let session_id = decrypted.header.sid;

        let assembler = self
            .fragment_assemblers
            .get_mut(&session_id)
            .expect("Session should be registered");

        if let Ok(Some(reassembled)) = assembler.process(decrypted) {
            Some((session_id, reassembled.payload))
        } else {
            None
        }
    }

    /// Encapsulate and fragment an IP packet for sending to a specific client
    fn encapsulate_for_client(&mut self, session_id: u32, ip_packet: &[u8]) -> Vec<Vec<u8>> {
        let seq = self.sequences.get_mut(&session_id).unwrap();
        let current_seq = *seq;
        *seq += 1;

        let hop_packet = Packet::data(current_seq, session_id, ip_packet.to_vec());

        let fragments =
            fragment_packet(&hop_packet, MAX_FRAGMENT_SIZE).expect("Fragmentation should succeed");

        fragments
            .iter()
            .map(|frag| {
                self.cipher
                    .encrypt(frag, 50)
                    .expect("Encryption should succeed")
            })
            .collect()
    }

}

/// Application-level request/response processor
/// Simulates an application running behind the VPN server
struct ApplicationSimulator;

impl ApplicationSimulator {
    /// Process a request IP packet and generate a response
    /// The response is based on the request content and is larger to ensure fragmentation
    fn process_request(request_ip_packet: &[u8]) -> Option<Vec<u8>> {
        let ip_info = IpPacketInfo::parse(request_ip_packet)?;

        if !ip_info.is_udp() {
            return None;
        }

        let udp_info = ip_info.parse_udp()?;

        // Extract request data
        let request_data = &udp_info.data;

        // Generate a response that's larger than the request
        // This simulates a server responding with more data
        let mut response_data = Vec::new();
        response_data.extend_from_slice(b"RESPONSE:");
        response_data.extend_from_slice(request_data);
        response_data.extend_from_slice(b":DATA_BLOCK_");

        // Add extra data to ensure fragmentation (repeat the original data multiple times)
        for i in 0..5 {
            response_data.extend_from_slice(format!("|BLOCK_{}:", i).as_bytes());
            response_data.extend_from_slice(request_data);
        }
        response_data.extend_from_slice(b":END");

        // Build response IP packet (swap src/dst)
        let (src_ip, dst_ip) = match (&ip_info.src_addr, &ip_info.dst_addr) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => (dst.octets(), src.octets()),
            _ => return None,
        };

        let response_packet = IpPacketBuilder::ipv4()
            .src_v4(src_ip[0], src_ip[1], src_ip[2], src_ip[3])
            .dst_v4(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3])
            .with_udp(
                udp_info.dst_port, // Swap ports
                udp_info.src_port,
                &response_data,
            )
            .build();

        Some(response_packet)
    }
}

/// Simulated network channel for client-server communication
struct NetworkChannel {
    /// Packets in transit: destination -> queue of packets
    packets: HashMap<String, Vec<Vec<u8>>>,
}

impl NetworkChannel {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    fn send(&mut self, destination: &str, packet: Vec<u8>) {
        self.packets
            .entry(destination.to_string())
            .or_default()
            .push(packet);
    }

    fn receive(&mut self, destination: &str) -> Option<Vec<u8>> {
        self.packets
            .get_mut(destination)
            .and_then(|q| if q.is_empty() { None } else { Some(q.remove(0)) })
    }

    fn receive_all(&mut self, destination: &str) -> Vec<Vec<u8>> {
        self.packets.remove(destination).unwrap_or_default()
    }

}

/// Main test: Multi-client VPN with fragmented request/response
#[tokio::test]
async fn test_multi_client_vpn_with_fragmentation() {
    let shared_key = b"multi-client-vpn-test-key-2024";

    // Create server
    let mut server = VpnServer::new(shared_key);

    // Create clients with unique IPs
    let mut clients = vec![
        VpnClient::new(1, shared_key, [10, 0, 0, 101]),
        VpnClient::new(2, shared_key, [10, 0, 0, 102]),
        VpnClient::new(3, shared_key, [10, 0, 0, 103]),
    ];

    // Register all clients with server
    for client in &clients {
        server.register_client(client.session_id(), client.assigned_ip);
        println!(
            "Registered client {} (session: 0x{:08X}, IP: {}.{}.{}.{})",
            client.id,
            client.session_id(),
            client.assigned_ip[0],
            client.assigned_ip[1],
            client.assigned_ip[2],
            client.assigned_ip[3]
        );
    }

    // Create network channel
    let mut network = NetworkChannel::new();

    // =====================================================================
    // Phase 1: Clients send requests to server
    // =====================================================================
    println!("\n=== Phase 1: Clients sending requests ===");

    // Each client creates a unique large request
    let client_requests: Vec<Vec<u8>> = clients
        .iter()
        .map(|c| {
            // Create request data larger than fragment size
            let mut request = format!("CLIENT_{}_REQUEST:", c.id).into_bytes();
            // Add enough data to require fragmentation
            for i in 0..20 {
                request.extend_from_slice(
                    format!("|DATA_SEGMENT_{}:PAYLOAD_FOR_CLIENT_{}", i, c.id).as_bytes(),
                );
            }
            request.extend_from_slice(b":REQUEST_END");
            request
        })
        .collect();

    // Store original requests for later verification
    let mut original_requests: HashMap<u32, Vec<u8>> = HashMap::new();

    for (client, request_data) in clients.iter_mut().zip(client_requests.iter()) {
        // Create IP packet with request
        let request_ip = client.create_request(request_data);
        println!(
            "Client {} creating request: {} bytes IP packet, {} bytes payload",
            client.id,
            request_ip.len(),
            request_data.len()
        );

        // Store for verification
        original_requests.insert(client.session_id(), request_ip.clone());

        // Inject into client TUN (simulates application sending data)
        client.tun.inject_recv_packet(request_ip.clone());

        // Client reads from TUN
        let mut buf = vec![0u8; 2000];
        let n = client.tun.recv(&mut buf).await.unwrap();

        // Encapsulate and fragment
        let fragments = client.encapsulate_and_fragment(&buf[..n]);
        println!(
            "Client {} fragmented into {} packets",
            client.id,
            fragments.len()
        );

        assert!(
            fragments.len() > 1,
            "Request should require fragmentation (got {} fragments)",
            fragments.len()
        );

        // Send all fragments to server
        for frag in fragments {
            network.send("server", frag);
        }
    }

    // =====================================================================
    // Phase 2: Server receives and processes requests
    // =====================================================================
    println!("\n=== Phase 2: Server processing requests ===");

    let mut reassembled_requests: Vec<(u32, Vec<u8>)> = Vec::new();

    // Server receives all fragments
    while let Some(fragment) = network.receive("server") {
        if let Some((session_id, ip_packet)) = server.receive_fragment(&fragment) {
            println!(
                "Server reassembled request from session 0x{:08X}: {} bytes",
                session_id,
                ip_packet.len()
            );
            reassembled_requests.push((session_id, ip_packet));
        }
    }

    // Verify all requests were received
    assert_eq!(
        reassembled_requests.len(),
        clients.len(),
        "Should receive request from each client"
    );

    // Verify request integrity
    for (session_id, ip_packet) in &reassembled_requests {
        let original = original_requests
            .get(session_id)
            .expect("Should have original request");
        assert_eq!(
            ip_packet, original,
            "Reassembled request should match original"
        );

        // Verify IP packet structure
        let ip_info = IpPacketInfo::parse(ip_packet).expect("Should be valid IP packet");
        assert!(ip_info.is_udp(), "Should be UDP packet");

        let udp_info = ip_info.parse_udp().unwrap();
        assert_eq!(udp_info.dst_port, 8080, "Should target application port");

        println!(
            "Verified request from session 0x{:08X}: UDP {}:{} -> {}:{}",
            session_id, ip_info.src_addr, udp_info.src_port, ip_info.dst_addr, udp_info.dst_port
        );
    }

    // =====================================================================
    // Phase 3: Server TUN receives packets and application generates responses
    // =====================================================================
    println!("\n=== Phase 3: Application processing and response generation ===");

    let mut responses: HashMap<u32, Vec<u8>> = HashMap::new();

    for (session_id, ip_packet) in &reassembled_requests {
        // Send to server TUN (simulates packet going to protected network)
        server.tun.send(ip_packet).await.unwrap();

        // Application processes and generates response
        let response_ip = ApplicationSimulator::process_request(ip_packet)
            .expect("Should generate response");

        println!(
            "Application generated response for session 0x{:08X}: {} bytes",
            session_id,
            response_ip.len()
        );

        responses.insert(*session_id, response_ip);
    }

    // Verify server TUN captured all packets
    let server_capture = server.tun.capture();
    assert_eq!(
        server_capture.sent_count(),
        clients.len(),
        "Server TUN should have received all requests"
    );

    // =====================================================================
    // Phase 4: Server sends responses back to clients
    // =====================================================================
    println!("\n=== Phase 4: Server sending responses ===");

    let mut original_responses: HashMap<u32, Vec<u8>> = HashMap::new();

    for (session_id, response_ip) in &responses {
        // Store for verification
        original_responses.insert(*session_id, response_ip.clone());

        // Find client's destination based on IP
        let ip_info = IpPacketInfo::parse(response_ip).unwrap();
        let client_id = match &ip_info.dst_addr {
            IpAddr::V4(addr) => addr.octets()[3] - 100, // 101 -> 1, 102 -> 2, etc.
            _ => panic!("Expected IPv4"),
        };

        // Encapsulate and fragment response
        let fragments = server.encapsulate_for_client(*session_id, response_ip);
        println!(
            "Server sending {} fragments to client {}",
            fragments.len(),
            client_id
        );

        assert!(
            fragments.len() > 1,
            "Response should require fragmentation (got {} fragments)",
            fragments.len()
        );

        // Send to client
        let client_dest = format!("client_{}", client_id);
        for frag in fragments {
            network.send(&client_dest, frag);
        }
    }

    // =====================================================================
    // Phase 5: Clients receive and verify responses
    // =====================================================================
    println!("\n=== Phase 5: Clients receiving and verifying responses ===");

    for client in &mut clients {
        let client_dest = format!("client_{}", client.id);
        let fragments = network.receive_all(&client_dest);

        println!(
            "Client {} receiving {} fragments",
            client.id,
            fragments.len()
        );

        assert!(
            !fragments.is_empty(),
            "Client {} should receive fragments",
            client.id
        );

        // Reassemble response
        let mut reassembled_response: Option<Vec<u8>> = None;
        for frag in fragments {
            if let Some(ip_packet) = client.receive_and_reassemble(&frag) {
                reassembled_response = Some(ip_packet);
            }
        }

        let response_ip = reassembled_response.expect("Should reassemble response");

        // Verify response matches original
        let original_response = original_responses
            .get(&client.session_id())
            .expect("Should have original response");
        assert_eq!(
            &response_ip, original_response,
            "Reassembled response should match original"
        );

        // Verify response structure
        let ip_info = IpPacketInfo::parse(&response_ip).expect("Should be valid IP packet");
        assert!(ip_info.is_udp(), "Response should be UDP");

        let udp_info = ip_info.parse_udp().unwrap();

        // Verify destination is this client
        match &ip_info.dst_addr {
            IpAddr::V4(addr) => {
                assert_eq!(
                    addr.octets(),
                    client.assigned_ip,
                    "Response should be addressed to this client"
                );
            }
            _ => panic!("Expected IPv4"),
        }

        // Verify response content
        let response_data = &udp_info.data;
        assert!(
            response_data.starts_with(b"RESPONSE:"),
            "Response should have expected prefix"
        );
        assert!(
            response_data.ends_with(b":END"),
            "Response should have expected suffix"
        );

        // Verify response contains original request data
        let expected_marker = format!("CLIENT_{}_REQUEST:", client.id);
        assert!(
            String::from_utf8_lossy(response_data).contains(&expected_marker),
            "Response should contain original request data"
        );

        // Send to client TUN (simulates delivering to application)
        client.tun.send(&response_ip).await.unwrap();

        println!(
            "Client {} verified response: {} bytes, UDP {}:{} -> {}:{}",
            client.id,
            response_ip.len(),
            ip_info.src_addr,
            udp_info.src_port,
            ip_info.dst_addr,
            udp_info.dst_port
        );
    }

    // =====================================================================
    // Final Verification
    // =====================================================================
    println!("\n=== Final Verification ===");

    for client in &clients {
        let capture = client.tun.capture();

        // Should have sent request (via inject) and received response
        assert_eq!(
            capture.received_count(),
            1,
            "Client {} should have 1 received packet (request)",
            client.id
        );
        assert_eq!(
            capture.sent_count(),
            1,
            "Client {} should have 1 sent packet (response)",
            client.id
        );

        // Verify packet analysis
        let sent = &capture.sent_packets()[0];
        let sent_info = sent.ip_info.as_ref().unwrap();
        assert!(sent_info.is_udp());

        let recv = &capture.received_packets()[0];
        let recv_info = recv.ip_info.as_ref().unwrap();
        assert!(recv_info.is_udp());

        println!(
            "Client {} final state: {} packets received, {} packets sent",
            client.id,
            capture.received_count(),
            capture.sent_count()
        );
    }

    // Verify server TUN
    let server_capture = server.tun.capture();
    assert_eq!(
        server_capture.sent_count(),
        clients.len(),
        "Server should have processed all client requests"
    );

    println!("\n=== Test completed successfully! ===");
    println!(
        "Processed {} clients with fragmented requests and responses",
        clients.len()
    );
}

/// Test concurrent requests from multiple clients
#[tokio::test]
async fn test_concurrent_client_requests() {
    let shared_key = b"concurrent-test-key-2024";

    let mut server = VpnServer::new(shared_key);
    let mut clients: Vec<VpnClient> = (1..=5)
        .map(|i| VpnClient::new(i, shared_key, [10, 0, 0, 100 + i as u8]))
        .collect();

    for client in &clients {
        server.register_client(client.session_id(), client.assigned_ip);
    }

    let mut network = NetworkChannel::new();

    // All clients send fragments in interleaved order (simulating concurrent transmission)
    let mut all_fragments: Vec<(u32, Vec<u8>)> = Vec::new();

    for client in &mut clients {
        let request_data: Vec<u8> = (0..300)
            .map(|i| ((client.id as usize * 17 + i) % 256) as u8)
            .collect();

        let request_ip = client.create_request(&request_data);
        client.tun.inject_recv_packet(request_ip.clone());

        let mut buf = vec![0u8; 2000];
        let n = client.tun.recv(&mut buf).await.unwrap();

        let fragments = client.encapsulate_and_fragment(&buf[..n]);
        for frag in fragments {
            all_fragments.push((client.session_id(), frag));
        }
    }

    // Shuffle fragments to simulate network reordering
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    all_fragments.shuffle(&mut rng);

    println!(
        "Sending {} interleaved fragments from {} clients",
        all_fragments.len(),
        clients.len()
    );

    // Send all fragments
    for (_session_id, frag) in all_fragments {
        network.send("server", frag);
    }

    // Server receives and reassembles
    let mut reassembled_count = 0;
    while let Some(fragment) = network.receive("server") {
        if let Some((session_id, _ip_packet)) = server.receive_fragment(&fragment) {
            reassembled_count += 1;
            println!(
                "Reassembled packet {} from session 0x{:08X}",
                reassembled_count, session_id
            );
        }
    }

    assert_eq!(
        reassembled_count,
        clients.len(),
        "Should reassemble one request per client despite interleaving"
    );
}

/// Test with varying packet sizes and fragment counts
#[tokio::test]
async fn test_varying_packet_sizes() {
    let shared_key = b"varying-size-test-key";

    let mut server = VpnServer::new(shared_key);
    let mut client = VpnClient::new(1, shared_key, [10, 0, 0, 101]);
    server.register_client(client.session_id(), client.assigned_ip);

    let mut network = NetworkChannel::new();

    // Test with various payload sizes
    let payload_sizes = [50, 150, 300, 500, 800, 1000];

    for size in payload_sizes {
        println!("\nTesting with payload size: {} bytes", size);

        // Create request with specific size
        let request_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let request_ip = client.create_request(&request_data);

        client.tun.inject_recv_packet(request_ip.clone());
        let mut buf = vec![0u8; 2000];
        let n = client.tun.recv(&mut buf).await.unwrap();

        // Encapsulate and fragment
        let fragments = client.encapsulate_and_fragment(&buf[..n]);
        let fragment_count = fragments.len();
        println!("  -> {} fragments", fragment_count);

        // Send to server
        for frag in fragments {
            network.send("server", frag);
        }

        // Server receives
        let mut reassembled = None;
        while let Some(fragment) = network.receive("server") {
            if let Some((_, ip_packet)) = server.receive_fragment(&fragment) {
                reassembled = Some(ip_packet);
            }
        }

        let reassembled = reassembled.expect("Should reassemble");
        assert_eq!(reassembled, request_ip, "Reassembled should match original");

        // Generate and send response
        let response_ip =
            ApplicationSimulator::process_request(&reassembled).expect("Should generate response");

        let response_fragments = server.encapsulate_for_client(client.session_id(), &response_ip);
        println!("  <- {} response fragments", response_fragments.len());

        for frag in response_fragments {
            network.send("client", frag);
        }

        // Client receives response
        let mut client_reassembled = None;
        while let Some(fragment) = network.receive("client") {
            if let Some(ip_packet) = client.receive_and_reassemble(&fragment) {
                client_reassembled = Some(ip_packet);
            }
        }

        let client_reassembled = client_reassembled.expect("Client should reassemble response");
        assert_eq!(
            client_reassembled, response_ip,
            "Client reassembled should match"
        );

        println!("  ✓ Round-trip successful for {} byte payload", size);
    }
}

/// Test error handling: out-of-order fragments
#[tokio::test]
async fn test_out_of_order_fragment_delivery() {
    let shared_key = b"out-of-order-test-key";

    let mut server = VpnServer::new(shared_key);
    let mut client = VpnClient::new(1, shared_key, [10, 0, 0, 101]);
    server.register_client(client.session_id(), client.assigned_ip);

    // Create large request
    let request_data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
    let request_ip = client.create_request(&request_data);

    client.tun.inject_recv_packet(request_ip.clone());
    let mut buf = vec![0u8; 2000];
    let n = client.tun.recv(&mut buf).await.unwrap();

    let mut fragments = client.encapsulate_and_fragment(&buf[..n]);
    let original_count = fragments.len();

    println!(
        "Created {} fragments, delivering in reverse order",
        original_count
    );

    // Reverse the order
    fragments.reverse();

    // Deliver in reverse order
    let mut reassembled = None;
    for frag in fragments {
        if let Some((_, ip_packet)) = server.receive_fragment(&frag) {
            reassembled = Some(ip_packet);
        }
    }

    let reassembled = reassembled.expect("Should reassemble despite out-of-order delivery");
    assert_eq!(
        reassembled, request_ip,
        "Reassembled should match original"
    );

    println!("✓ Successfully reassembled {} out-of-order fragments", original_count);
}

/// Test session isolation: packets from different sessions shouldn't interfere
#[tokio::test]
async fn test_session_isolation() {
    let shared_key = b"session-isolation-test";

    let mut server = VpnServer::new(shared_key);

    // Create two clients
    let mut client1 = VpnClient::new(1, shared_key, [10, 0, 0, 101]);
    let mut client2 = VpnClient::new(2, shared_key, [10, 0, 0, 102]);

    server.register_client(client1.session_id(), client1.assigned_ip);
    server.register_client(client2.session_id(), client2.assigned_ip);

    // Create distinct requests
    let request1_data = b"CLIENT_1_SPECIFIC_DATA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
    let request2_data = b"CLIENT_2_SPECIFIC_DATA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_vec();

    let request1_ip = client1.create_request(&request1_data);
    let request2_ip = client2.create_request(&request2_data);

    // Fragment both
    client1.tun.inject_recv_packet(request1_ip.clone());
    client2.tun.inject_recv_packet(request2_ip.clone());

    let mut buf = vec![0u8; 2000];

    let n1 = client1.tun.recv(&mut buf).await.unwrap();
    let fragments1 = client1.encapsulate_and_fragment(&buf[..n1]);

    let n2 = client2.tun.recv(&mut buf).await.unwrap();
    let fragments2 = client2.encapsulate_and_fragment(&buf[..n2]);

    // Interleave fragments from both clients
    let mut all_fragments = Vec::new();
    let max_len = fragments1.len().max(fragments2.len());
    for i in 0..max_len {
        if i < fragments1.len() {
            all_fragments.push((1, fragments1[i].clone()));
        }
        if i < fragments2.len() {
            all_fragments.push((2, fragments2[i].clone()));
        }
    }

    println!(
        "Interleaved {} fragments from 2 clients",
        all_fragments.len()
    );

    // Deliver interleaved
    let mut results: HashMap<u32, Vec<u8>> = HashMap::new();
    for (_, frag) in all_fragments {
        if let Some((session_id, ip_packet)) = server.receive_fragment(&frag) {
            results.insert(session_id, ip_packet);
        }
    }

    // Verify both were reassembled correctly
    assert_eq!(results.len(), 2, "Should reassemble both client packets");

    let result1 = results.get(&client1.session_id()).unwrap();
    let result2 = results.get(&client2.session_id()).unwrap();

    assert_eq!(result1, &request1_ip, "Client 1 packet should match");
    assert_eq!(result2, &request2_ip, "Client 2 packet should match");

    // Verify contents are distinct
    let info1 = IpPacketInfo::parse(result1).unwrap();
    let info2 = IpPacketInfo::parse(result2).unwrap();

    let udp1 = info1.parse_udp().unwrap();
    let udp2 = info2.parse_udp().unwrap();

    assert!(
        udp1.data.starts_with(b"CLIENT_1"),
        "Client 1 data should be distinct"
    );
    assert!(
        udp2.data.starts_with(b"CLIENT_2"),
        "Client 2 data should be distinct"
    );

    println!("✓ Session isolation verified");
}
