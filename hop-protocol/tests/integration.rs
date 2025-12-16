//! Integration tests for the hop protocol
//!
//! These tests simulate full client-server communication flows,
//! verifying the protocol works end-to-end.

use hop_protocol::{
    fragment_packet, Cipher, FragmentAssembler, Packet, Session, SessionId, SessionState,
    HOP_HDR_LEN,
};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Simulated network channel between peers
/// Supports multiple addresses to simulate port hopping
struct SimulatedChannel {
    /// Messages queued for delivery, keyed by destination address
    messages: HashMap<SocketAddr, Vec<Vec<u8>>>,
}

impl SimulatedChannel {
    fn new() -> Self {
        Self {
            messages: HashMap::new(),
        }
    }

    /// Send encrypted message to an address
    fn send(&mut self, to: SocketAddr, data: Vec<u8>) {
        self.messages.entry(to).or_default().push(data);
    }

    /// Receive next message from any source destined to this address
    fn recv(&mut self, at: SocketAddr) -> Option<Vec<u8>> {
        self.messages.get_mut(&at).and_then(|q| {
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        })
    }

    /// Check if there are pending messages for an address
    fn has_pending(&self, at: SocketAddr) -> bool {
        self.messages.get(&at).is_some_and(|q| !q.is_empty())
    }
}

/// Simulated peer (can act as client or server)
struct Peer {
    cipher: Cipher,
    session: Session,
    /// Addresses this peer listens on (for port hopping)
    listen_addrs: Vec<SocketAddr>,
    /// Known remote addresses (populated during port knocking)
    remote_addrs: Vec<SocketAddr>,
    /// Fragment assembler for incoming packets
    fragment_assembler: FragmentAssembler,
    /// Sequence counter for sent packets
    send_seq: u32,
}

impl Peer {
    fn new_client(key: &[u8], listen_addrs: Vec<SocketAddr>) -> Self {
        Self {
            cipher: Cipher::new(key),
            session: Session::new_client(),
            listen_addrs,
            remote_addrs: Vec::new(),
            fragment_assembler: FragmentAssembler::new(),
            send_seq: 0,
        }
    }

    fn new_server(key: &[u8], listen_addrs: Vec<SocketAddr>) -> Self {
        // Server starts with a placeholder session, will be populated on knock
        Self {
            cipher: Cipher::new(key),
            session: Session::new_client(), // Will be replaced
            listen_addrs,
            remote_addrs: Vec::new(),
            fragment_assembler: FragmentAssembler::new(),
            send_seq: 0,
        }
    }

    /// Get a random remote address (simulates port hopping on send)
    fn random_remote_addr(&self) -> Option<SocketAddr> {
        use rand::seq::SliceRandom;
        self.remote_addrs.choose(&mut rand::thread_rng()).copied()
    }

    /// Encrypt and send a packet
    fn send_packet(&self, channel: &mut SimulatedChannel, packet: &Packet, to: SocketAddr) {
        let encrypted = self.cipher.encrypt(packet, 0).unwrap();
        channel.send(to, encrypted);
    }

    /// Receive and decrypt a packet from any listen address
    fn recv_packet(&mut self, channel: &mut SimulatedChannel) -> Option<Packet> {
        for addr in &self.listen_addrs {
            if let Some(data) = channel.recv(*addr) {
                if let Ok(packet) = self.cipher.decrypt(&data) {
                    // Handle fragmentation
                    if let Ok(Some(assembled)) = self.fragment_assembler.process(packet) {
                        return Some(assembled);
                    }
                }
            }
        }
        None
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq += 1;
        seq
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_full_handshake_flow() {
    let key = b"shared-secret-key";

    // Setup addresses - server listens on multiple ports (port hopping)
    let server_addrs: Vec<SocketAddr> = (4001..=4005)
        .map(|p| format!("127.0.0.1:{}", p).parse().unwrap())
        .collect();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let mut client = Peer::new_client(key, vec![client_addr]);
    let mut server = Peer::new_server(key, server_addrs.clone());

    // Client knows server addresses
    client.remote_addrs = server_addrs.clone();

    // ========== Port Knocking Phase ==========
    // Client sends knock to ALL server ports
    let client_sid = client.session.id.value();

    for server_addr in &server_addrs {
        let knock = Packet::knock(client_sid);
        client.send_packet(&mut channel, &knock, *server_addr);
    }

    // Server receives knocks and records client address
    let mut received_knocks = 0;
    for server_addr in &server_addrs {
        if let Some(data) = channel.recv(*server_addr) {
            let packet = server.cipher.decrypt(&data).unwrap();
            assert!(packet.header.flag.is_push());

            let sid = packet.parse_sid_payload().unwrap();
            assert_eq!(sid, client_sid);

            // Server records this is from the client
            if server.remote_addrs.is_empty() {
                server.session = Session::new_server(SessionId::new(sid));
            }
            if !server.remote_addrs.contains(&client_addr) {
                server.remote_addrs.push(client_addr);
            }
            received_knocks += 1;
        }
    }
    assert_eq!(received_knocks, 5, "Should receive knock on all ports");

    // ========== Handshake Phase ==========
    // Client sends handshake request
    client.session.start_handshake().unwrap();
    let handshake_req = Packet::handshake_request(client_sid);
    let target = client.random_remote_addr().unwrap();
    client.send_packet(&mut channel, &handshake_req, target);

    // Server receives handshake request
    let packet = server.recv_packet(&mut channel).unwrap();
    assert!(packet.header.flag.is_handshake());
    assert!(!packet.header.flag.is_ack());

    // Server sends handshake response with assigned IP
    server.session.start_handshake().unwrap();
    let assigned_ip = [10, 1, 1, 100];
    let mask = 24;
    let handshake_resp = Packet::handshake_response(client_sid, assigned_ip, mask);
    server.send_packet(&mut channel, &handshake_resp, client_addr);

    // Client receives handshake response
    let packet = client.recv_packet(&mut channel).unwrap();
    assert!(packet.header.flag.is_handshake_ack());

    let (version, ip, recv_mask) = packet.parse_handshake_response().unwrap();
    assert_eq!(version, hop_protocol::HOP_PROTO_VERSION);
    assert_eq!(ip, assigned_ip);
    assert_eq!(recv_mask, mask);

    // Client sends handshake confirmation
    let confirm = Packet::handshake_confirm(client_sid);
    client.send_packet(&mut channel, &confirm, client.random_remote_addr().unwrap());
    client.session.complete_handshake(ip, recv_mask).unwrap();

    // Server receives confirmation
    let packet = server.recv_packet(&mut channel).unwrap();
    assert!(packet.header.flag.is_handshake_ack());
    server.session.complete_handshake(assigned_ip, mask).unwrap();

    // Both peers should now be in Working state
    assert_eq!(client.session.state, SessionState::Working);
    assert_eq!(server.session.state, SessionState::Working);
    assert_eq!(
        client.session.assigned_ip(),
        Some(hop_protocol::IpAddress::from_ipv4_bytes(assigned_ip))
    );
}

#[test]
fn test_data_transfer_bidirectional() {
    let key = b"data-transfer-key";

    let server_addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let mut client = Peer::new_client(key, vec![client_addr]);
    let mut server = Peer::new_server(key, vec![server_addr]);

    client.remote_addrs = vec![server_addr];
    server.remote_addrs = vec![client_addr];

    // Simulate already established session
    client.session.start_handshake().unwrap();
    client.session.complete_handshake([10, 1, 1, 5], 24).unwrap();
    server.session.start_handshake().unwrap();
    server.session.complete_handshake([10, 1, 1, 5], 24).unwrap();

    let client_sid = client.session.id.value();
    let server_sid = server.session.id.value();

    // ========== Client -> Server Data ==========
    let client_data = b"Hello from client!".to_vec();
    let seq = client.next_seq();
    let packet = Packet::data(seq, client_sid, client_data.clone());
    client.send_packet(&mut channel, &packet, server_addr);

    let received = server.recv_packet(&mut channel).unwrap();
    assert!(received.header.flag.is_data());
    assert_eq!(received.payload, client_data);

    // ========== Server -> Client Data ==========
    let server_data = b"Hello from server!".to_vec();
    let seq = server.next_seq();
    let packet = Packet::data(seq, server_sid, server_data.clone());
    server.send_packet(&mut channel, &packet, client_addr);

    let received = client.recv_packet(&mut channel).unwrap();
    assert!(received.header.flag.is_data());
    assert_eq!(received.payload, server_data);

    // ========== Multiple packets ==========
    for i in 0..10 {
        let data = format!("Packet {}", i).into_bytes();
        let seq = client.next_seq();
        let packet = Packet::data(seq, client_sid, data.clone());
        client.send_packet(&mut channel, &packet, server_addr);
    }

    // Server receives all packets
    let mut received_count = 0;
    while let Some(packet) = server.recv_packet(&mut channel) {
        assert!(packet.header.flag.is_data());
        received_count += 1;
    }
    assert_eq!(received_count, 10);
}

#[test]
fn test_port_hopping_simulation() {
    let key = b"port-hop-key";

    // Server listens on 10 different ports
    let server_addrs: Vec<SocketAddr> = (4001..=4010)
        .map(|p| format!("127.0.0.1:{}", p).parse().unwrap())
        .collect();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let mut client = Peer::new_client(key, vec![client_addr]);
    let mut server = Peer::new_server(key, server_addrs.clone());

    client.remote_addrs = server_addrs.clone();
    server.remote_addrs = vec![client_addr];

    // Setup sessions
    client.session.start_handshake().unwrap();
    client.session.complete_handshake([10, 1, 1, 5], 24).unwrap();

    let client_sid = client.session.id.value();

    // Send 100 packets to random server ports (simulating port hopping)
    let mut ports_used: HashMap<u16, usize> = HashMap::new();

    for i in 0..100 {
        let data = format!("Hop packet {}", i).into_bytes();
        let seq = client.next_seq();
        let packet = Packet::data(seq, client_sid, data);

        // Pick random server port
        let target = client.random_remote_addr().unwrap();
        *ports_used.entry(target.port()).or_insert(0) += 1;

        client.send_packet(&mut channel, &packet, target);
    }

    // Verify packets were distributed across multiple ports
    assert!(
        ports_used.len() > 1,
        "Should use multiple ports for hopping"
    );

    // Most ports should have been used at least once with 100 packets over 10 ports
    let used_ports = ports_used.len();
    assert!(
        used_ports >= 5,
        "Expected at least 5 different ports used, got {}",
        used_ports
    );

    // Server should be able to receive from all ports
    let mut received = 0;
    for addr in &server_addrs {
        while channel.has_pending(*addr) {
            if let Some(data) = channel.recv(*addr) {
                let packet = server.cipher.decrypt(&data).unwrap();
                assert!(packet.header.flag.is_data());
                received += 1;
            }
        }
    }
    assert_eq!(received, 100, "Should receive all 100 packets");

    println!("Port distribution: {:?}", ports_used);
}

#[test]
fn test_heartbeat_exchange() {
    let key = b"heartbeat-key";

    let server_addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let client = Peer::new_client(key, vec![client_addr]);
    let server = Peer::new_server(key, vec![server_addr]);

    let client_sid = client.session.id.value();

    // ========== Server sends heartbeat request ==========
    let heartbeat_req = Packet::heartbeat_request(client_sid);
    server.send_packet(&mut channel, &heartbeat_req, client_addr);

    // Client receives heartbeat
    let data = channel.recv(client_addr).unwrap();
    let packet = client.cipher.decrypt(&data).unwrap();
    assert!(packet.header.flag.is_push());
    assert!(!packet.header.flag.is_ack());
    assert!(packet.payload.is_empty()); // Heartbeat request has empty payload

    // ========== Client sends heartbeat response ==========
    let heartbeat_resp = Packet::heartbeat_response(client_sid);
    client.send_packet(&mut channel, &heartbeat_resp, server_addr);

    // Server receives response
    let data = channel.recv(server_addr).unwrap();
    let packet = server.cipher.decrypt(&data).unwrap();
    assert!(packet.header.flag.is_push_ack());

    // Response should contain SID
    let resp_sid = packet.parse_sid_payload().unwrap();
    assert_eq!(resp_sid, client_sid);
}

#[test]
fn test_session_termination() {
    let key = b"termination-key";

    let server_addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let mut client = Peer::new_client(key, vec![client_addr]);
    let mut server = Peer::new_server(key, vec![server_addr]);

    // Setup established session
    client.session.start_handshake().unwrap();
    client.session.complete_handshake([10, 1, 1, 5], 24).unwrap();
    server.session = Session::new_server(client.session.id);
    server.session.start_handshake().unwrap();
    server.session.complete_handshake([10, 1, 1, 5], 24).unwrap();

    assert_eq!(client.session.state, SessionState::Working);
    assert_eq!(server.session.state, SessionState::Working);

    let client_sid = client.session.id.value();

    // ========== Client initiates termination ==========
    let fin_req = Packet::finish_request(client_sid);
    client.send_packet(&mut channel, &fin_req, server_addr);
    client.session.start_finish().unwrap();

    // Server receives FIN
    let data = channel.recv(server_addr).unwrap();
    let packet = server.cipher.decrypt(&data).unwrap();
    assert!(packet.header.flag.is_finish());
    assert!(!packet.header.flag.is_ack());

    // Server sends FIN ACK
    let fin_ack = Packet::finish_ack(client_sid);
    server.send_packet(&mut channel, &fin_ack, client_addr);
    server.session.start_finish().unwrap();

    // Client receives FIN ACK
    let data = channel.recv(client_addr).unwrap();
    let packet = client.cipher.decrypt(&data).unwrap();
    assert!(packet.header.flag.is_finish_ack());

    // Both should be in FIN state
    assert_eq!(client.session.state, SessionState::Fin);
    assert_eq!(server.session.state, SessionState::Fin);
}

#[test]
fn test_fragmentation_and_reassembly() {
    let key = b"fragment-key";

    let server_addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let mut client = Peer::new_client(key, vec![client_addr]);
    let mut server = Peer::new_server(key, vec![server_addr]);

    let client_sid = client.session.id.value();

    // Create a large payload that needs fragmentation
    let large_payload: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
    let seq = client.next_seq();
    let original_packet = Packet::data(seq, client_sid, large_payload.clone());

    // Fragment into small pieces (header + 50 bytes payload max)
    let fragments = fragment_packet(&original_packet, HOP_HDR_LEN + 50).unwrap();
    assert!(fragments.len() > 1, "Should create multiple fragments");

    println!("Created {} fragments for 500 byte payload", fragments.len());

    // Send all fragments
    for frag in &fragments {
        client.send_packet(&mut channel, frag, server_addr);
    }

    // Server receives and reassembles
    // Note: fragments might arrive and we need to collect them all
    let mut assembled = None;
    for _ in 0..fragments.len() {
        if let Some(packet) = server.recv_packet(&mut channel) {
            assembled = Some(packet);
        }
    }

    // Should have reassembled the complete packet
    let reassembled = assembled.expect("Should reassemble packet");
    assert_eq!(reassembled.payload, large_payload);
}

#[test]
fn test_out_of_order_fragment_delivery() {
    let key = b"ooo-fragment-key";

    let cipher = Cipher::new(key);
    let mut assembler = FragmentAssembler::new();

    let client_sid = 0x12345678u32;

    // Create large payload
    let payload: Vec<u8> = (0..200).collect();
    let packet = Packet::data(42, client_sid, payload.clone());

    // Fragment it
    let fragments = fragment_packet(&packet, HOP_HDR_LEN + 30).unwrap();
    assert!(fragments.len() >= 3, "Need multiple fragments for this test");

    println!("Testing with {} fragments", fragments.len());

    // Encrypt fragments
    let encrypted: Vec<Vec<u8>> = fragments
        .iter()
        .map(|f| cipher.encrypt(f, 0).unwrap())
        .collect();

    // Deliver in reverse order
    let mut result = None;
    for data in encrypted.into_iter().rev() {
        let decrypted = cipher.decrypt(&data).unwrap();
        if let Ok(Some(assembled)) = assembler.process(decrypted) {
            result = Some(assembled);
        }
    }

    let reassembled = result.expect("Should reassemble despite out-of-order delivery");
    assert_eq!(reassembled.payload, payload);
}

#[test]
fn test_wrong_key_rejection() {
    let correct_key = b"correct-key";
    let wrong_key = b"wrong-key";

    let addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let client = Peer::new_client(correct_key, vec![addr]);
    let server_wrong = Peer::new_server(wrong_key, vec![addr]);

    // Client sends with correct key
    let packet = Packet::data(1, 0x1234, b"secret data".to_vec());
    client.send_packet(&mut channel, &packet, addr);

    // Server with wrong key tries to decrypt
    let data = channel.recv(addr).unwrap();
    let result = server_wrong.cipher.decrypt(&data);

    // Decryption should fail
    assert!(result.is_err(), "Should reject packet encrypted with different key");
}

#[test]
fn test_noise_padding_transparency() {
    let key = b"noise-key";
    let cipher = Cipher::new(key);

    // Create packet and encrypt with different noise levels
    let original = Packet::data(1, 0xABCD, b"test payload".to_vec());

    for max_noise in [0, 50, 100, 500] {
        let encrypted = cipher.encrypt(&original, max_noise).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        // Payload should be identical regardless of noise
        assert_eq!(decrypted.payload, original.payload);
        assert_eq!(decrypted.header.seq, original.header.seq);
        assert_eq!(decrypted.header.sid, original.header.sid);
    }
}

#[test]
fn test_handshake_error_flow() {
    let key = b"error-key";

    let server_addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let mut channel = SimulatedChannel::new();
    let client = Peer::new_client(key, vec![client_addr]);
    let server = Peer::new_server(key, vec![server_addr]);

    let client_sid = client.session.id.value();

    // Client sends handshake
    let handshake_req = Packet::handshake_request(client_sid);
    client.send_packet(&mut channel, &handshake_req, server_addr);

    // Server receives handshake
    let data = channel.recv(server_addr).unwrap();
    let _packet = server.cipher.decrypt(&data).unwrap();

    // Server rejects with error (e.g., no available IPs)
    let error_msg = "No IP addresses available";
    let error_packet = Packet::handshake_error(client_sid, error_msg);
    server.send_packet(&mut channel, &error_packet, client_addr);

    // Client receives error
    let data = channel.recv(client_addr).unwrap();
    let packet = client.cipher.decrypt(&data).unwrap();

    assert!(packet.header.flag.is_handshake_error());
    assert_eq!(packet.parse_handshake_error(), error_msg);
}

// =============================================================================
// Real UDP Integration Tests
// =============================================================================
//
// These tests use actual UDP sockets to verify the protocol works over a real
// network stack, not just simulated channels.

mod udp_tests {
    use hop_protocol::{Cipher, Packet, Session, SessionState};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;
    use tokio::time::{timeout, Duration};

    /// Helper to bind to an available port
    async fn bind_random_port() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    /// Helper to bind to multiple consecutive ports for port hopping
    async fn bind_port_range(base_port: u16, count: u16) -> Vec<UdpSocket> {
        let mut sockets = Vec::new();
        for offset in 0..count {
            let addr = format!("127.0.0.1:{}", base_port + offset);
            match UdpSocket::bind(&addr).await {
                Ok(sock) => sockets.push(sock),
                Err(_) => {
                    // Port unavailable, try binding to any available port
                    sockets.push(bind_random_port().await);
                }
            }
        }
        sockets
    }

    #[tokio::test]
    async fn test_udp_basic_send_recv() {
        let key = b"udp-basic-test-key";
        let cipher = Cipher::new(key);

        // Bind two UDP sockets
        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        // Connect client to server (for send without specifying addr)
        client_socket.connect(server_addr).await.unwrap();

        // Create and encrypt a data packet
        let original_data = b"Hello over real UDP!".to_vec();
        let packet = Packet::data(1, 0x12345678, original_data.clone());
        let encrypted = cipher.encrypt(&packet, 0).unwrap();

        // Send from client
        client_socket.send(&encrypted).await.unwrap();

        // Receive on server
        let mut buf = vec![0u8; 2048];
        let (len, from_addr) = timeout(Duration::from_secs(1), server_socket.recv_from(&mut buf))
            .await
            .expect("Timeout receiving packet")
            .unwrap();

        assert_eq!(from_addr, client_addr);

        // Decrypt and verify
        let received_packet = cipher.decrypt(&buf[..len]).unwrap();
        assert!(received_packet.header.flag.is_data());
        assert_eq!(received_packet.payload, original_data);
    }

    #[tokio::test]
    async fn test_udp_bidirectional_communication() {
        let key = b"udp-bidir-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        // Client -> Server
        let client_msg = b"Request from client".to_vec();
        let packet = Packet::data(1, 0xAAAA, client_msg.clone());
        let encrypted = cipher.encrypt(&packet, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server receives
        let mut buf = vec![0u8; 2048];
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let received = cipher.decrypt(&buf[..len]).unwrap();
        assert_eq!(received.payload, client_msg);

        // Server -> Client (response)
        let server_msg = b"Response from server".to_vec();
        let response = Packet::data(1, 0xBBBB, server_msg.clone());
        let encrypted_resp = cipher.encrypt(&response, 0).unwrap();
        server_socket
            .send_to(&encrypted_resp, client_addr)
            .await
            .unwrap();

        // Client receives response
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let received_resp = cipher.decrypt(&buf[..len]).unwrap();
        assert_eq!(received_resp.payload, server_msg);
    }

    #[tokio::test]
    async fn test_udp_port_hopping_10_ports() {
        let key = b"udp-port-hop-key";
        let cipher = Cipher::new(key);

        // Server listens on 10 ports
        let server_sockets = bind_port_range(14000, 10).await;
        let server_addrs: Vec<SocketAddr> = server_sockets
            .iter()
            .map(|s| s.local_addr().unwrap())
            .collect();

        let client_socket = bind_random_port().await;
        let client_addr = client_socket.local_addr().unwrap();

        println!("Client: {}", client_addr);
        println!(
            "Server ports: {:?}",
            server_addrs.iter().map(|a| a.port()).collect::<Vec<_>>()
        );

        // Track which ports receive packets
        let packets_per_port: Arc<Mutex<std::collections::HashMap<u16, usize>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Spawn receivers for all server ports
        let mut handles = Vec::new();
        for socket in server_sockets {
            let cipher = cipher.clone();
            let packets_per_port = packets_per_port.clone();
            let port = socket.local_addr().unwrap().port();

            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok(Ok((len, _))) =
                    timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await
                {
                    if let Ok(packet) = cipher.decrypt(&buf[..len]) {
                        if packet.header.flag.is_data() {
                            let mut map = packets_per_port.lock().await;
                            *map.entry(port).or_insert(0) += 1;
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Client sends 100 packets to random server ports (simulating port hopping)
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();

        for i in 0..100u32 {
            let data = format!("Hop packet {}", i).into_bytes();
            let packet = Packet::data(i, 0xCAFE, data);
            let encrypted = cipher.encrypt(&packet, 0).unwrap();

            // Pick random server port
            let target = server_addrs.choose(&mut rng).unwrap();
            client_socket.send_to(&encrypted, target).await.unwrap();

            // Small delay to avoid overwhelming
            tokio::time::sleep(Duration::from_micros(100)).await;
        }

        // Wait for all receivers to timeout and finish
        tokio::time::sleep(Duration::from_millis(600)).await;

        // Check distribution
        let map = packets_per_port.lock().await;
        let total_received: usize = map.values().sum();
        let ports_used = map.len();

        println!("Port distribution: {:?}", *map);
        println!(
            "Total received: {}, Ports used: {}",
            total_received, ports_used
        );

        assert!(
            total_received >= 90,
            "Should receive most packets, got {}",
            total_received
        );
        assert!(
            ports_used >= 5,
            "Should distribute across at least 5 ports, got {}",
            ports_used
        );
    }

    #[tokio::test]
    async fn test_udp_full_handshake() {
        let key = b"udp-handshake-key";
        let client_cipher = Cipher::new(key);
        let server_cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let mut client_session = Session::new_client();
        let client_sid = client_session.id.value();

        // ========== Port Knock ==========
        let knock = Packet::knock(client_sid);
        let encrypted = client_cipher.encrypt(&knock, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server receives knock
        let mut buf = vec![0u8; 2048];
        let (len, from) = server_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, client_addr);

        let knock_packet = server_cipher.decrypt(&buf[..len]).unwrap();
        assert!(knock_packet.header.flag.is_push());
        let received_sid = knock_packet.parse_sid_payload().unwrap();
        assert_eq!(received_sid, client_sid);

        // Server creates session for this client
        let mut server_session =
            Session::new_server(hop_protocol::SessionId::new(received_sid));

        // ========== Handshake Request ==========
        client_session.start_handshake().unwrap();
        let hs_req = Packet::handshake_request(client_sid);
        let encrypted = client_cipher.encrypt(&hs_req, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server receives handshake request
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let hs_req_packet = server_cipher.decrypt(&buf[..len]).unwrap();
        assert!(hs_req_packet.header.flag.is_handshake());
        assert!(!hs_req_packet.header.flag.is_ack());

        // ========== Handshake Response ==========
        server_session.start_handshake().unwrap();
        let assigned_ip = [10, 0, 0, 42];
        let mask = 24;
        let hs_resp = Packet::handshake_response(client_sid, assigned_ip, mask);
        let encrypted = server_cipher.encrypt(&hs_resp, 0).unwrap();
        server_socket
            .send_to(&encrypted, client_addr)
            .await
            .unwrap();

        // Client receives handshake response
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let hs_resp_packet = client_cipher.decrypt(&buf[..len]).unwrap();
        assert!(hs_resp_packet.header.flag.is_handshake_ack());

        let (version, ip, recv_mask) = hs_resp_packet.parse_handshake_response().unwrap();
        assert_eq!(version, hop_protocol::HOP_PROTO_VERSION);
        assert_eq!(ip, assigned_ip);
        assert_eq!(recv_mask, mask);

        // ========== Handshake Confirm ==========
        let hs_confirm = Packet::handshake_confirm(client_sid);
        let encrypted = client_cipher.encrypt(&hs_confirm, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();
        client_session.complete_handshake(ip, recv_mask).unwrap();

        // Server receives confirmation
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let confirm_packet = server_cipher.decrypt(&buf[..len]).unwrap();
        assert!(confirm_packet.header.flag.is_handshake_ack());
        server_session.complete_handshake(assigned_ip, mask).unwrap();

        // Both should be in Working state
        assert_eq!(client_session.state, SessionState::Working);
        assert_eq!(server_session.state, SessionState::Working);
        assert_eq!(
            client_session.assigned_ip(),
            Some(hop_protocol::IpAddress::from_ipv4_bytes(assigned_ip))
        );
    }

    #[tokio::test]
    async fn test_udp_data_transfer_after_handshake() {
        let key = b"udp-data-xfer-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let sid = 0xDEADBEEF;

        // Simulate established session - send multiple data packets
        let messages = vec![
            b"First message".to_vec(),
            b"Second message with more data".to_vec(),
            b"Third message".to_vec(),
            vec![0u8; 1000], // Binary data
        ];

        // Send all messages from client
        for (seq, msg) in messages.iter().enumerate() {
            let packet = Packet::data(seq as u32, sid, msg.clone());
            let encrypted = cipher.encrypt(&packet, 50).unwrap(); // Add noise
            client_socket.send_to(&encrypted, server_addr).await.unwrap();
        }

        // Server receives all messages
        let mut buf = vec![0u8; 2048];
        let mut received_messages = Vec::new();

        for _ in 0..messages.len() {
            let (len, from) = timeout(Duration::from_secs(1), server_socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();

            assert_eq!(from, client_addr);
            let packet = cipher.decrypt(&buf[..len]).unwrap();
            assert!(packet.header.flag.is_data());
            received_messages.push(packet.payload);
        }

        // Verify all messages received correctly (order may vary with UDP)
        assert_eq!(received_messages.len(), messages.len());
        for msg in &messages {
            assert!(
                received_messages.contains(msg),
                "Missing message: {:?}",
                msg
            );
        }
    }

    #[tokio::test]
    async fn test_udp_heartbeat_exchange() {
        let key = b"udp-heartbeat-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let sid = 0x11223344;

        // Server sends heartbeat request
        let hb_req = Packet::heartbeat_request(sid);
        let encrypted = cipher.encrypt(&hb_req, 0).unwrap();
        server_socket
            .send_to(&encrypted, client_addr)
            .await
            .unwrap();

        // Client receives heartbeat
        let mut buf = vec![0u8; 2048];
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let packet = cipher.decrypt(&buf[..len]).unwrap();
        assert!(packet.header.flag.is_push());
        assert!(!packet.header.flag.is_ack());

        // Client sends heartbeat response
        let hb_resp = Packet::heartbeat_response(sid);
        let encrypted = cipher.encrypt(&hb_resp, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server receives response
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let resp_packet = cipher.decrypt(&buf[..len]).unwrap();
        assert!(resp_packet.header.flag.is_push_ack());
        let resp_sid = resp_packet.parse_sid_payload().unwrap();
        assert_eq!(resp_sid, sid);
    }

    #[tokio::test]
    async fn test_udp_session_termination() {
        let key = b"udp-fin-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let sid = 0xF1F1F1F1;

        // Client sends FIN
        let fin_req = Packet::finish_request(sid);
        let encrypted = cipher.encrypt(&fin_req, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server receives FIN
        let mut buf = vec![0u8; 2048];
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = cipher.decrypt(&buf[..len]).unwrap();
        assert!(packet.header.flag.is_finish());
        assert!(!packet.header.flag.is_ack());

        // Server sends FIN ACK
        let fin_ack = Packet::finish_ack(sid);
        let encrypted = cipher.encrypt(&fin_ack, 0).unwrap();
        server_socket
            .send_to(&encrypted, client_addr)
            .await
            .unwrap();

        // Client receives FIN ACK
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let ack_packet = cipher.decrypt(&buf[..len]).unwrap();
        assert!(ack_packet.header.flag.is_finish_ack());
    }

    #[tokio::test]
    async fn test_udp_wrong_key_rejection() {
        let correct_key = b"correct-udp-key";
        let wrong_key = b"wrong-udp-key!!!";

        let client_cipher = Cipher::new(correct_key);
        let server_cipher = Cipher::new(wrong_key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();

        // Client sends with correct key
        let packet = Packet::data(1, 0x1234, b"secret data".to_vec());
        let encrypted = client_cipher.encrypt(&packet, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server with wrong key tries to decrypt
        let mut buf = vec![0u8; 2048];
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let result = server_cipher.decrypt(&buf[..len]);

        // Should fail to decrypt
        assert!(
            result.is_err(),
            "Should reject packet encrypted with different key"
        );
    }

    #[tokio::test]
    async fn test_udp_concurrent_clients() {
        let key = b"udp-concurrent-key";
        let server_cipher = Cipher::new(key);

        let server_socket = Arc::new(bind_random_port().await);
        let server_addr = server_socket.local_addr().unwrap();

        // Track received packets by session ID
        let received: Arc<Mutex<std::collections::HashMap<u32, Vec<Vec<u8>>>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Spawn server receiver
        let server_recv = received.clone();
        let server_cipher_clone = server_cipher.clone();
        let server_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok(Ok((len, _))) =
                timeout(Duration::from_secs(2), server_socket.recv_from(&mut buf)).await
            {
                if let Ok(packet) = server_cipher_clone.decrypt(&buf[..len]) {
                    if packet.header.flag.is_data() {
                        let mut map = server_recv.lock().await;
                        map.entry(packet.header.sid)
                            .or_default()
                            .push(packet.payload);
                    }
                }
            }
        });

        // Spawn multiple clients
        let num_clients = 5;
        let packets_per_client = 10;
        let mut client_handles = Vec::new();

        for client_id in 0..num_clients {
            let cipher = Cipher::new(key);
            let sid = 0x1000 + client_id as u32;

            let handle = tokio::spawn(async move {
                let socket = bind_random_port().await;

                for seq in 0..packets_per_client {
                    let data = format!("Client {} packet {}", client_id, seq).into_bytes();
                    let packet = Packet::data(seq as u32, sid, data);
                    let encrypted = cipher.encrypt(&packet, 0).unwrap();
                    socket.send_to(&encrypted, server_addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            client_handles.push(handle);
        }

        // Wait for all clients to finish
        for handle in client_handles {
            handle.await.unwrap();
        }

        // Wait for server to process all packets
        tokio::time::sleep(Duration::from_millis(500)).await;
        server_handle.abort();

        // Verify all clients' packets were received
        let map = received.lock().await;
        assert_eq!(
            map.len(),
            num_clients,
            "Should have packets from all clients"
        );

        for client_id in 0..num_clients {
            let sid = 0x1000 + client_id as u32;
            let packets = map.get(&sid).unwrap();
            assert_eq!(
                packets.len(),
                packets_per_client,
                "Client {} should have {} packets",
                client_id,
                packets_per_client
            );
        }
    }

    #[tokio::test]
    async fn test_udp_port_hopping_with_handshake() {
        let key = b"udp-hop-hs-key";
        let cipher = Cipher::new(key);

        // Server listens on 10 ports
        let server_sockets = bind_port_range(15000, 10).await;
        let server_addrs: Vec<SocketAddr> = server_sockets
            .iter()
            .map(|s| s.local_addr().unwrap())
            .collect();

        // Client socket
        let client_socket = Arc::new(bind_random_port().await);

        // Shared state for tracking
        let received_knocks: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));

        // Spawn receivers for all server ports
        let mut handles = Vec::new();
        for socket in server_sockets {
            let cipher = cipher.clone();
            let received_knocks = received_knocks.clone();
            let port = socket.local_addr().unwrap().port();

            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok(Ok((len, _))) =
                    timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await
                {
                    if let Ok(packet) = cipher.decrypt(&buf[..len]) {
                        if packet.header.flag.is_push() {
                            let mut knocks = received_knocks.lock().await;
                            knocks.push(port);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Client performs port knocking on ALL ports
        let client_session = Session::new_client();
        let client_sid = client_session.id.value();

        for addr in &server_addrs {
            let knock = Packet::knock(client_sid);
            let encrypted = cipher.encrypt(&knock, 0).unwrap();
            client_socket.send_to(&encrypted, addr).await.unwrap();
        }

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(600)).await;

        // Verify knocks received on all ports
        let knocks = received_knocks.lock().await;
        assert_eq!(
            knocks.len(),
            10,
            "Should receive knock on all 10 ports, got {}",
            knocks.len()
        );

        println!("Knocks received on ports: {:?}", *knocks);
    }

    #[tokio::test]
    async fn test_udp_large_packet_transfer() {
        let key = b"udp-large-pkt-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();

        // Create a moderately large payload (fits in single UDP packet)
        let large_payload: Vec<u8> = (0..1200).map(|i| (i % 256) as u8).collect();
        let packet = Packet::data(1, 0xB16DA7A, large_payload.clone());
        let encrypted = cipher.encrypt(&packet, 0).unwrap();

        // Send
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Receive
        let mut buf = vec![0u8; 4096];
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let received = cipher.decrypt(&buf[..len]).unwrap();

        assert_eq!(received.payload, large_payload);
    }

    #[tokio::test]
    async fn test_udp_noise_padding_over_network() {
        let key = b"udp-noise-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();

        let original_data = b"test payload".to_vec();

        // Send same packet with different noise levels
        let noise_levels = [0, 50, 100, 200];
        let mut packet_sizes = Vec::new();

        for max_noise in noise_levels {
            let packet = Packet::data(1, 0x0015E, original_data.clone());
            let encrypted = cipher.encrypt(&packet, max_noise).unwrap();
            packet_sizes.push(encrypted.len());

            client_socket.send_to(&encrypted, server_addr).await.unwrap();

            let mut buf = vec![0u8; 2048];
            let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
            let received = cipher.decrypt(&buf[..len]).unwrap();

            // Payload should be identical despite noise
            assert_eq!(received.payload, original_data);
        }

        // Packet sizes should vary with noise (probabilistically)
        println!("Packet sizes with different noise levels: {:?}", packet_sizes);
    }

    #[tokio::test]
    async fn test_udp_rapid_port_switching() {
        let key = b"udp-rapid-switch";
        let cipher = Cipher::new(key);

        // Server on 10 ports
        let server_sockets = bind_port_range(16000, 10).await;
        let server_addrs: Vec<SocketAddr> = server_sockets
            .iter()
            .map(|s| s.local_addr().unwrap())
            .collect();

        let client_socket = bind_random_port().await;
        let sid = 0xBA91D;

        // Packets received per port
        let port_counts: Arc<Mutex<std::collections::HashMap<u16, usize>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Spawn receivers
        let mut handles = Vec::new();
        for socket in server_sockets {
            let cipher = cipher.clone();
            let port_counts = port_counts.clone();
            let port = socket.local_addr().unwrap().port();

            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok(Ok((len, _))) =
                    timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await
                {
                    if cipher.decrypt(&buf[..len]).is_ok() {
                        let mut counts = port_counts.lock().await;
                        *counts.entry(port).or_insert(0) += 1;
                    }
                }
            }));
        }

        // Send 200 packets switching ports every packet
        for seq in 0..200u32 {
            let port_idx = (seq as usize) % server_addrs.len();
            let target = server_addrs[port_idx];

            let packet = Packet::data(seq, sid, vec![seq as u8]);
            let encrypted = cipher.encrypt(&packet, 0).unwrap();
            client_socket.send_to(&encrypted, target).await.unwrap();
        }

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let counts = port_counts.lock().await;
        let total: usize = counts.values().sum();

        println!("Rapid port switching distribution: {:?}", *counts);
        println!("Total received: {}", total);

        // Each port should get roughly 20 packets (200/10)
        assert!(total >= 180, "Should receive most packets");
        assert_eq!(counts.len(), 10, "Should use all 10 ports");
    }

    /// Test multi-address handshake using local network interfaces
    #[tokio::test]
    async fn test_multi_address_handshake() {
        use hop_protocol::{AssignedAddress, AssignedAddresses, IpAddress};
        use local_ip_address::list_afinet_netifas;

        let key = b"multi-addr-test-key";
        let cipher = Cipher::new(key);

        let server_socket = bind_random_port().await;
        let client_socket = bind_random_port().await;

        let server_addr = server_socket.local_addr().unwrap();

        // Get all local IP addresses from the system
        let local_ips: Vec<AssignedAddress> = list_afinet_netifas()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_name, ip)| {
                // Filter out loopback and link-local addresses for this test
                match ip {
                    std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() => {
                        Some(AssignedAddress::new(IpAddress::from(v4), 24))
                    }
                    std::net::IpAddr::V6(v6)
                        if !v6.is_loopback()
                            && !v6.to_string().starts_with("fe80") // link-local
                            && !v6.to_string().starts_with("::1") =>
                    {
                        Some(AssignedAddress::new(IpAddress::from(v6), 64))
                    }
                    _ => None,
                }
            })
            .take(5) // Limit to 5 addresses for test
            .collect();

        // If no non-loopback addresses found, use test addresses
        let addresses = if local_ips.is_empty() {
            AssignedAddresses::multiple(vec![
                AssignedAddress::from_ipv4([10, 0, 0, 1], 24),
                AssignedAddress::from_ipv4([192, 168, 1, 100], 24),
            ])
            .unwrap()
        } else {
            AssignedAddresses::multiple(local_ips).unwrap()
        };

        println!(
            "Testing multi-address handshake with {} addresses",
            addresses.len()
        );
        for addr in addresses.iter() {
            println!("  - {}", addr);
        }

        // Client initiates handshake
        let mut client_session = Session::new_client();
        let client_sid = client_session.id.value();

        // Knock
        let knock = Packet::knock(client_sid);
        let encrypted = cipher.encrypt(&knock, 0).unwrap();
        client_socket.send_to(&encrypted, server_addr).await.unwrap();

        // Server receives knock
        let mut buf = vec![0u8; 2048];
        let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
        let _knock_packet = cipher.decrypt(&buf[..len]).unwrap();

        // Server creates session and sends multi-address handshake response
        let mut server_session = Session::new_server(hop_protocol::SessionId::new(client_sid));
        server_session.start_handshake().unwrap();

        let handshake_resp = Packet::handshake_response_multi_ip(client_sid, addresses.clone());
        let encrypted = cipher.encrypt(&handshake_resp, 0).unwrap();
        server_socket
            .send_to(&encrypted, client_addr)
            .await
            .unwrap();

        // Client receives multi-address handshake response
        let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
        let resp_packet = cipher.decrypt(&buf[..len]).unwrap();

        assert!(resp_packet.header.flag.is_handshake_ack());

        // Parse using v3 to get all addresses
        let (version, received_addrs) = resp_packet.parse_handshake_response_v3().unwrap();
        assert_eq!(version, hop_protocol::HOP_PROTO_VERSION);
        assert_eq!(received_addrs.len(), addresses.len());

        // Complete client handshake with multi-addresses
        client_session.start_handshake().unwrap();
        client_session
            .complete_handshake_v3(received_addrs.clone())
            .unwrap();

        assert_eq!(client_session.state, SessionState::Working);
        assert!(client_session.has_multiple_addresses() || addresses.len() == 1);
        assert_eq!(client_session.address_count(), addresses.len());

        // Verify all addresses are stored
        let all_addrs = client_session.all_addresses().unwrap();
        assert_eq!(all_addrs.len(), addresses.len());

        // Primary address should match
        assert_eq!(all_addrs.primary(), addresses.primary());

        println!("Multi-address handshake successful!");
        println!("Client can hop between {} server IPs", addresses.len());
    }
}
