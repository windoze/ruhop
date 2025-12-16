//! Integration tests using mock transport to verify protocol correctness
//!
//! These tests simulate VPN data flows using mock TUN devices and verify:
//! - IP packet encapsulation and decapsulation
//! - Protocol encryption/decryption with payload analysis
//! - Session state machine with transport layer
//! - Fragmentation handling over the transport
//! - Bidirectional communication flows

use std::sync::Arc;

use hop_protocol::transport::mock::{IpPacketBuilder, MockTunDevice, MockUdpSocket};
use hop_protocol::transport::{TunTransport, UdpTransport};
use hop_protocol::{
    fragment_packet, Cipher, FragmentAssembler, Packet, Session, SessionId, SessionState,
    HOP_HDR_LEN,
};

/// Simulates a complete VPN data path:
/// 1. TUN device receives IP packet from OS
/// 2. IP packet is encapsulated in hop protocol packet
/// 3. Protocol packet is encrypted
/// 4. Encrypted packet is sent via UDP
/// 5. Receiver decrypts and decapsulates
/// 6. Original IP packet is sent to OS via TUN
#[tokio::test]
async fn test_full_vpn_data_path() {
    let key = b"vpn-data-path-test-key";
    let cipher = Cipher::new(key);

    // Create mock TUN devices for client and server
    let client_tun = MockTunDevice::new("tun-client", 1400);
    let server_tun = MockTunDevice::new("tun-server", 1400);

    // Create mock UDP sockets
    let client_udp = Arc::new(MockUdpSocket::new("10.0.0.1:5000".parse().unwrap()));
    let server_udp = Arc::new(MockUdpSocket::new("10.0.0.2:5000".parse().unwrap()));
    MockUdpSocket::connect_pair(&client_udp, &server_udp);

    // Sessions
    let client_session = Session::new_client();
    let client_sid = client_session.id.value();

    // Simulate OS sending an IP packet through the VPN
    let original_ip_packet = IpPacketBuilder::ipv4()
        .src_v4(192, 168, 1, 100) // Client's real IP
        .dst_v4(8, 8, 8, 8) // External destination
        .with_udp(12345, 53, b"DNS query for example.com")
        .build();

    client_tun.inject_recv_packet(original_ip_packet.clone());

    // Step 1: Client reads IP packet from TUN
    let mut buf = vec![0u8; 2000];
    let n = client_tun.recv(&mut buf).await.unwrap();
    let ip_packet = buf[..n].to_vec();

    // Verify it's a valid IP packet
    let capture = client_tun.capture();
    let recv_packet = &capture.received_packets()[0];
    let ip_info = recv_packet.ip_info.as_ref().unwrap();
    assert!(ip_info.is_udp());
    assert_eq!(ip_info.protocol_name(), "UDP");

    // Step 2: Encapsulate in hop protocol packet
    let hop_packet = Packet::data(1, client_sid, ip_packet.clone());

    // Step 3: Encrypt
    let encrypted = cipher.encrypt(&hop_packet, 0).unwrap();

    // Step 4: Send via UDP to server
    let server_addr = server_udp.local_addr().unwrap();
    client_udp.send_to(&encrypted, server_addr).await.unwrap();

    // Step 5: Server receives and decrypts
    let mut recv_buf = vec![0u8; 2000];
    let (n, _from) = server_udp.recv_from(&mut recv_buf).await.unwrap();
    let decrypted = cipher.decrypt(&recv_buf[..n]).unwrap();

    // Verify protocol packet
    assert!(decrypted.header.flag.is_data());
    assert_eq!(decrypted.header.sid, client_sid);

    // Step 6: Extract and send IP packet to server TUN
    let extracted_ip_packet = &decrypted.payload;
    server_tun.send(extracted_ip_packet).await.unwrap();

    // Verify the IP packet went through correctly
    let server_capture = server_tun.capture();
    assert_eq!(server_capture.sent_count(), 1);

    let sent_packet = &server_capture.sent_packets()[0];
    assert_eq!(sent_packet.data, original_ip_packet);

    let sent_ip_info = sent_packet.ip_info.as_ref().unwrap();
    assert!(sent_ip_info.is_udp());
    let udp_info = sent_ip_info.parse_udp().unwrap();
    assert_eq!(udp_info.dst_port, 53);
    assert_eq!(udp_info.data, b"DNS query for example.com");
}

/// Test bidirectional communication through mock transport
#[tokio::test]
async fn test_bidirectional_vpn_communication() {
    let key = b"bidirectional-test-key";
    let cipher = Cipher::new(key);

    // Create connected TUN pair (packets sent to one appear in the other)
    let (client_tun, server_tun) = MockTunDevice::create_pair(1400);

    let client_sid = 0x12345678;
    let server_sid = 0xABCDEF00;

    // === Client -> Server ===
    let client_to_server = IpPacketBuilder::ipv4()
        .src_v4(10, 0, 0, 1)
        .dst_v4(10, 0, 0, 2)
        .with_tcp(1234, 80, 1000, 0, 0x02, b"GET /index.html")
        .build();

    // Client encapsulates and "sends" (via TUN pair connection)
    let hop_packet = Packet::data(1, client_sid, client_to_server.clone());
    let encrypted = cipher.encrypt(&hop_packet, 50).unwrap();

    // Simulate decryption on "other side"
    let decrypted = cipher.decrypt(&encrypted).unwrap();

    // Server TUN receives the decapsulated packet
    server_tun.send(&decrypted.payload).await.unwrap();

    // Verify server received correct IP packet
    let server_capture = server_tun.capture();
    assert_eq!(server_capture.sent_count(), 1);
    let received_on_server = &server_capture.sent_packets()[0];
    let ip_info = received_on_server.ip_info.as_ref().unwrap();
    assert!(ip_info.is_tcp());
    let tcp_info = ip_info.parse_tcp().unwrap();
    assert!(tcp_info.is_syn());
    assert_eq!(tcp_info.dst_port, 80);
    assert_eq!(tcp_info.data, b"GET /index.html");

    // === Server -> Client (response) ===
    let server_to_client = IpPacketBuilder::ipv4()
        .src_v4(10, 0, 0, 2)
        .dst_v4(10, 0, 0, 1)
        .with_tcp(80, 1234, 2000, 1001, 0x12, b"HTTP/1.1 200 OK")
        .build();

    let hop_response = Packet::data(1, server_sid, server_to_client.clone());
    let encrypted_response = cipher.encrypt(&hop_response, 50).unwrap();

    let decrypted_response = cipher.decrypt(&encrypted_response).unwrap();

    // Client TUN receives the response (through the connected pair)
    client_tun.send(&decrypted_response.payload).await.unwrap();

    // Because of the connected pair, server_tun should have it in recv queue
    assert!(server_tun.has_pending_recv());
    let mut buf = vec![0u8; 2000];
    let n = server_tun.recv(&mut buf).await.unwrap();

    // Verify the response packet
    let response_ip_info =
        hop_protocol::transport::mock::IpPacketInfo::parse(&buf[..n]).unwrap();
    assert!(response_ip_info.is_tcp());
    let response_tcp = response_ip_info.parse_tcp().unwrap();
    assert!(response_tcp.is_syn());
    assert!(response_tcp.is_ack());
}

/// Test protocol correctness with handshake over mock transport
#[tokio::test]
async fn test_handshake_over_mock_transport() {
    let key = b"handshake-mock-test-key";
    let cipher = Cipher::new(key);

    let client_tun = MockTunDevice::new("tun-client", 1400);
    let server_tun = MockTunDevice::new("tun-server", 1400);

    let client_udp = Arc::new(MockUdpSocket::new("10.0.0.1:5000".parse().unwrap()));
    let server_udp = Arc::new(MockUdpSocket::new("10.0.0.2:5000".parse().unwrap()));
    MockUdpSocket::connect_pair(&client_udp, &server_udp);

    // === Phase 1: Port Knocking ===
    let mut client_session = Session::new_client();
    let client_sid = client_session.id.value();

    let knock = Packet::knock(client_sid);
    let encrypted_knock = cipher.encrypt(&knock, 0).unwrap();

    let server_addr = server_udp.local_addr().unwrap();
    client_udp
        .send_to(&encrypted_knock, server_addr)
        .await
        .unwrap();

    // Server receives knock
    let mut buf = vec![0u8; 2000];
    let (n, from_addr) = server_udp.recv_from(&mut buf).await.unwrap();
    let knock_packet = cipher.decrypt(&buf[..n]).unwrap();

    assert!(knock_packet.header.flag.is_push());
    let received_sid = knock_packet.parse_sid_payload().unwrap();
    assert_eq!(received_sid, client_sid);

    // Server creates session
    let mut server_session = Session::new_server(SessionId::new(received_sid));

    // === Phase 2: Handshake Request ===
    client_session.start_handshake().unwrap();
    let hs_req = Packet::handshake_request(client_sid);
    let encrypted_hs_req = cipher.encrypt(&hs_req, 0).unwrap();
    client_udp
        .send_to(&encrypted_hs_req, server_addr)
        .await
        .unwrap();

    let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();
    let hs_req_packet = cipher.decrypt(&buf[..n]).unwrap();
    assert!(hs_req_packet.header.flag.is_handshake());
    assert!(!hs_req_packet.header.flag.is_ack());

    // === Phase 3: Handshake Response ===
    server_session.start_handshake().unwrap();
    let assigned_ip = [10, 1, 1, 100];
    let mask = 24;
    let hs_resp = Packet::handshake_response(client_sid, assigned_ip, mask);
    let encrypted_hs_resp = cipher.encrypt(&hs_resp, 0).unwrap();
    server_udp
        .send_to(&encrypted_hs_resp, from_addr)
        .await
        .unwrap();

    let (n, _) = client_udp.recv_from(&mut buf).await.unwrap();
    let hs_resp_packet = cipher.decrypt(&buf[..n]).unwrap();
    assert!(hs_resp_packet.header.flag.is_handshake_ack());

    let (version, ip, recv_mask) = hs_resp_packet.parse_handshake_response().unwrap();
    assert_eq!(version, hop_protocol::HOP_PROTO_VERSION);
    assert_eq!(ip, assigned_ip);
    assert_eq!(recv_mask, mask);

    // === Phase 4: Handshake Confirm ===
    let hs_confirm = Packet::handshake_confirm(client_sid);
    let encrypted_confirm = cipher.encrypt(&hs_confirm, 0).unwrap();
    client_udp
        .send_to(&encrypted_confirm, server_addr)
        .await
        .unwrap();
    client_session.complete_handshake(ip, recv_mask).unwrap();

    let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();
    let confirm_packet = cipher.decrypt(&buf[..n]).unwrap();
    assert!(confirm_packet.header.flag.is_handshake_ack());
    server_session
        .complete_handshake(assigned_ip, mask)
        .unwrap();

    // Both should be in Working state
    assert_eq!(client_session.state, SessionState::Working);
    assert_eq!(server_session.state, SessionState::Working);

    // === Phase 5: Data Transfer ===
    // Now send actual IP traffic through the established tunnel
    let test_packet = IpPacketBuilder::ipv4()
        .src_v4(10, 1, 1, 100) // Assigned IP
        .dst_v4(93, 184, 216, 34) // example.com
        .with_tcp(54321, 443, 1, 0, 0x02, b"TLS ClientHello")
        .build();

    client_tun.inject_recv_packet(test_packet.clone());

    let n = client_tun.recv(&mut buf).await.unwrap();
    let hop_data = Packet::data(client_session.next_sequence(), client_sid, buf[..n].to_vec());
    let encrypted_data = cipher.encrypt(&hop_data, 100).unwrap();
    client_udp
        .send_to(&encrypted_data, server_addr)
        .await
        .unwrap();

    let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();
    let data_packet = cipher.decrypt(&buf[..n]).unwrap();
    assert!(data_packet.header.flag.is_data());

    // Send to server TUN
    server_tun.send(&data_packet.payload).await.unwrap();

    // Verify
    let capture = server_tun.capture();
    assert_eq!(capture.sent_count(), 1);
    let sent = &capture.sent_packets()[0];
    assert_eq!(sent.data, test_packet);

    let ip_info = sent.ip_info.as_ref().unwrap();
    assert!(ip_info.is_tcp());
    let tcp_info = ip_info.parse_tcp().unwrap();
    assert!(tcp_info.is_syn());
    assert_eq!(tcp_info.dst_port, 443);
}

/// Test fragmentation with mock transport
#[tokio::test]
async fn test_fragmentation_over_mock_transport() {
    let key = b"fragmentation-mock-key";
    let cipher = Cipher::new(key);

    let client_tun = MockTunDevice::new("tun-client", 1400);
    let server_tun = MockTunDevice::new("tun-server", 1400);

    let client_udp = Arc::new(MockUdpSocket::new("10.0.0.1:5000".parse().unwrap()));
    let server_udp = Arc::new(MockUdpSocket::new("10.0.0.2:5000".parse().unwrap()));
    MockUdpSocket::connect_pair(&client_udp, &server_udp);

    let client_sid = 0xF8A60001;

    // Create a large IP packet that will need fragmentation
    let large_payload: Vec<u8> = (0..800).map(|i| (i % 256) as u8).collect();
    let large_ip_packet = IpPacketBuilder::ipv4()
        .src_v4(10, 0, 0, 1)
        .dst_v4(10, 0, 0, 2)
        .payload(large_payload.clone())
        .build();

    client_tun.inject_recv_packet(large_ip_packet.clone());

    // Read from TUN
    let mut buf = vec![0u8; 2000];
    let n = client_tun.recv(&mut buf).await.unwrap();
    let ip_packet = buf[..n].to_vec();

    // Create hop protocol packet
    let hop_packet = Packet::data(1, client_sid, ip_packet.clone());

    // Fragment it (small fragment size to force fragmentation)
    let fragments = fragment_packet(&hop_packet, HOP_HDR_LEN + 100).unwrap();
    assert!(
        fragments.len() > 1,
        "Expected multiple fragments, got {}",
        fragments.len()
    );

    println!(
        "Large packet ({} bytes) split into {} fragments",
        ip_packet.len(),
        fragments.len()
    );

    // Send all fragments
    let server_addr = server_udp.local_addr().unwrap();
    for frag in &fragments {
        let encrypted = cipher.encrypt(frag, 0).unwrap();
        client_udp.send_to(&encrypted, server_addr).await.unwrap();
    }

    // Server receives and reassembles
    let mut assembler = FragmentAssembler::new();
    let mut reassembled = None;

    for _ in 0..fragments.len() {
        let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();
        let decrypted = cipher.decrypt(&buf[..n]).unwrap();

        if let Ok(Some(packet)) = assembler.process(decrypted) {
            reassembled = Some(packet);
        }
    }

    let reassembled = reassembled.expect("Should reassemble all fragments");
    assert_eq!(reassembled.payload, ip_packet);

    // Send reassembled IP packet to server TUN
    server_tun.send(&reassembled.payload).await.unwrap();

    // Verify
    let capture = server_tun.capture();
    assert_eq!(capture.sent_count(), 1);
    assert_eq!(capture.sent_packets()[0].data, large_ip_packet);
}

/// Test payload analysis capabilities
#[tokio::test]
async fn test_payload_analysis() {
    let device = MockTunDevice::new("tun0", 1500);

    // Inject various packet types
    let udp_packet = IpPacketBuilder::ipv4()
        .src_v4(192, 168, 1, 1)
        .dst_v4(8, 8, 8, 8)
        .with_udp(12345, 53, b"DNS query")
        .build();

    let tcp_syn = IpPacketBuilder::ipv4()
        .src_v4(192, 168, 1, 1)
        .dst_v4(93, 184, 216, 34)
        .with_tcp(54321, 80, 1000, 0, 0x02, b"")
        .build();

    let tcp_data = IpPacketBuilder::ipv4()
        .src_v4(192, 168, 1, 1)
        .dst_v4(93, 184, 216, 34)
        .with_tcp(54321, 80, 1001, 5001, 0x18, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .build();

    let icmp_packet = IpPacketBuilder::ipv4()
        .src_v4(192, 168, 1, 1)
        .dst_v4(8, 8, 8, 8)
        .icmp()
        .payload(vec![8, 0, 0, 0, 0, 1, 0, 1]) // ICMP echo request
        .build();

    // Send all packets
    device.send(&udp_packet).await.unwrap();
    device.send(&tcp_syn).await.unwrap();
    device.send(&tcp_data).await.unwrap();
    device.send(&icmp_packet).await.unwrap();

    // Analyze capture
    let capture = device.capture();
    assert_eq!(capture.sent_count(), 4);

    // Filter by protocol
    let udp_packets = capture.sent_udp();
    assert_eq!(udp_packets.len(), 1);
    let udp_info = udp_packets[0].ip_info.as_ref().unwrap();
    let udp_header = udp_info.parse_udp().unwrap();
    assert_eq!(udp_header.dst_port, 53);
    assert_eq!(udp_header.data, b"DNS query");

    let tcp_packets = capture.sent_tcp();
    assert_eq!(tcp_packets.len(), 2);

    // Analyze TCP packets
    let syn_info = tcp_packets[0].ip_info.as_ref().unwrap();
    let syn_tcp = syn_info.parse_tcp().unwrap();
    assert!(syn_tcp.is_syn());
    assert!(!syn_tcp.is_ack());

    let data_info = tcp_packets[1].ip_info.as_ref().unwrap();
    let data_tcp = data_info.parse_tcp().unwrap();
    assert!(data_tcp.is_psh());
    assert!(data_tcp.is_ack());
    assert!(String::from_utf8_lossy(&data_tcp.data).contains("GET /"));

    // Check total bytes
    let total = capture.total_sent_bytes();
    println!("Total bytes sent: {}", total);
    assert!(total > 0);
}

/// Test IPv6 packet handling
#[tokio::test]
async fn test_ipv6_over_mock_transport() {
    let key = b"ipv6-mock-test-key";
    let cipher = Cipher::new(key);

    let client_tun = MockTunDevice::new("tun-client", 1400);
    let server_tun = MockTunDevice::new("tun-server", 1400);

    let client_sid = 0x1B060001;

    // Create IPv6 packet
    let ipv6_packet = IpPacketBuilder::ipv6()
        .src(hop_protocol::transport::mock::IpAddr::V6(
            "fd00::1".parse().unwrap(),
        ))
        .dst(hop_protocol::transport::mock::IpAddr::V6(
            "fd00::2".parse().unwrap(),
        ))
        .with_udp(5000, 443, b"QUIC initial packet")
        .build();

    client_tun.inject_recv_packet(ipv6_packet.clone());

    // Read and encapsulate
    let mut buf = vec![0u8; 2000];
    let n = client_tun.recv(&mut buf).await.unwrap();

    // Verify IPv6 was read correctly
    let capture = client_tun.capture();
    let recv_pkt = &capture.received_packets()[0];
    let ip_info = recv_pkt.ip_info.as_ref().unwrap();
    assert_eq!(ip_info.version, 6);
    assert!(ip_info.is_udp());

    // Encapsulate and encrypt
    let hop_packet = Packet::data(1, client_sid, buf[..n].to_vec());
    let encrypted = cipher.encrypt(&hop_packet, 0).unwrap();

    // Decrypt and decapsulate
    let decrypted = cipher.decrypt(&encrypted).unwrap();
    server_tun.send(&decrypted.payload).await.unwrap();

    // Verify
    let server_capture = server_tun.capture();
    assert_eq!(server_capture.sent_count(), 1);
    let sent = &server_capture.sent_packets()[0];
    assert_eq!(sent.data, ipv6_packet);

    let sent_info = sent.ip_info.as_ref().unwrap();
    assert_eq!(sent_info.version, 6);
    let udp_info = sent_info.parse_udp().unwrap();
    assert_eq!(udp_info.data, b"QUIC initial packet");
}

/// Test wrong key rejection with mock transport
#[tokio::test]
async fn test_wrong_key_rejection_mock_transport() {
    let correct_key = b"correct-key-12345";
    let wrong_key = b"wrong-key-999999";

    let client_cipher = Cipher::new(correct_key);
    let server_cipher = Cipher::new(wrong_key);

    let client_udp = Arc::new(MockUdpSocket::new("10.0.0.1:5000".parse().unwrap()));
    let server_udp = Arc::new(MockUdpSocket::new("10.0.0.2:5000".parse().unwrap()));
    MockUdpSocket::connect_pair(&client_udp, &server_udp);

    // Client sends with correct key
    let packet = Packet::data(1, 0x1234, b"secret data".to_vec());
    let encrypted = client_cipher.encrypt(&packet, 0).unwrap();

    let server_addr = server_udp.local_addr().unwrap();
    client_udp.send_to(&encrypted, server_addr).await.unwrap();

    // Server with wrong key tries to decrypt
    let mut buf = vec![0u8; 2000];
    let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();

    let result = server_cipher.decrypt(&buf[..n]);
    assert!(
        result.is_err(),
        "Should reject packet encrypted with different key"
    );
}

/// Test device up/down state
#[tokio::test]
async fn test_device_state() {
    let device = MockTunDevice::new("tun0", 1500);

    // Device is up by default
    assert!(device.is_up());

    // Can send/recv when up
    device.inject_recv_packet(vec![1, 2, 3]);
    let mut buf = [0u8; 100];
    assert!(device.recv(&mut buf).await.is_ok());
    assert!(device.send(&[4, 5, 6]).await.is_ok());

    // Bring device down
    device.set_up(false);
    assert!(!device.is_up());

    // Operations should fail when down
    device.inject_recv_packet(vec![7, 8, 9]);
    assert!(device.recv(&mut buf).await.is_err());
    assert!(device.send(&[10, 11, 12]).await.is_err());

    // Bring back up
    device.set_up(true);
    assert!(device.recv(&mut buf).await.is_ok()); // Should get the packet injected earlier
}

/// Test MTU enforcement
#[tokio::test]
async fn test_mtu_enforcement() {
    let device = MockTunDevice::new("tun0", 100);

    // Packet within MTU should work
    let small_packet = vec![0u8; 50];
    assert!(device.send(&small_packet).await.is_ok());

    // Packet at exactly MTU should work
    let exact_packet = vec![0u8; 100];
    assert!(device.send(&exact_packet).await.is_ok());

    // Packet exceeding MTU should fail
    let large_packet = vec![0u8; 101];
    let result = device.send(&large_packet).await;
    assert!(result.is_err());
}

/// Test concurrent packet handling
#[tokio::test]
async fn test_concurrent_packet_handling() {
    let device = Arc::new(MockTunDevice::new("tun0", 1500));
    let key = b"concurrent-test-key";
    let cipher = Cipher::new(key);

    // Inject multiple packets
    for i in 0..100 {
        let packet = IpPacketBuilder::ipv4()
            .src_v4(10, 0, 0, 1)
            .dst_v4(10, 0, 0, 2)
            .with_udp(1000 + i as u16, 80, format!("packet {}", i).as_bytes())
            .build();
        device.inject_recv_packet(packet);
    }

    assert_eq!(device.pending_recv_count(), 100);

    // Process all packets
    let mut buf = vec![0u8; 2000];
    let mut processed = 0;

    while device.has_pending_recv() {
        let n = device.recv(&mut buf).await.unwrap();

        // Encapsulate and encrypt
        let hop_packet = Packet::data(processed, 0x1234, buf[..n].to_vec());
        let _encrypted = cipher.encrypt(&hop_packet, 0).unwrap();

        processed += 1;
    }

    assert_eq!(processed, 100);

    // Verify capture
    let capture = device.capture();
    assert_eq!(capture.received_count(), 100);
}

/// Test session lifecycle with transport
#[tokio::test]
async fn test_session_lifecycle_with_transport() {
    let key = b"session-lifecycle-key";
    let cipher = Cipher::new(key);

    let client_udp = Arc::new(MockUdpSocket::new("10.0.0.1:5000".parse().unwrap()));
    let server_udp = Arc::new(MockUdpSocket::new("10.0.0.2:5000".parse().unwrap()));
    MockUdpSocket::connect_pair(&client_udp, &server_udp);

    let server_addr = server_udp.local_addr().unwrap();
    let client_addr = client_udp.local_addr().unwrap();

    let mut buf = vec![0u8; 2000];

    // === INIT -> HANDSHAKE ===
    let mut client_session = Session::new_client();
    let client_sid = client_session.id.value();
    assert_eq!(client_session.state, SessionState::Init);

    // Knock
    let knock = Packet::knock(client_sid);
    client_udp
        .send_to(&cipher.encrypt(&knock, 0).unwrap(), server_addr)
        .await
        .unwrap();

    let (n, from) = server_udp.recv_from(&mut buf).await.unwrap();
    let knock_pkt = cipher.decrypt(&buf[..n]).unwrap();
    let sid = knock_pkt.parse_sid_payload().unwrap();
    let mut server_session = Session::new_server(SessionId::new(sid));
    assert_eq!(server_session.state, SessionState::Init);

    // Start handshake
    client_session.start_handshake().unwrap();
    server_session.start_handshake().unwrap();
    assert_eq!(client_session.state, SessionState::Handshake);
    assert_eq!(server_session.state, SessionState::Handshake);

    // Exchange handshake packets
    let hs_req = Packet::handshake_request(client_sid);
    client_udp
        .send_to(&cipher.encrypt(&hs_req, 0).unwrap(), server_addr)
        .await
        .unwrap();
    server_udp.recv_from(&mut buf).await.unwrap();

    let hs_resp = Packet::handshake_response(client_sid, [10, 0, 0, 100], 24);
    server_udp
        .send_to(&cipher.encrypt(&hs_resp, 0).unwrap(), from)
        .await
        .unwrap();
    client_udp.recv_from(&mut buf).await.unwrap();

    // === HANDSHAKE -> WORKING ===
    let hs_confirm = Packet::handshake_confirm(client_sid);
    client_udp
        .send_to(&cipher.encrypt(&hs_confirm, 0).unwrap(), server_addr)
        .await
        .unwrap();
    client_session
        .complete_handshake([10, 0, 0, 100], 24)
        .unwrap();

    server_udp.recv_from(&mut buf).await.unwrap();
    server_session
        .complete_handshake([10, 0, 0, 100], 24)
        .unwrap();

    assert_eq!(client_session.state, SessionState::Working);
    assert_eq!(server_session.state, SessionState::Working);

    // Data transfer in WORKING state
    let data = Packet::data(
        client_session.next_sequence(),
        client_sid,
        b"tunnel data".to_vec(),
    );
    client_udp
        .send_to(&cipher.encrypt(&data, 0).unwrap(), server_addr)
        .await
        .unwrap();

    let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();
    let data_pkt = cipher.decrypt(&buf[..n]).unwrap();
    assert!(data_pkt.header.flag.is_data());
    assert_eq!(data_pkt.payload, b"tunnel data");

    // === WORKING -> FIN ===
    let fin_req = Packet::finish_request(client_sid);
    client_udp
        .send_to(&cipher.encrypt(&fin_req, 0).unwrap(), server_addr)
        .await
        .unwrap();
    client_session.start_finish().unwrap();

    let (n, _) = server_udp.recv_from(&mut buf).await.unwrap();
    let fin_pkt = cipher.decrypt(&buf[..n]).unwrap();
    assert!(fin_pkt.header.flag.is_finish());

    let fin_ack = Packet::finish_ack(client_sid);
    server_udp
        .send_to(&cipher.encrypt(&fin_ack, 0).unwrap(), client_addr)
        .await
        .unwrap();
    server_session.start_finish().unwrap();

    assert_eq!(client_session.state, SessionState::Fin);
    assert_eq!(server_session.state, SessionState::Fin);
}
