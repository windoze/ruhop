//! Session state management

use crate::{AssignedAddress, AssignedAddresses, IpAddress};
use std::fmt;

/// Session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

impl SessionId {
    /// Generate a random session ID
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Create from raw value
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get the raw value
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Create from bytes (big-endian)
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Create a session key combining SID and IPv4 address for routing (legacy)
    /// Upper 32 bits: SID, Lower 32 bits: IP address
    pub fn make_key(&self, ip: u32) -> u64 {
        ((self.0 as u64) << 32) | (ip as u64)
    }

    /// Create a session key combining SID and any IP address for routing
    /// For IPv4: Upper 32 bits: SID, Lower 32 bits: IP address (returns u64)
    /// For IPv6: Uses 128-bit hash combining SID and IP
    /// Returns u128 to accommodate both IPv4 and IPv6
    pub fn make_key_v2(&self, ip: &IpAddress) -> u128 {
        match ip {
            IpAddress::V4(_) => {
                // For IPv4, zero-extend to u128 for compatibility
                let ip_u32 = ip.to_u128() as u32;
                (((self.0 as u64) << 32) | (ip_u32 as u64)) as u128
            }
            IpAddress::V6(_) => {
                // For IPv6, combine SID into upper bits of u128
                let ip_u128 = ip.to_u128();
                // XOR SID into upper 32 bits to create unique key
                ip_u128 ^ ((self.0 as u128) << 96)
            }
        }
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}", self.0)
    }
}

impl From<u32> for SessionId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SessionId> for u32 {
    fn from(sid: SessionId) -> Self {
        sid.0
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum SessionState {
    /// Initial state, not connected
    #[default]
    Init = 0,
    /// Handshake in progress
    Handshake = 1,
    /// Session established, data transfer active
    Working = 2,
    /// Session terminating
    Fin = 3,
}

impl SessionState {
    /// Check if data transfer is allowed in this state
    pub const fn can_transfer_data(&self) -> bool {
        matches!(self, SessionState::Working)
    }

    /// Check if the session is active (not init or fin)
    pub const fn is_active(&self) -> bool {
        matches!(self, SessionState::Handshake | SessionState::Working)
    }

    /// Check if the session is terminated or terminating
    pub const fn is_finished(&self) -> bool {
        matches!(self, SessionState::Fin)
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Init => write!(f, "INIT"),
            SessionState::Handshake => write!(f, "HANDSHAKE"),
            SessionState::Working => write!(f, "WORKING"),
            SessionState::Fin => write!(f, "FIN"),
        }
    }
}

/// Session state machine for tracking connection state
#[derive(Debug, Clone)]
pub struct Session {
    /// Session ID
    pub id: SessionId,
    /// Current state
    pub state: SessionState,
    /// Assigned IP addresses (set after handshake) - supports multiple addresses for IP hopping
    /// The first address is the primary address used for TUN interface
    pub assigned_addresses: Option<AssignedAddresses>,
    /// Next sequence number for outgoing packets
    pub next_seq: u32,
    /// Last received sequence number
    pub last_recv_seq: u32,
    /// Handshake retry count
    pub handshake_retries: u8,
}

impl Session {
    /// Maximum handshake retries before timeout
    pub const MAX_HANDSHAKE_RETRIES: u8 = 5;

    /// Create a new client session
    pub fn new_client() -> Self {
        Self {
            id: SessionId::random(),
            state: SessionState::Init,
            assigned_addresses: None,
            next_seq: 0,
            last_recv_seq: 0,
            handshake_retries: 0,
        }
    }

    /// Create a new server session for a peer
    pub fn new_server(sid: SessionId) -> Self {
        Self {
            id: sid,
            state: SessionState::Init,
            assigned_addresses: None,
            next_seq: 0,
            last_recv_seq: 0,
            handshake_retries: 0,
        }
    }

    /// Transition to handshake state (after port knocking)
    pub fn start_handshake(&mut self) -> crate::Result<()> {
        match self.state {
            SessionState::Init => {
                self.state = SessionState::Handshake;
                Ok(())
            }
            _ => Err(crate::Error::InvalidStateTransition {
                from: self.state,
                to: SessionState::Handshake,
            }),
        }
    }

    /// Complete handshake and transition to working state (legacy IPv4 version)
    pub fn complete_handshake(&mut self, ip: [u8; 4], mask: u8) -> crate::Result<()> {
        self.complete_handshake_v2(IpAddress::from_ipv4_bytes(ip), mask)
    }

    /// Complete handshake and transition to working state with IPv4/IPv6 support (single address)
    pub fn complete_handshake_v2(&mut self, ip: IpAddress, mask: u8) -> crate::Result<()> {
        self.complete_handshake_v3(AssignedAddresses::single(ip, mask))
    }

    /// Complete handshake and transition to working state with multi-address support
    pub fn complete_handshake_v3(&mut self, addresses: AssignedAddresses) -> crate::Result<()> {
        match self.state {
            SessionState::Handshake => {
                self.assigned_addresses = Some(addresses);
                self.state = SessionState::Working;
                Ok(())
            }
            _ => Err(crate::Error::InvalidStateTransition {
                from: self.state,
                to: SessionState::Working,
            }),
        }
    }

    /// Start session termination
    pub fn start_finish(&mut self) -> crate::Result<()> {
        match self.state {
            SessionState::Working | SessionState::Handshake => {
                self.state = SessionState::Fin;
                Ok(())
            }
            _ => Err(crate::Error::InvalidStateTransition {
                from: self.state,
                to: SessionState::Fin,
            }),
        }
    }

    /// Get and increment the next sequence number
    pub fn next_sequence(&mut self) -> u32 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// Update the last received sequence number
    pub fn update_recv_seq(&mut self, seq: u32) {
        if seq > self.last_recv_seq || self.last_recv_seq.wrapping_sub(seq) > 0x80000000 {
            self.last_recv_seq = seq;
        }
    }

    /// Increment handshake retry count, returns true if exceeded max
    pub fn increment_handshake_retry(&mut self) -> bool {
        self.handshake_retries += 1;
        self.handshake_retries > Self::MAX_HANDSHAKE_RETRIES
    }

    /// Reset handshake retry count
    pub fn reset_handshake_retries(&mut self) {
        self.handshake_retries = 0;
    }

    /// Get the primary assigned IP as u32 (for session key) - IPv4 only
    pub fn ip_as_u32(&self) -> Option<u32> {
        self.primary_address()
            .and_then(|addr| addr.ip.as_ipv4_bytes())
            .map(u32::from_be_bytes)
    }

    /// Create session routing key (legacy, IPv4 only)
    pub fn routing_key(&self) -> Option<u64> {
        self.ip_as_u32().map(|ip| self.id.make_key(ip))
    }

    /// Create session routing key with IPv4/IPv6 support
    pub fn routing_key_v2(&self) -> Option<u128> {
        self.primary_address()
            .map(|addr| self.id.make_key_v2(&addr.ip))
    }

    /// Get the primary assigned address (first address, used for TUN interface)
    pub fn primary_address(&self) -> Option<&AssignedAddress> {
        self.assigned_addresses.as_ref().map(|a| a.primary())
    }

    /// Get the primary assigned IP address
    pub fn ip_address(&self) -> Option<&IpAddress> {
        self.primary_address().map(|a| &a.ip)
    }

    /// Get the primary subnet mask
    pub fn subnet_mask(&self) -> Option<u8> {
        self.primary_address().map(|a| a.mask)
    }

    /// Get all assigned addresses (for IP hopping)
    pub fn all_addresses(&self) -> Option<&AssignedAddresses> {
        self.assigned_addresses.as_ref()
    }

    /// Get the number of assigned addresses
    pub fn address_count(&self) -> usize {
        self.assigned_addresses.as_ref().map_or(0, |a| a.len())
    }

    /// Check if primary address is IPv6
    pub fn is_ipv6(&self) -> bool {
        self.primary_address().is_some_and(|a| a.ip.is_ipv6())
    }

    /// Check if session has multiple addresses for IP hopping
    pub fn has_multiple_addresses(&self) -> bool {
        self.assigned_addresses
            .as_ref()
            .is_some_and(|a| !a.is_single())
    }

    // Legacy compatibility: assigned_ip getter for backwards compatibility
    #[doc(hidden)]
    pub fn assigned_ip(&self) -> Option<IpAddress> {
        self.ip_address().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id() {
        let sid = SessionId::new(0x12345678);
        assert_eq!(sid.value(), 0x12345678);
        assert_eq!(format!("{}", sid), "12345678");

        let bytes = sid.to_bytes();
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78]);

        let restored = SessionId::from_bytes(bytes);
        assert_eq!(sid, restored);
    }

    #[test]
    fn test_session_key() {
        let sid = SessionId::new(0xDEADBEEF);
        let ip = 0x0A010103; // 10.1.1.3
        let key = sid.make_key(ip);

        assert_eq!(key >> 32, 0xDEADBEEF);
        assert_eq!(key & 0xFFFFFFFF, 0x0A010103);
    }

    #[test]
    fn test_session_key_v2_ipv4() {
        let sid = SessionId::new(0xDEADBEEF);
        let ip = IpAddress::from_ipv4_bytes([10, 1, 1, 3]);
        let key = sid.make_key_v2(&ip);

        // For IPv4, should be same as legacy format (zero-extended to u128)
        let legacy_key = sid.make_key(0x0A010103);
        assert_eq!(key, legacy_key as u128);
    }

    #[test]
    fn test_session_key_v2_ipv6() {
        let sid = SessionId::new(0xDEADBEEF);
        let ip = IpAddress::from_ipv6_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let key = sid.make_key_v2(&ip);

        // Key should incorporate both SID and IPv6 address
        assert_ne!(key, ip.to_u128()); // Not just the IP
        assert_ne!(key, 0); // Not zero

        // Different SIDs should produce different keys for same IP
        let sid2 = SessionId::new(0xCAFEBABE);
        let key2 = sid2.make_key_v2(&ip);
        assert_ne!(key, key2);
    }

    #[test]
    fn test_client_session_lifecycle() {
        let mut session = Session::new_client();
        assert_eq!(session.state, SessionState::Init);

        // Start handshake
        session.start_handshake().unwrap();
        assert_eq!(session.state, SessionState::Handshake);

        // Complete handshake
        session.complete_handshake([10, 1, 1, 5], 24).unwrap();
        assert_eq!(session.state, SessionState::Working);
        assert_eq!(
            session.assigned_ip(),
            Some(IpAddress::from_ipv4_bytes([10, 1, 1, 5]))
        );
        assert_eq!(session.subnet_mask(), Some(24));

        // Finish
        session.start_finish().unwrap();
        assert_eq!(session.state, SessionState::Fin);
    }

    #[test]
    fn test_client_session_lifecycle_ipv6() {
        let mut session = Session::new_client();
        assert_eq!(session.state, SessionState::Init);

        // Start handshake
        session.start_handshake().unwrap();
        assert_eq!(session.state, SessionState::Handshake);

        // Complete handshake with IPv6 address
        let ipv6 = IpAddress::from_ipv6_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x64, // 2001:db8::64
        ]);
        session.complete_handshake_v2(ipv6, 64).unwrap();
        assert_eq!(session.state, SessionState::Working);
        assert_eq!(session.assigned_ip(), Some(ipv6));
        assert_eq!(session.subnet_mask(), Some(64));
        assert!(session.is_ipv6());

        // Legacy IPv4 methods should return None for IPv6 session
        assert!(session.ip_as_u32().is_none());
        assert!(session.routing_key().is_none());

        // But v2 routing key should work
        assert!(session.routing_key_v2().is_some());

        // Finish
        session.start_finish().unwrap();
        assert_eq!(session.state, SessionState::Fin);
    }

    #[test]
    fn test_client_session_multi_address() {
        let mut session = Session::new_client();
        session.start_handshake().unwrap();

        // Complete handshake with multiple addresses
        let addresses = AssignedAddresses::multiple(vec![
            AssignedAddress::from_ipv4([10, 0, 0, 1], 24),
            AssignedAddress::from_ipv4([192, 168, 1, 1], 24),
            AssignedAddress::from_ipv6(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                64,
            ),
        ])
        .unwrap();

        session.complete_handshake_v3(addresses).unwrap();
        assert_eq!(session.state, SessionState::Working);

        // Check primary address
        assert_eq!(
            session.ip_address(),
            Some(&IpAddress::from_ipv4_bytes([10, 0, 0, 1]))
        );
        assert_eq!(session.subnet_mask(), Some(24));

        // Check multi-address support
        assert!(session.has_multiple_addresses());
        assert_eq!(session.address_count(), 3);

        // All addresses should be available
        let all = session.all_addresses().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all.ipv4_addresses().count(), 2);
        assert_eq!(all.ipv6_addresses().count(), 1);
    }

    #[test]
    fn test_invalid_state_transitions() {
        let mut session = Session::new_client();

        // Can't complete handshake from Init
        assert!(session.complete_handshake([10, 0, 0, 1], 24).is_err());

        // Can't finish from Init
        assert!(session.start_finish().is_err());
    }

    #[test]
    fn test_sequence_numbers() {
        let mut session = Session::new_client();

        assert_eq!(session.next_sequence(), 0);
        assert_eq!(session.next_sequence(), 1);
        assert_eq!(session.next_sequence(), 2);

        // Test wrapping
        session.next_seq = u32::MAX;
        assert_eq!(session.next_sequence(), u32::MAX);
        assert_eq!(session.next_sequence(), 0);
    }

    #[test]
    fn test_handshake_retries() {
        let mut session = Session::new_client();

        for _ in 0..Session::MAX_HANDSHAKE_RETRIES {
            assert!(!session.increment_handshake_retry());
        }

        // Exceeds max
        assert!(session.increment_handshake_retry());

        // Reset
        session.reset_handshake_retries();
        assert!(!session.increment_handshake_retry());
    }
}
