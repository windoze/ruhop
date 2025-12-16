//! Packet flags for the hop protocol

use std::fmt;

/// Packet flag constants
pub mod consts {
    /// Data packet
    pub const HOP_FLG_DAT: u8 = 0x00;
    /// Port knock / Heartbeat
    pub const HOP_FLG_PSH: u8 = 0x80;
    /// Handshake
    pub const HOP_FLG_HSH: u8 = 0x40;
    /// Finish session
    pub const HOP_FLG_FIN: u8 = 0x20;
    /// More fragments follow
    pub const HOP_FLG_MFR: u8 = 0x08;
    /// Acknowledgment
    pub const HOP_FLG_ACK: u8 = 0x04;
}

/// Packet flags wrapper with helper methods
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    /// Create new flags from raw byte
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Data packet
    pub const fn data() -> Self {
        Self(consts::HOP_FLG_DAT)
    }

    /// Port knock / Heartbeat packet
    pub const fn push() -> Self {
        Self(consts::HOP_FLG_PSH)
    }

    /// Handshake packet
    pub const fn handshake() -> Self {
        Self(consts::HOP_FLG_HSH)
    }

    /// Finish packet
    pub const fn finish() -> Self {
        Self(consts::HOP_FLG_FIN)
    }

    /// Check if this is a data packet (no control flags set)
    pub const fn is_data(&self) -> bool {
        self.0 & (consts::HOP_FLG_PSH | consts::HOP_FLG_HSH | consts::HOP_FLG_FIN) == 0
    }

    /// Check if PSH (push/knock/heartbeat) flag is set
    pub const fn is_push(&self) -> bool {
        self.0 & consts::HOP_FLG_PSH != 0
    }

    /// Check if HSH (handshake) flag is set
    pub const fn is_handshake(&self) -> bool {
        self.0 & consts::HOP_FLG_HSH != 0
    }

    /// Check if FIN (finish) flag is set
    pub const fn is_finish(&self) -> bool {
        self.0 & consts::HOP_FLG_FIN != 0
    }

    /// Check if MFR (more fragments) flag is set
    pub const fn is_more_fragments(&self) -> bool {
        self.0 & consts::HOP_FLG_MFR != 0
    }

    /// Check if ACK flag is set
    pub const fn is_ack(&self) -> bool {
        self.0 & consts::HOP_FLG_ACK != 0
    }

    /// Set the ACK flag
    pub const fn with_ack(self) -> Self {
        Self(self.0 | consts::HOP_FLG_ACK)
    }

    /// Set the MFR flag
    pub const fn with_more_fragments(self) -> Self {
        Self(self.0 | consts::HOP_FLG_MFR)
    }

    /// Set the FIN flag
    pub const fn with_finish(self) -> Self {
        Self(self.0 | consts::HOP_FLG_FIN)
    }

    /// Get raw byte value
    pub const fn as_u8(&self) -> u8 {
        self.0
    }

    /// Check if this is a handshake error (HSH | FIN)
    pub const fn is_handshake_error(&self) -> bool {
        self.is_handshake() && self.is_finish()
    }

    /// Check if this is a handshake acknowledgment (HSH | ACK)
    pub const fn is_handshake_ack(&self) -> bool {
        self.is_handshake() && self.is_ack() && !self.is_finish()
    }

    /// Check if this is a finish acknowledgment (FIN | ACK)
    pub const fn is_finish_ack(&self) -> bool {
        self.is_finish() && self.is_ack() && !self.is_handshake()
    }

    /// Check if this is a push acknowledgment (PSH | ACK)
    pub const fn is_push_ack(&self) -> bool {
        self.is_push() && self.is_ack()
    }
}

impl From<u8> for Flags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Flags> for u8 {
    fn from(flags: Flags) -> Self {
        flags.0
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if self.is_push() {
            parts.push("PSH");
        }
        if self.is_handshake() {
            parts.push("HSH");
        }
        if self.is_finish() {
            parts.push("FIN");
        }
        if self.is_more_fragments() {
            parts.push("MFR");
        }
        if self.is_ack() {
            parts.push("ACK");
        }

        if parts.is_empty() {
            write!(f, "DAT")
        } else {
            write!(f, "{}", parts.join("|"))
        }
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_combinations() {
        // Data packet
        let flags = Flags::data();
        assert!(flags.is_data());
        assert!(!flags.is_push());
        assert_eq!(flags.as_u8(), 0x00);

        // Heartbeat request
        let flags = Flags::push();
        assert!(flags.is_push());
        assert!(!flags.is_ack());
        assert_eq!(flags.as_u8(), 0x80);

        // Heartbeat ack
        let flags = Flags::push().with_ack();
        assert!(flags.is_push());
        assert!(flags.is_ack());
        assert!(flags.is_push_ack());
        assert_eq!(flags.as_u8(), 0x84);

        // Handshake request
        let flags = Flags::handshake();
        assert!(flags.is_handshake());
        assert_eq!(flags.as_u8(), 0x40);

        // Handshake ack
        let flags = Flags::handshake().with_ack();
        assert!(flags.is_handshake_ack());
        assert_eq!(flags.as_u8(), 0x44);

        // Handshake error
        let flags = Flags::handshake().with_finish();
        assert!(flags.is_handshake_error());
        assert_eq!(flags.as_u8(), 0x60);

        // Finish request
        let flags = Flags::finish();
        assert!(flags.is_finish());
        assert_eq!(flags.as_u8(), 0x20);

        // Finish ack
        let flags = Flags::finish().with_ack();
        assert!(flags.is_finish_ack());
        assert_eq!(flags.as_u8(), 0x24);

        // Fragmented data
        let flags = Flags::data().with_more_fragments();
        assert!(flags.is_data());
        assert!(flags.is_more_fragments());
        assert_eq!(flags.as_u8(), 0x08);
    }

    #[test]
    fn test_flag_display() {
        assert_eq!(format!("{}", Flags::data()), "DAT");
        assert_eq!(format!("{}", Flags::push()), "PSH");
        assert_eq!(format!("{}", Flags::push().with_ack()), "PSH|ACK");
        assert_eq!(format!("{}", Flags::handshake().with_finish()), "HSH|FIN");
    }
}
