//! Packet fragmentation and reassembly

use std::collections::HashMap;

use crate::{Error, Flags, Packet, PacketHeader, Result, HOP_HDR_LEN};

/// A fragmented packet being assembled
#[derive(Debug, Clone)]
pub struct FragmentedPacket {
    /// Sequence number (used to correlate fragments)
    pub seq: u32,
    /// Session ID
    pub sid: u32,
    /// Total payload length
    pub total_len: u16,
    /// Received fragments indexed by fragment number
    fragments: HashMap<u8, Vec<u8>>,
    /// Total bytes received so far
    bytes_received: usize,
}

impl FragmentedPacket {
    /// Create a new fragmented packet tracker
    pub fn new(seq: u32, sid: u32, total_len: u16) -> Self {
        Self {
            seq,
            sid,
            total_len,
            fragments: HashMap::new(),
            bytes_received: 0,
        }
    }

    /// Add a fragment
    /// Returns true if this was a new fragment
    pub fn add_fragment(&mut self, frag_index: u8, data: Vec<u8>) -> bool {
        if self.fragments.contains_key(&frag_index) {
            return false;
        }
        self.bytes_received += data.len();
        self.fragments.insert(frag_index, data);
        true
    }

    /// Check if all fragments have been received
    pub fn is_complete(&self) -> bool {
        self.bytes_received >= self.total_len as usize
    }

    /// Reassemble the complete payload
    /// Returns None if not all fragments received
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        // Sort fragments by index and concatenate
        let mut indices: Vec<_> = self.fragments.keys().copied().collect();
        indices.sort();

        let mut payload = Vec::with_capacity(self.total_len as usize);
        for idx in indices {
            payload.extend_from_slice(&self.fragments[&idx]);
        }

        // Truncate to exact total length
        payload.truncate(self.total_len as usize);
        Some(payload)
    }

    /// Get the number of fragments received
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
}

/// Assembler for handling fragmented packets
#[derive(Debug, Default)]
pub struct FragmentAssembler {
    /// Packets being assembled, keyed by sequence number
    pending: HashMap<u32, FragmentedPacket>,
}

impl FragmentAssembler {
    /// Create a new fragment assembler
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Process an incoming packet
    ///
    /// Returns the complete packet if reassembly is done, or None if still waiting for fragments
    pub fn process(&mut self, packet: Packet) -> Result<Option<Packet>> {
        let header = &packet.header;

        // Non-fragmented packet (MFR not set and frag == 0)
        if !header.flag.is_more_fragments() && header.frag == 0 && header.frag_prefix == 0 {
            return Ok(Some(packet));
        }

        // Get or create the fragmented packet tracker
        let seq = header.seq;
        let entry = self
            .pending
            .entry(seq)
            .or_insert_with(|| FragmentedPacket::new(seq, header.sid, header.plen));

        // Add this fragment
        entry.add_fragment(header.frag, packet.payload);

        // Check if complete
        if entry.is_complete() {
            let fragmented = self.pending.remove(&seq).unwrap();
            if let Some(payload) = fragmented.reassemble() {
                // Create reassembled packet with data flag
                let reassembled_header = PacketHeader {
                    flag: Flags::data(),
                    seq: fragmented.seq,
                    plen: fragmented.total_len,
                    frag_prefix: 0,
                    frag: 0,
                    sid: fragmented.sid,
                    dlen: fragmented.total_len,
                };
                return Ok(Some(Packet::new(reassembled_header, payload)));
            }
        }

        Ok(None)
    }

    /// Clear old pending fragments (for cleanup)
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Remove a specific pending packet (e.g., on timeout)
    pub fn remove(&mut self, seq: u32) -> Option<FragmentedPacket> {
        self.pending.remove(&seq)
    }

    /// Get number of pending fragmented packets
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Fragment a large packet into smaller pieces
pub fn fragment_packet(packet: &Packet, max_fragment_size: usize) -> Result<Vec<Packet>> {
    let payload = &packet.payload;
    let total_len = payload.len();

    if total_len == 0 || max_fragment_size == 0 {
        return Err(Error::Fragment("invalid fragment parameters".to_string()));
    }

    // Calculate max payload per fragment (excluding header)
    let max_payload = max_fragment_size.saturating_sub(HOP_HDR_LEN);
    if max_payload == 0 {
        return Err(Error::Fragment("fragment size too small".to_string()));
    }

    // If packet fits in one fragment, return as-is
    if total_len <= max_payload {
        return Ok(vec![packet.clone()]);
    }

    let mut fragments = Vec::new();
    let mut offset = 0;
    let mut frag_index: u8 = 0;

    while offset < total_len {
        let remaining = total_len - offset;
        let frag_len = remaining.min(max_payload);
        let is_last = offset + frag_len >= total_len;

        let mut flag = Flags::data();
        if !is_last {
            flag = flag.with_more_fragments();
        }

        let header = PacketHeader {
            flag,
            seq: packet.header.seq,
            plen: total_len as u16,
            frag_prefix: offset as u16,
            frag: frag_index,
            sid: packet.header.sid,
            dlen: frag_len as u16,
        };

        let frag_payload = payload[offset..offset + frag_len].to_vec();
        fragments.push(Packet::new(header, frag_payload));

        offset += frag_len;
        frag_index = frag_index.saturating_add(1);
    }

    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_fragmentation_needed() {
        let packet = Packet::data(1, 0x1234, vec![1, 2, 3, 4, 5]);
        let fragments = fragment_packet(&packet, 1000).unwrap();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], packet);
    }

    #[test]
    fn test_fragmentation() {
        let payload: Vec<u8> = (0..100).collect();
        let packet = Packet::data(42, 0xABCD, payload.clone());

        // Fragment into ~30 byte payloads (+ 16 byte header = 46 byte packets)
        let fragments = fragment_packet(&packet, 46).unwrap();

        assert!(fragments.len() > 1);

        // Check first fragment has MFR flag
        assert!(fragments[0].header.flag.is_more_fragments());
        assert_eq!(fragments[0].header.frag, 0);
        assert_eq!(fragments[0].header.frag_prefix, 0);
        assert_eq!(fragments[0].header.plen, 100);

        // Check last fragment doesn't have MFR flag
        let last = fragments.last().unwrap();
        assert!(!last.header.flag.is_more_fragments());

        // Verify total payload size
        let total: usize = fragments.iter().map(|f| f.payload.len()).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn test_reassembly() {
        let payload: Vec<u8> = (0..100).collect();
        let packet = Packet::data(42, 0xABCD, payload.clone());

        let fragments = fragment_packet(&packet, 46).unwrap();

        let mut assembler = FragmentAssembler::new();

        // Process all but last fragment
        for frag in fragments.iter().take(fragments.len() - 1) {
            let result = assembler.process(frag.clone()).unwrap();
            assert!(result.is_none());
        }

        // Process last fragment
        let result = assembler
            .process(fragments.last().unwrap().clone())
            .unwrap();
        assert!(result.is_some());

        let reassembled = result.unwrap();
        assert_eq!(reassembled.payload, payload);
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let payload: Vec<u8> = (0..100).collect();
        let packet = Packet::data(42, 0xABCD, payload.clone());

        let fragments = fragment_packet(&packet, 46).unwrap();

        let mut assembler = FragmentAssembler::new();

        // Process in reverse order
        let mut result = None;
        for frag in fragments.into_iter().rev() {
            if let Some(r) = assembler.process(frag).unwrap() {
                result = Some(r);
            }
        }

        assert!(result.is_some());
        assert_eq!(result.unwrap().payload, payload);
    }

    #[test]
    fn test_non_fragmented_passthrough() {
        let packet = Packet::data(1, 0x1234, vec![1, 2, 3]);
        let mut assembler = FragmentAssembler::new();

        let result = assembler.process(packet.clone()).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), packet);
    }

    #[test]
    fn test_duplicate_fragment_ignored() {
        let payload: Vec<u8> = (0..100).collect();
        let packet = Packet::data(42, 0xABCD, payload);

        let fragments = fragment_packet(&packet, 46).unwrap();

        let mut fp = FragmentedPacket::new(42, 0xABCD, 100);

        // Add first fragment
        assert!(fp.add_fragment(0, fragments[0].payload.clone()));

        // Adding same fragment again should return false
        assert!(!fp.add_fragment(0, fragments[0].payload.clone()));
    }
}
