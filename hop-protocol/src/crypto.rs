//! Encryption and compression for the hop protocol
//!
//! Uses AES-256-CBC with Snappy compression.
//!
//! ## Obfuscation Mode
//!
//! When obfuscation is enabled, packets are further disguised:
//! - Pre-compression padding: Random bytes appended after the packet data (before compression)
//!   to obscure data length. Since the packet header contains `Dlen`, the receiver knows where
//!   the actual payload ends, so no length prefix is needed.
//! - Post-encryption padding: Random bytes (< block size) prepended before the IV to obscure
//!   the encrypted payload length (which would otherwise be a multiple of block size)
//!
//! Wire format with obfuscation:
//! ```text
//! +------------------+------------------------+------------------+
//! | Post-pad (0-15)  |   IV (16 bytes)        | Encrypted data   |
//! +------------------+------------------------+------------------+
//! ```
//!
//! Pre-compression format (before Snappy compression):
//! ```text
//! +------------------+------------------+
//! | Packet data      | Random padding   |
//! +------------------+------------------+
//! ```
//!
//! The post-encryption padding length is determined by: `total_len % CIPHER_BLOCK_SIZE`
//! Since encrypted data is always block-aligned, any remainder must be the padding.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::Rng;

use crate::{Error, Packet, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES block size / IV size
const CIPHER_BLOCK_SIZE: usize = 16;

/// Cipher for encrypting and decrypting packets
#[derive(Clone)]
pub struct Cipher {
    key: [u8; 32],
    /// Enable packet obfuscation with pre/post encryption padding
    obfuscation: bool,
    /// Maximum pre-encryption padding bytes (default: 16)
    max_pre_padding: usize,
}

impl Cipher {
    /// Create a new cipher from a pre-shared key
    ///
    /// The key will be padded to 32 bytes using PKCS5 padding
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: pkcs5_pad_key(key),
            obfuscation: false,
            max_pre_padding: 16,
        }
    }

    /// Create a new cipher with obfuscation enabled
    ///
    /// When obfuscation is enabled:
    /// - Random padding is added before encryption to obscure data length
    /// - Random padding (< block size) is added after encryption to obscure encrypted length
    pub fn with_obfuscation(key: &[u8]) -> Self {
        Self {
            key: pkcs5_pad_key(key),
            obfuscation: true,
            max_pre_padding: 16,
        }
    }

    /// Set the maximum pre-encryption padding size
    ///
    /// Default is 16 bytes. The actual padding added per packet is random
    /// between 0 and this value.
    pub fn set_max_pre_padding(&mut self, max_bytes: usize) {
        self.max_pre_padding = max_bytes;
    }

    /// Enable or disable obfuscation
    pub fn set_obfuscation(&mut self, enabled: bool) {
        self.obfuscation = enabled;
    }

    /// Returns whether obfuscation is enabled
    pub fn is_obfuscation_enabled(&self) -> bool {
        self.obfuscation
    }

    /// Encrypt a packet
    ///
    /// Process:
    /// 1. Encode packet to bytes (header + payload)
    /// 2. Optionally add noise (already handled by encode_with_noise)
    /// 3. If obfuscation enabled: append random padding to plaintext
    /// 4. Compress with Snappy
    /// 5. Pad to 16-byte boundary (PKCS7)
    /// 6. Encrypt with AES-256-CBC
    /// 7. Prepend IV
    /// 8. If obfuscation enabled: prepend post-encryption padding
    pub fn encrypt(&self, packet: &Packet, max_noise: usize) -> Result<Vec<u8>> {
        // Encode packet with optional noise
        let mut plaintext = packet.encode_with_noise(max_noise);

        // Add pre-compression padding if obfuscation enabled
        // Padding is appended AFTER the packet data - no length prefix needed
        // because the packet header contains Dlen which tells the receiver the actual payload length
        if self.obfuscation && self.max_pre_padding > 0 {
            let mut rng = rand::thread_rng();
            // Random padding length (0 to max_pre_padding)
            let pre_pad_len = rng.gen_range(0..=self.max_pre_padding);
            // Append random bytes after the packet data
            plaintext.extend((0..pre_pad_len).map(|_| rng.gen::<u8>()));
        }

        // Compress
        let compressed =
            snap::raw::Encoder::new()
                .compress_vec(&plaintext)
                .map_err(|e| Error::Compression(e.to_string()))?;

        // Generate random IV
        let iv: [u8; CIPHER_BLOCK_SIZE] = rand::thread_rng().gen();

        // Encrypt with PKCS7 padding
        let cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());

        // Calculate padded size
        let padded_len = ((compressed.len() / CIPHER_BLOCK_SIZE) + 1) * CIPHER_BLOCK_SIZE;
        let mut buffer = vec![0u8; padded_len];
        buffer[..compressed.len()].copy_from_slice(&compressed);

        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, compressed.len())
            .map_err(|e| Error::Encryption(e.to_string()))?;

        // Add post-encryption padding if obfuscation enabled
        if self.obfuscation {
            let mut rng = rand::thread_rng();
            // Random 0 to CIPHER_BLOCK_SIZE-1 bytes of post-encryption padding
            let post_pad_len = rng.gen_range(0..CIPHER_BLOCK_SIZE);
            let mut result = Vec::with_capacity(post_pad_len + CIPHER_BLOCK_SIZE + ciphertext.len());
            // Prepend random post-encryption padding
            result.extend((0..post_pad_len).map(|_| rng.gen::<u8>()));
            result.extend_from_slice(&iv);
            result.extend_from_slice(ciphertext);
            Ok(result)
        } else {
            // No obfuscation - standard format
            let mut result = Vec::with_capacity(CIPHER_BLOCK_SIZE + ciphertext.len());
            result.extend_from_slice(&iv);
            result.extend_from_slice(ciphertext);
            Ok(result)
        }
    }

    /// Decrypt a packet
    ///
    /// Process:
    /// 1. If obfuscation enabled: strip post-encryption padding
    /// 2. Extract IV (first 16 bytes)
    /// 3. Decrypt with AES-256-CBC
    /// 4. Remove PKCS7 padding
    /// 5. Decompress with Snappy
    /// 6. Decode packet (pre-compression padding is automatically ignored via Dlen)
    pub fn decrypt(&self, data: &[u8]) -> Result<Packet> {
        // Strip post-encryption padding if obfuscation enabled
        // Post-encryption padding length = total_len % CIPHER_BLOCK_SIZE
        // because IV is 16 bytes and ciphertext is always block-aligned
        let data = if self.obfuscation {
            let post_pad_len = data.len() % CIPHER_BLOCK_SIZE;
            &data[post_pad_len..]
        } else {
            data
        };

        if data.len() < CIPHER_BLOCK_SIZE {
            return Err(Error::PacketTooShort {
                expected: CIPHER_BLOCK_SIZE,
                actual: data.len(),
            });
        }

        // Extract IV
        let iv: [u8; CIPHER_BLOCK_SIZE] = data[..CIPHER_BLOCK_SIZE]
            .try_into()
            .map_err(|_| Error::Decryption("invalid IV".to_string()))?;

        // Decrypt
        let cipher = Aes256CbcDec::new(&self.key.into(), &iv.into());
        let mut buffer = data[CIPHER_BLOCK_SIZE..].to_vec();

        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| Error::Decryption(e.to_string()))?;

        // Decompress
        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(decrypted)
            .map_err(|e| Error::Decompression(e.to_string()))?;

        // Decode packet
        // Note: The packet header contains Dlen which tells us the actual payload length,
        // so any trailing pre-compression padding bytes are automatically ignored.
        Packet::decode(&decompressed)
    }

    /// Encrypt raw bytes (for testing or custom use)
    pub fn encrypt_raw(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Compress
        let compressed =
            snap::raw::Encoder::new()
                .compress_vec(plaintext)
                .map_err(|e| Error::Compression(e.to_string()))?;

        // Generate random IV
        let iv: [u8; CIPHER_BLOCK_SIZE] = rand::thread_rng().gen();

        // Encrypt
        let cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());
        let padded_len = ((compressed.len() / CIPHER_BLOCK_SIZE) + 1) * CIPHER_BLOCK_SIZE;
        let mut buffer = vec![0u8; padded_len];
        buffer[..compressed.len()].copy_from_slice(&compressed);

        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, compressed.len())
            .map_err(|e| Error::Encryption(e.to_string()))?;

        let mut result = Vec::with_capacity(CIPHER_BLOCK_SIZE + ciphertext.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(ciphertext);

        Ok(result)
    }

    /// Decrypt raw bytes (for testing or custom use)
    pub fn decrypt_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < CIPHER_BLOCK_SIZE {
            return Err(Error::PacketTooShort {
                expected: CIPHER_BLOCK_SIZE,
                actual: data.len(),
            });
        }

        let iv: [u8; CIPHER_BLOCK_SIZE] = data[..CIPHER_BLOCK_SIZE]
            .try_into()
            .map_err(|_| Error::Decryption("invalid IV".to_string()))?;

        let cipher = Aes256CbcDec::new(&self.key.into(), &iv.into());
        let mut buffer = data[CIPHER_BLOCK_SIZE..].to_vec();

        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| Error::Decryption(e.to_string()))?;

        snap::raw::Decoder::new()
            .decompress_vec(decrypted)
            .map_err(|e| Error::Decompression(e.to_string()))
    }
}

/// Pad key to 32 bytes using PKCS5-style padding
fn pkcs5_pad_key(key: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let key_len = key.len().min(32);
    padded[..key_len].copy_from_slice(&key[..key_len]);

    if key_len < 32 {
        let pad_byte = (32 - key_len) as u8;
        for byte in padded.iter_mut().skip(key_len) {
            *byte = pad_byte;
        }
    }

    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs5_pad_key() {
        // Short key
        let key = b"secret";
        let padded = pkcs5_pad_key(key);
        assert_eq!(padded[..6], *b"secret");
        assert!(padded[6..].iter().all(|&b| b == 26)); // 32 - 6 = 26

        // Exact length
        let key = [0xAA; 32];
        let padded = pkcs5_pad_key(&key);
        assert_eq!(padded, key);

        // Too long (truncated)
        let key = [0xBB; 64];
        let padded = pkcs5_pad_key(&key);
        assert!(padded.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_encrypt_decrypt_raw() {
        let cipher = Cipher::new(b"my-secret-key");
        let plaintext = b"Hello, World!";

        let encrypted = cipher.encrypt_raw(plaintext).unwrap();
        let decrypted = cipher.decrypt_raw(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_packet() {
        let cipher = Cipher::new(b"test-key-12345");

        let packet = Packet::data(42, 0x12345678, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let encrypted = cipher.encrypt(&packet, 0).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(packet, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_with_noise() {
        let cipher = Cipher::new(b"noisy-key");

        let packet = Packet::data(1, 0xDEAD, vec![0xCA, 0xFE]);
        let encrypted = cipher.encrypt(&packet, 100).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        // Payload should match even with noise
        assert_eq!(packet.payload, decrypted.payload);
        assert_eq!(packet.header, decrypted.header);
    }

    #[test]
    fn test_wrong_key_fails() {
        let cipher1 = Cipher::new(b"key-one");
        let cipher2 = Cipher::new(b"key-two");

        let packet = Packet::data(1, 1, vec![1, 2, 3]);
        let encrypted = cipher1.encrypt(&packet, 0).unwrap();

        // Decryption with wrong key should fail
        assert!(cipher2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_handshake_packet_roundtrip() {
        let cipher = Cipher::new(b"handshake-key");

        let packet = Packet::handshake_response(0x1234, [10, 0, 0, 1], 24);
        let encrypted = cipher.encrypt(&packet, 0).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        let (version, ip, mask) = decrypted.parse_handshake_response().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(ip, [10, 0, 0, 1]);
        assert_eq!(mask, 24);
    }

    #[test]
    fn test_obfuscation_encrypt_decrypt() {
        let cipher = Cipher::with_obfuscation(b"obfuscation-key");

        let packet = Packet::data(42, 0x12345678, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let encrypted = cipher.encrypt(&packet, 0).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(packet, decrypted);
    }

    #[test]
    fn test_obfuscation_varies_length() {
        let cipher = Cipher::with_obfuscation(b"length-test-key");
        let packet = Packet::data(1, 0x1234, vec![0xAA; 100]);

        // Encrypt multiple times and check lengths vary
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..20 {
            let encrypted = cipher.encrypt(&packet, 0).unwrap();
            lengths.insert(encrypted.len());
        }

        // With obfuscation, lengths should vary due to random padding
        // (pre-encryption padding + post-encryption padding)
        assert!(
            lengths.len() > 1,
            "Expected varying lengths with obfuscation, got {:?}",
            lengths
        );
    }

    #[test]
    fn test_obfuscation_not_block_aligned() {
        let cipher = Cipher::with_obfuscation(b"alignment-test");
        let packet = Packet::data(1, 0x1234, vec![0xBB; 50]);

        // With post-encryption padding, most encrypted lengths should NOT be block-aligned
        let mut non_aligned_count = 0;
        for _ in 0..20 {
            let encrypted = cipher.encrypt(&packet, 0).unwrap();
            if !encrypted.len().is_multiple_of(CIPHER_BLOCK_SIZE) {
                non_aligned_count += 1;
            }
        }

        // Most should be non-aligned (15/16 chance per packet)
        assert!(
            non_aligned_count > 10,
            "Expected most packets to be non-block-aligned, got {} out of 20",
            non_aligned_count
        );
    }

    #[test]
    fn test_obfuscation_with_noise() {
        let cipher = Cipher::with_obfuscation(b"noise-obfuscation");

        let packet = Packet::data(99, 0xDEADBEEF, vec![1, 2, 3]);
        let encrypted = cipher.encrypt(&packet, 50).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(packet.payload, decrypted.payload);
        assert_eq!(packet.header, decrypted.header);
    }

    #[test]
    fn test_obfuscation_toggle() {
        let mut cipher = Cipher::new(b"toggle-test");
        assert!(!cipher.is_obfuscation_enabled());

        cipher.set_obfuscation(true);
        assert!(cipher.is_obfuscation_enabled());

        cipher.set_obfuscation(false);
        assert!(!cipher.is_obfuscation_enabled());
    }

    #[test]
    fn test_obfuscation_cross_compatibility() {
        // Cipher with obfuscation can decrypt its own packets
        let cipher_obf = Cipher::with_obfuscation(b"cross-compat");

        let packet = Packet::data(1, 0x1111, vec![0xCC; 20]);
        let encrypted = cipher_obf.encrypt(&packet, 0).unwrap();
        let decrypted = cipher_obf.decrypt(&encrypted).unwrap();

        assert_eq!(packet, decrypted);
    }

    #[test]
    fn test_non_obfuscated_cipher_decrypt_still_block_aligned() {
        // Without obfuscation, encrypted length should always be block-aligned
        // (IV 16 bytes + ciphertext which is always block-aligned)
        let cipher = Cipher::new(b"no-obfuscation");
        let packet = Packet::data(1, 0x2222, vec![0xDD; 50]);

        for _ in 0..10 {
            let encrypted = cipher.encrypt(&packet, 0).unwrap();
            assert_eq!(
                encrypted.len() % CIPHER_BLOCK_SIZE,
                0,
                "Without obfuscation, encrypted length should be block-aligned"
            );
        }
    }

    #[test]
    fn test_obfuscation_max_pre_padding() {
        let mut cipher = Cipher::with_obfuscation(b"pre-padding-test");
        cipher.set_max_pre_padding(4); // Small pre-padding for deterministic size range

        let packet = Packet::data(1, 0x3333, vec![0xEE; 10]);

        for _ in 0..10 {
            let encrypted = cipher.encrypt(&packet, 0).unwrap();
            let decrypted = cipher.decrypt(&encrypted).unwrap();
            assert_eq!(packet, decrypted);
        }
    }
}
