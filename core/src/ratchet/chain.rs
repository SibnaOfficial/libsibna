//! Chain Key Implementation - Hardened Edition
//!
//! Implements the symmetric ratchet chain keys for message key derivation.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Message key seed constant
const MESSAGE_KEY_SEED: u8 = 0x01;

/// Chain key seed constant
const CHAIN_KEY_SEED: u8 = 0x02;

/// Chain key seed for header encryption
const HEADER_KEY_SEED: u8 = 0x03;

/// Chain Key for Double Ratchet
///
/// Each chain key can derive message keys and the next chain key.
/// This provides forward secrecy within a single chain.
#[derive(Serialize, Deserialize)]
pub struct ChainKey {
    /// The chain key value
    pub key: [u8; 32],
    /// Current message number in this chain
    pub index: u64,
    /// Chain creation timestamp
    pub created_at: u64,
    /// Maximum messages in this chain before rotation
    pub max_messages: u64,
}

impl ChainKey {
    /// Maximum messages before chain rotation (default: 1000)
    pub const DEFAULT_MAX_MESSAGES: u64 = 1000;

    /// Create a new chain key from raw bytes
    ///
    /// # Arguments
    /// * `key` - 32-byte chain key value
    pub fn new(key: [u8; 32]) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key,
            index: 0,
            created_at,
            max_messages: Self::DEFAULT_MAX_MESSAGES,
        }
    }

    /// Create a new chain key with custom max messages
    pub fn with_max_messages(key: [u8; 32], max_messages: u64) -> Self {
        let mut ck = Self::new(key);
        ck.max_messages = max_messages;
        ck
    }

    /// Derive the next message key
    ///
    /// This also advances the chain key to the next state.
    ///
    /// # Returns
    /// A 32-byte message key
    ///
    /// # Security
    /// - Uses HMAC-SHA256 for derivation
    /// - Automatically advances chain key
    /// - Checks for chain rotation
    pub fn next_message_key(&mut self) -> Option<[u8; 32]> {
        // Check if chain needs rotation
        if self.index >= self.max_messages {
            return None;
        }

        // Derive message key: MK = HMAC(CK, 0x01)
        let message_key = self.derive_key(MESSAGE_KEY_SEED);

        // Advance chain key: CK' = HMAC(CK, 0x02)
        let next_key = self.derive_key(CHAIN_KEY_SEED);

        // Securely update state
        self.key.zeroize();
        self.key = next_key;
        self.index += 1;

        Some(message_key)
    }

    /// Derive a header encryption key
    ///
    /// This is used for encrypting message headers
    pub fn derive_header_key(&self) -> [u8; 32] {
        self.derive_key(HEADER_KEY_SEED)
    }

    /// Derive a key from the current chain key
    fn derive_key(&self, seed: u8) -> [u8; 32] {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC key length is valid");
        hmac.update(&[seed]);
        let result = hmac.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes()[..32]);

        key
    }

    /// Get the current index without advancing
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Get the chain age in seconds
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(self.created_at)
    }

    /// Check if the chain needs rotation
    pub fn needs_rotation(&self) -> bool {
        self.index >= self.max_messages || self.age_secs() > 86400 // 24 hours
    }

    /// Get remaining messages before rotation
    pub fn remaining_messages(&self) -> u64 {
        self.max_messages.saturating_sub(self.index)
    }

    /// Clone the current chain key without advancing
    ///
    /// # Security
    /// This creates a copy of the chain key. Use with caution.
    pub fn clone_key(&self) -> [u8; 32] {
        self.key
    }
}

impl Clone for ChainKey {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            index: self.index,
            created_at: self.created_at,
            max_messages: self.max_messages,
        }
    }
}

impl Zeroize for ChainKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.index = 0;
        self.created_at = 0;
    }
}

impl ZeroizeOnDrop for ChainKey {}

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Message key with metadata
#[derive(Clone, Debug)]
pub struct MessageKey {
    /// The message key
    pub key: [u8; 32],
    /// Message number
    pub message_number: u64,
    /// Creation timestamp
    pub created_at: u64,
}

impl MessageKey {
    /// Create a new message key
    pub fn new(key: [u8; 32], message_number: u64) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key,
            message_number,
            created_at,
        }
    }

    /// Check if the key has expired (older than 24 hours)
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.created_at + 86400
    }
}

impl Zeroize for MessageKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.message_number = 0;
        self.created_at = 0;
    }
}

impl ZeroizeOnDrop for MessageKey {}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Chain key manager for handling multiple chains
pub struct ChainKeyManager {
    /// Active chains
    chains: Vec<ChainKey>,
    /// Maximum number of chains to maintain
    max_chains: usize,
}

impl ChainKeyManager {
    /// Create a new chain key manager
    pub fn new(max_chains: usize) -> Self {
        Self {
            chains: Vec::new(),
            max_chains,
        }
    }

    /// Add a new chain
    pub fn add_chain(&mut self, chain: ChainKey) {
        if self.chains.len() >= self.max_chains {
            // Remove oldest chain
            self.chains.remove(0);
        }
        self.chains.push(chain);
    }

    /// Get a chain by index
    pub fn get_chain(&self, index: usize) -> Option<&ChainKey> {
        self.chains.get(index)
    }

    /// Get a mutable chain by index
    pub fn get_chain_mut(&mut self, index: usize) -> Option<&mut ChainKey> {
        self.chains.get_mut(index)
    }

    /// Remove expired chains
    pub fn prune_expired(&mut self) {
        self.chains.retain(|chain| !chain.needs_rotation());
    }

    /// Get the number of active chains
    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    /// Clear all chains
    pub fn clear(&mut self) {
        self.chains.clear();
    }
}

impl Zeroize for ChainKeyManager {
    fn zeroize(&mut self) {
        for chain in &mut self.chains {
            chain.zeroize();
        }
        self.chains.clear();
    }
}

impl ZeroizeOnDrop for ChainKeyManager {}

impl Drop for ChainKeyManager {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation() {
        let key = [0x42u8; 32];
        let mut chain = ChainKey::new(key);

        let mk1 = chain.next_message_key().unwrap();
        let mk2 = chain.next_message_key().unwrap();
        let mk3 = chain.next_message_key().unwrap();

        // Each message key should be different
        assert_ne!(mk1, mk2);
        assert_ne!(mk2, mk3);
        assert_ne!(mk1, mk3);

        // Index should advance
        assert_eq!(chain.index, 3);
    }

    #[test]
    fn test_chain_key_clone() {
        let key = [0x42u8; 32];
        let chain1 = ChainKey::new(key);
        let chain2 = chain1.clone();

        // Keys should match
        assert_eq!(chain1.key, chain2.key);
        assert_eq!(chain1.index, chain2.index);
    }

    #[test]
    fn test_chain_key_max_messages() {
        let key = [0x42u8; 32];
        let mut chain = ChainKey::with_max_messages(key, 5);

        // Should be able to derive 5 keys
        for _ in 0..5 {
            assert!(chain.next_message_key().is_some());
        }

        // Should return None after max messages
        assert!(chain.next_message_key().is_none());
    }

    #[test]
    fn test_chain_key_needs_rotation() {
        let key = [0x42u8; 32];
        let mut chain = ChainKey::with_max_messages(key, 10);

        assert!(!chain.needs_rotation());

        // Advance to max
        for _ in 0..10 {
            chain.next_message_key();
        }

        assert!(chain.needs_rotation());
    }

    #[test]
    fn test_message_key() {
        let key = [0x42u8; 32];
        let mk = MessageKey::new(key, 100);

        assert_eq!(mk.message_number, 100);
        assert!(!mk.is_expired());
    }

    #[test]
    fn test_chain_key_manager() {
        let mut manager = ChainKeyManager::new(3);

        let chain1 = ChainKey::new([1u8; 32]);
        let chain2 = ChainKey::new([2u8; 32]);
        let chain3 = ChainKey::new([3u8; 32]);
        let chain4 = ChainKey::new([4u8; 32]);

        manager.add_chain(chain1);
        manager.add_chain(chain2);
        manager.add_chain(chain3);

        assert_eq!(manager.chain_count(), 3);

        // Adding a 4th chain should remove the first
        manager.add_chain(chain4);
        assert_eq!(manager.chain_count(), 3);
    }

    #[test]
    fn test_header_key_derivation() {
        let key = [0x42u8; 32];
        let chain = ChainKey::new(key);

        let header_key = chain.derive_header_key();
        let message_key = chain.derive_key(MESSAGE_KEY_SEED);

        // Header key should be different from message key
        assert_ne!(header_key, message_key);
    }

    #[test]
    fn test_remaining_messages() {
        let key = [0x42u8; 32];
        let mut chain = ChainKey::with_max_messages(key, 10);

        assert_eq!(chain.remaining_messages(), 10);

        chain.next_message_key();
        assert_eq!(chain.remaining_messages(), 9);

        for _ in 0..9 {
            chain.next_message_key();
        }

        assert_eq!(chain.remaining_messages(), 0);
    }
}
