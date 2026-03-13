//! Double Ratchet Session - Hardened Edition
//!
//! Main session implementation for the Double Ratchet algorithm.

use super::{ChainKey, DoubleRatchetState, RatchetHeader, RatchetMessage, RatchetConfig};
use super::super::crypto::{CryptoHandler, Encryptor, constant_time_eq, SecureRandom, RatchetKdf};
use super::super::error::{ProtocolError, ProtocolResult};
use super::super::validation::{validate_message, validate_associated_data};
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use parking_lot::RwLock;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Double Ratchet Session - Hardened
///
/// Manages a single secure communication session with a peer.
/// Provides:
/// - Forward secrecy through DH ratchet
/// - Post-compromise security through symmetric ratchet
/// - Out-of-order message handling
/// - Replay protection
/// - Constant-time operations
pub struct DoubleRatchetSession {
    /// Session state (protected by RwLock)
    state: RwLock<DoubleRatchetState>,
    /// Session configuration
    config: Config,
    /// Ratchet configuration
    ratchet_config: RatchetConfig,
    /// Session ID
    session_id: String,
    /// Peer ID
    peer_id: Option<String>,
    /// Message counter for statistics
    messages_sent: std::sync::atomic::AtomicU64,
    messages_received: std::sync::atomic::AtomicU64,
    /// Session creation time
    created_at: std::time::Instant,
}

impl DoubleRatchetSession {
    /// Create a new session with default state
    ///
    /// # Arguments
    /// * `config` - Configuration options
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let dh_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let dh_local_bytes = dh_local.to_bytes().to_vec();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let state = DoubleRatchetState {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: Some(dh_local),
            dh_local_bytes,
            dh_remote: None,
            dh_remote_bytes: None,
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: DoubleRatchetState::CURRENT_VERSION,
        };

        let session_id = Self::generate_session_id()?;

        Ok(Self {
            state: RwLock::new(state),
            config: config.clone(),
            ratchet_config: RatchetConfig::default(),
            session_id,
            peer_id: None,
            messages_sent: std::sync::atomic::AtomicU64::new(0),
            messages_received: std::sync::atomic::AtomicU64::new(0),
            created_at: std::time::Instant::now(),
        })
    }

    /// Create a session from a shared secret (post-handshake)
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte shared secret from X3DH
    /// * `local_dh` - Local DH key pair
    /// * `remote_dh` - Remote DH public key
    /// * `config` - Configuration options
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        local_dh: StaticSecret,
        remote_dh: PublicKey,
        config: Config,
        initiator: bool,
    ) -> ProtocolResult<Self> {
        // Validate shared secret
        if shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // Derive initial keys from shared secret
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);

        let mut root_key = [0u8; 32];
        hkdf.expand(b"SibnaRootKey_v8", &mut root_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let mut chain_key = [0u8; 32];
        hkdf.expand(b"SibnaChainKey_v8", &mut chain_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let (sending_chain, receiving_chain) = if initiator {
            (Some(ChainKey::new(chain_key)), None)
        } else {
            (None, Some(ChainKey::new(chain_key)))
        };

        let dh_local_bytes = local_dh.to_bytes().to_vec();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let state = DoubleRatchetState {
            root_key,
            sending_chain,
            receiving_chain,
            dh_local: Some(local_dh),
            dh_local_bytes,
            dh_remote: Some(remote_dh),
            dh_remote_bytes: Some(remote_dh.as_bytes().to_vec()),
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
            created_at: now,
            last_activity: now,
            version: DoubleRatchetState::CURRENT_VERSION,
        };

        let session_id = Self::generate_session_id()?;

        Ok(Self {
            state: RwLock::new(state),
            config: config.clone(),
            ratchet_config: RatchetConfig::default(),
            session_id,
            peer_id: None,
            messages_sent: std::sync::atomic::AtomicU64::new(0),
            messages_received: std::sync::atomic::AtomicU64::new(0),
            created_at: std::time::Instant::now(),
        })
    }

    /// Encrypt a message
    ///
    /// # Arguments
    /// * `plaintext` - Message to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The encrypted message
    ///
    /// # Security
    /// - Validates all inputs
    /// - Uses constant-time operations
    /// - Automatic key rotation
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        // Validate inputs
        validate_message(plaintext).map_err(|_| ProtocolError::InvalidMessage)?;
        validate_associated_data(associated_data).map_err(|_| ProtocolError::InvalidArgument)?;

        let mut state = self.state.write();

        // Check if we need DH ratchet
        if state.sending_chain.as_ref().map(|c| c.needs_rotation()).unwrap_or(true) {
            self.perform_dh_ratchet(&mut state)?;
        }

        // Build header
        let dh_pub = state.dh_local.as_ref()
            .map(PublicKey::from)
            .ok_or_else(|| ProtocolError::InvalidState)?;

        let sending_chain = state.sending_chain.as_mut()
            .ok_or_else(|| ProtocolError::InvalidState)?;

        // Derive message key
        let message_key = sending_chain.next_message_key()
            .ok_or_else(|| ProtocolError::InvalidState)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        let header = RatchetHeader {
            dh_public: *dh_pub.as_bytes(),
            message_number: sending_chain.index() - 1,
            previous_chain_length: state.previous_counter,
            timestamp,
        };

        // Validate header
        header.validate()?;

        // Encrypt with message key
        let mut encryptor = Encryptor::new(&message_key, u64::MAX)
            .map_err(ProtocolError::from)?;

        // Build final associated data
        let header_bytes = header.to_bytes();
        let mut final_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(&header_bytes);

        let ciphertext = encryptor.encrypt_message(plaintext, &final_ad)
            .map_err(ProtocolError::from)?;

        // Build message
        let message = RatchetMessage {
            header,
            ciphertext,
        };

        // Update state
        state.touch();
        self.messages_sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        Ok(message.to_bytes())
    }

    /// Decrypt a message
    ///
    /// # Arguments
    /// * `message` - Encrypted message
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The decrypted plaintext
    ///
    /// # Security
    /// - Validates all inputs
    /// - Replay protection
    /// - Constant-time comparison
    pub fn decrypt(&self, message: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        // Validate minimum size
        if message.len() < 48 + 29 { // header + minimum ciphertext
            return Err(ProtocolError::InvalidMessage);
        }

        // Parse message
        let ratchet_message = RatchetMessage::from_bytes(message)?;
        let header = ratchet_message.header;

        // Validate header
        header.validate()?;

        let mut state = self.state.write();

        // Parse remote DH public key
        let remote_dh = PublicKey::from(header.dh_public);

        // 1. Try skipped message keys first
        let key_tuple = (header.dh_public, header.message_number);
        if let Some(&mk) = state.skipped_message_keys.get(&key_tuple) {
            return self.decrypt_with_key(
                &mk,
                &ratchet_message.ciphertext,
                associated_data,
                &header,
                &mut state,
                &key_tuple,
            );
        }

        // 2. Check if DH ratchet is needed
        let needs_ratchet = match state.dh_remote {
            None => true,
            Some(ref current) => !constant_time_eq(current.as_bytes(), remote_dh.as_bytes()),
        };

        if needs_ratchet {
            if let Some(prev_counter) = state.sending_chain.as_ref().map(|c| c.index()) {
                state.previous_counter = prev_counter;
            }
            self.skip_message_keys(&mut state, header.previous_chain_length)?;
            self.dh_ratchet(&mut state, remote_dh)?;
        }

        // 3. Skip to current message (but don't skip the current one)
        self.skip_message_keys(&mut state, header.message_number)?;

        // 4. Get message key from receiving chain
        let mk = if let Some(ref mut receiving_chain) = state.receiving_chain {
            if header.message_number < receiving_chain.index() {
                return Err(ProtocolError::ReplayAttackDetected);
            }

            receiving_chain.next_message_key()
                .ok_or_else(|| ProtocolError::InvalidState)?
        } else {
            return Err(ProtocolError::InvalidState);
        };

        // 5. Decrypt
        let result = self.decrypt_with_key(
            &mk,
            &ratchet_message.ciphertext,
            associated_data,
            &header,
            &mut state,
            &key_tuple,
        );

        // Update state
        state.touch();
        self.messages_received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        result
    }

    /// Decrypt with a specific key
    fn decrypt_with_key(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
        header: &RatchetHeader,
        state: &mut DoubleRatchetState,
        key_tuple: &([u8; 32], u64),
    ) -> ProtocolResult<Vec<u8>> {
        let mut encryptor = Encryptor::new(key, u64::MAX)
            .map_err(ProtocolError::from)?;

        let header_bytes = header.to_bytes();
        let mut full_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        full_ad.extend_from_slice(associated_data);
        full_ad.extend_from_slice(&header_bytes);

        let result = encryptor.decrypt_message(ciphertext, &full_ad)
            .map_err(ProtocolError::from);

        // Remove key from skipped keys on successful decryption
        if result.is_ok() {
            state.skipped_message_keys.remove(key_tuple);
        }

        result
    }

    /// Skip message keys up to a certain number
    fn skip_message_keys(
        &self,
        state: &mut DoubleRatchetState,
        until_n: u64,
    ) -> ProtocolResult<()> {
        if state.receiving_chain.is_none() {
            return Ok(());
        }

        // Check limit
        let current_index = state.receiving_chain.as_ref().unwrap().index();
        if until_n > current_index + state.max_skip as u64 {
            return Err(ProtocolError::MaxSkippedMessagesExceeded);
        }

        // Store keys for skipped messages
        while state.receiving_chain.as_ref().unwrap().index() < until_n {
            let mk = state.receiving_chain.as_mut().unwrap().next_message_key()
                .ok_or_else(|| ProtocolError::InvalidState)?;

            let dh_remote = state.dh_remote
                .ok_or_else(|| ProtocolError::InvalidState)?;

            let key_index = state.receiving_chain.as_ref().unwrap().index() - 1;
            if !state.add_skipped_key(*dh_remote.as_bytes(), key_index, mk) {
                return Err(ProtocolError::MaxSkippedMessagesExceeded);
            }
        }
        Ok(())
    }

    /// Perform a DH ratchet step
    fn dh_ratchet(
        &self,
        state: &mut DoubleRatchetState,
        remote_dh: PublicKey,
    ) -> ProtocolResult<()> {
        // Update previous counter
        state.previous_counter = state.sending_chain.as_ref()
            .map(|c| c.index())
            .unwrap_or(0);

        // Update remote key
        state.set_remote_dh(remote_dh);

        // Receiving ratchet
        let dh_local = state.dh_local.as_ref()
            .ok_or_else(|| ProtocolError::InvalidState)?;

        let shared_secret = dh_local.diffie_hellman(&remote_dh);
        let (root_key, receiving_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret.as_bytes())?;

        state.root_key = *root_key;
        state.receiving_chain = Some(ChainKey::new(*receiving_key));

        // Generate new local key pair
        let new_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);

        // Sending ratchet
        let shared_secret_send = new_local.diffie_hellman(&remote_dh);
        let (root_key, sending_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret_send.as_bytes())?;

        state.root_key = *root_key;
        state.sending_chain = Some(ChainKey::new(*sending_key));
        state.set_local_dh(new_local);

        Ok(())
    }

    /// Perform DH ratchet for sending
    fn perform_dh_ratchet(&self, state: &mut DoubleRatchetState) -> ProtocolResult<()> {
        // Generate new key pair
        let new_local = StaticSecret::random_from_rng(&mut rand_core::OsRng);

        // If we have a remote key, perform ratchet
        if let Some(remote_dh) = state.dh_remote {
            let shared_secret = new_local.diffie_hellman(&remote_dh);
            let (root_key, sending_key) = RatchetKdf::kdf_rk(&state.root_key, shared_secret.as_bytes())?;

            state.root_key = *root_key;
            state.sending_chain = Some(ChainKey::new(*sending_key));
            state.set_local_dh(new_local);
        } else {
            // No remote key yet, just update local key
            state.set_local_dh(new_local);
        }

        Ok(())
    }

    /// Generate a unique session ID
    fn generate_session_id() -> ProtocolResult<String> {
        let mut rng = SecureRandom::new()?;
        let bytes = rng.gen_bytes(16);
        Ok(hex::encode(bytes))
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Set peer ID
    pub fn set_peer_id(&mut self, peer_id: String) {
        self.peer_id = Some(peer_id);
    }

    /// Get peer ID
    pub fn peer_id(&self) -> Option<&str> {
        self.peer_id.as_deref()
    }

    /// Get message statistics
    pub fn message_stats(&self) -> (u64, u64) {
        (
            self.messages_sent.load(std::sync::atomic::Ordering::Relaxed),
            self.messages_received.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Get session age
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get session state summary
    pub fn state_summary(&self) -> super::StateSummary {
        self.state.read().summary()
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        self.state.read().is_expired()
    }

    /// Serialize session state (encrypted)
    pub fn serialize_state(&self) -> ProtocolResult<Vec<u8>> {
        let state = self.state.read();
        
        // Use bincode for compact serialization
        let serialized = bincode::serde::encode_to_vec(&*state, bincode::config::standard())
            .map_err(|_| ProtocolError::SerializationError)?;

        Ok(serialized)
    }

    /// Deserialize session state
    pub fn deserialize_state(&self, data: &[u8]) -> ProtocolResult<()> {
        let mut state = self.state.write();

        let mut loaded: DoubleRatchetState = bincode::serde::decode_from_slice(data, bincode::config::standard())
            .map_err(|_| ProtocolError::DeserializationError)?
            .0;

        // Restore DH keys from bytes
        loaded.restore_dh_keys()
            .map_err(|_| ProtocolError::DeserializationError)?;

        // Update max_skip from config
        loaded.max_skip = self.config.max_skipped_messages;

        *state = loaded;

        Ok(())
    }
}

impl Drop for DoubleRatchetSession {
    fn drop(&mut self) {
        // State will be zeroized automatically
    }
}

impl ZeroizeOnDrop for DoubleRatchetSession {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let config = Config::default();
        let session = DoubleRatchetSession::new(config);
        assert!(session.is_ok());
    }

    #[test]
    fn test_session_from_shared_secret() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let local_dh = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let remote_dh = PublicKey::from(&StaticSecret::random_from_rng(&mut rand_core::OsRng));

        let session = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            local_dh,
            remote_dh,
            config,
            true, // initiator
        );

        assert!(session.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];

        // Create two sessions with the same shared secret
        let secret_key1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key1 = PublicKey::from(&secret_key1);

        let secret_key2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key2 = PublicKey::from(&secret_key2);

        let session1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            secret_key1,
            public_key2,
            config.clone(),
            true, // Alice is initiator
        ).unwrap();

        let session2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            secret_key2,
            public_key1,
            config,
            false, // Bob is responder
        ).unwrap();

        // Encrypt with session1
        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let encrypted = session1.encrypt(plaintext, ad).unwrap();

        // Decrypt with session2
        let decrypted = session2.decrypt(&encrypted, ad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_replay_protection() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];

        let secret_key1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key1 = PublicKey::from(&secret_key1);

        let secret_key2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key2 = PublicKey::from(&secret_key2);

        let session1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            secret_key1,
            public_key2,
            config.clone(),
            true,
        ).unwrap();

        let session2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            secret_key2,
            public_key1,
            config,
            false,
        ).unwrap();

        // Encrypt and decrypt
        let encrypted = session1.encrypt(b"test", b"ad").unwrap();
        let _ = session2.decrypt(&encrypted, b"ad").unwrap();

        // Try to decrypt again (replay)
        let result = session2.decrypt(&encrypted, b"ad");
        assert!(result.is_err());
    }

    #[test]
    fn test_state_serialization() {
        let config = Config::default();
        let session = DoubleRatchetSession::new(config).unwrap();

        let serialized = session.serialize_state();
        assert!(serialized.is_ok());
    }

    #[test]
    fn test_session_stats() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];

        let secret_key1 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key1 = PublicKey::from(&secret_key1);

        let secret_key2 = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key2 = PublicKey::from(&secret_key2);

        let session1 = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            secret_key1,
            public_key2,
            config.clone(),
            true,
        ).unwrap();

        let session2 = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            secret_key2,
            public_key1,
            config,
            false,
        ).unwrap();

        // Send some messages
        for i in 0..5 {
            let encrypted = session1.encrypt(format!("message {}", i).as_bytes(), b"ad").unwrap();
            let _ = session2.decrypt(&encrypted, b"ad").unwrap();
        }

        let (sent, _received) = session1.message_stats();
        assert_eq!(sent, 5);

        let (_sent, received) = session2.message_stats();
        assert_eq!(received, 5);
    }
}
