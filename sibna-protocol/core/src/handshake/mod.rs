//! X3DH Handshake Implementation - Hardened Edition
//!
//! Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol
//! as specified in the Signal Protocol.

mod builder;
mod x3dh;

pub use builder::*;
pub use x3dh::*;

use crate::error::{ProtocolResult, ProtocolError};
use crate::crypto::constant_time_eq;
use x25519_dalek::{StaticSecret, PublicKey};

/// Handshake result containing shared secrets and keys
#[derive(Clone)]
pub struct HandshakeOutput {
    /// The shared secret derived from the handshake
    pub shared_secret: [u8; 32],
    /// Local ephemeral key pair
    pub local_ephemeral_key: StaticSecret,
    /// Local ephemeral public key
    pub local_ephemeral_public: PublicKey,
    /// Associated data for session binding
    pub associated_data: Vec<u8>,
    /// Handshake timestamp
    pub timestamp: u64,
}

impl HandshakeOutput {
    /// Create a new handshake output
    pub fn new(
        shared_secret: [u8; 32],
        local_ephemeral_key: StaticSecret,
        local_ephemeral_public: PublicKey,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            shared_secret,
            local_ephemeral_key,
            local_ephemeral_public,
            associated_data: Vec::new(),
            timestamp,
        }
    }

    /// Set associated data
    pub fn with_associated_data(mut self, ad: Vec<u8>) -> Self {
        self.associated_data = ad;
        self
    }

    /// Validate the handshake output
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check shared secret is not all zeros
        if self.shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // Check ephemeral key is valid
        let public = PublicKey::from(&self.local_ephemeral_key);
        if !constant_time_eq(public.as_bytes(), self.local_ephemeral_public.as_bytes()) {
            return Err(ProtocolError::InvalidArgument);
        }

        Ok(())
    }
}

impl std::fmt::Debug for HandshakeOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeOutput")
            .field("shared_secret", &"[REDACTED]")
            .field("local_ephemeral_public", &self.local_ephemeral_public)
            .field("associated_data_len", &self.associated_data.len())
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Handshake role (initiator or responder)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Initiator of the handshake
    Initiator,
    /// Responder to the handshake
    Responder,
}

/// Handshake state
#[derive(Clone, Debug)]
pub enum HandshakeState {
    /// Initial state
    Initial,
    /// Keys loaded
    KeysLoaded,
    /// Handshake in progress
    InProgress,
    /// Handshake completed
    Completed,
    /// Handshake failed
    Failed(String),
}

/// Prekey bundle for X3DH
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Identity key (Ed25519 public key)
    pub identity_key: [u8; 32],
    /// Signed prekey (X25519 public key)
    pub signed_prekey: [u8; 32],
    /// Signature of signed prekey
    pub signature: [u8; 64],
    /// One-time prekey (optional, X25519 public key)
    pub onetime_prekey: Option<[u8; 32]>,
    /// Timestamp of bundle creation
    pub timestamp: u64,
}

impl PreKeyBundle {
    /// Create a new prekey bundle
    pub fn new(
        identity_key: [u8; 32],
        signed_prekey: [u8; 32],
        signature: [u8; 64],
        onetime_prekey: Option<[u8; 32]>,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            identity_key,
            signed_prekey,
            signature,
            onetime_prekey,
            timestamp,
        }
    }

    /// Validate the prekey bundle
    pub fn validate(&self) -> ProtocolResult<()> {
        use ed25519_dalek::{VerifyingKey, Signature, Signer, Verifier};

        // Check keys are not all zeros
        if self.identity_key.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidKey);
        }
        if self.signed_prekey.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidKey);
        }

        // Verify signature
        let verifying_key = VerifyingKey::from_bytes(&self.identity_key)
            .map_err(|_| ProtocolError::InvalidKey)?;
        let signature = Signature::from_bytes(&self.signature);

        verifying_key.verify(&self.signed_prekey, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        // Check timestamp (bundle should not be older than 7 days)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::InternalError)?
            .as_secs();

        if now > self.timestamp + 7 * 86400 {
            return Err(ProtocolError::Expired);
        }

        Ok(())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(160);
        result.extend_from_slice(&self.identity_key);
        result.extend_from_slice(&self.signed_prekey);
        result.extend_from_slice(&self.signature);
        result.push(self.onetime_prekey.is_some() as u8);
        if let Some(ref opk) = self.onetime_prekey {
            result.extend_from_slice(opk);
        }
        result.extend_from_slice(&self.timestamp.to_le_bytes());
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < 32 + 32 + 64 + 1 + 8 {
            return Err(ProtocolError::InvalidMessage);
        }

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[0..32]);

        let mut signed_prekey = [0u8; 32];
        signed_prekey.copy_from_slice(&data[32..64]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[64..128]);

        let has_onetime = data[128] != 0;
        let onetime_prekey = if has_onetime {
            let mut opk = [0u8; 32];
            opk.copy_from_slice(&data[129..161]);
            Some(opk)
        } else {
            None
        };

        let timestamp_offset = if has_onetime { 161 } else { 129 };
        let timestamp = u64::from_le_bytes(
            data[timestamp_offset..timestamp_offset + 8].try_into()
                .map_err(|_| ProtocolError::InvalidMessage)?
        );

        Ok(Self {
            identity_key,
            signed_prekey,
            signature,
            onetime_prekey,
            timestamp,
        })
    }
}

/// Handshake metrics for monitoring
#[derive(Clone, Debug, Default)]
pub struct HandshakeMetrics {
    /// Number of successful handshakes
    pub successful: u64,
    /// Number of failed handshakes
    pub failed: u64,
    /// Average handshake time in milliseconds
    pub avg_time_ms: f64,
    /// Total handshakes
    pub total: u64,
}

impl HandshakeMetrics {
    /// Record a successful handshake
    pub fn record_success(&mut self, duration_ms: f64) {
        self.successful += 1;
        self.total += 1;
        // Update running average
        self.avg_time_ms = (self.avg_time_ms * (self.total - 1) as f64 + duration_ms) / self.total as f64;
    }

    /// Record a failed handshake
    pub fn record_failure(&mut self) {
        self.failed += 1;
        self.total += 1;
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.successful as f64 / self.total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;

    #[test]
    fn test_handshake_output_validation() {
        let ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral);

        let output = HandshakeOutput::new(
            [0x42u8; 32],
            ephemeral,
            ephemeral_public,
        );

        assert!(output.validate().is_ok());
    }

    #[test]
    fn test_handshake_output_invalid() {
        let ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let ephemeral_public = PublicKey::from(&StaticSecret::random_from_rng(&mut OsRng));

        let output = HandshakeOutput::new(
            [0u8; 32], // Invalid shared secret
            ephemeral,
            ephemeral_public,
        );

        assert!(output.validate().is_err());
    }

    #[test]
    fn test_prekey_bundle_validation() {
        // Generate signing key
        let signing_key = SigningKey::generate(&mut OsRng);
        let identity_key = signing_key.verifying_key().to_bytes();

        // Generate signed prekey
        let signed_prekey_secret = StaticSecret::random_from_rng(&mut OsRng);
        let signed_prekey = PublicKey::from(&signed_prekey_secret).to_bytes();

        // Sign the prekey
        let signature = signing_key.sign(&signed_prekey).to_bytes();

        let bundle = PreKeyBundle::new(
            identity_key,
            signed_prekey,
            signature,
            None,
        );

        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_prekey_bundle_invalid_signature() {
        let identity_key = [0x42u8; 32];
        let signed_prekey = [0x24u8; 32];
        let signature = [0u8; 64]; // Invalid signature

        let bundle = PreKeyBundle::new(
            identity_key,
            signed_prekey,
            signature,
            None,
        );

        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_prekey_bundle_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let identity_key = signing_key.verifying_key().to_bytes();

        let signed_prekey_secret = StaticSecret::random_from_rng(&mut OsRng);
        let signed_prekey = PublicKey::from(&signed_prekey_secret).to_bytes();

        let signature = signing_key.sign(&signed_prekey).to_bytes();

        let bundle = PreKeyBundle::new(
            identity_key,
            signed_prekey,
            signature,
            Some([0xABu8; 32]),
        );

        let bytes = bundle.to_bytes();
        let parsed = PreKeyBundle::from_bytes(&bytes).unwrap();

        assert_eq!(bundle.identity_key, parsed.identity_key);
        assert_eq!(bundle.signed_prekey, parsed.signed_prekey);
        assert_eq!(bundle.signature, parsed.signature);
        assert_eq!(bundle.onetime_prekey, parsed.onetime_prekey);
    }

    #[test]
    fn test_handshake_metrics() {
        let mut metrics = HandshakeMetrics::default();

        metrics.record_success(100.0);
        metrics.record_success(200.0);
        metrics.record_failure();

        assert_eq!(metrics.successful, 2);
        assert_eq!(metrics.failed, 1);
        assert_eq!(metrics.total, 3);
        assert!((metrics.success_rate() - 0.6667).abs() < 0.001);
    }
}
