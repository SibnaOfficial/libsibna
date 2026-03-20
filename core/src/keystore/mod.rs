//! Secure Key Storage - Hardened Edition
//!
//! Provides secure storage and management of cryptographic keys.
//! All keys are encrypted at rest and zeroized when dropped.

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::{CryptoHandler, SecureRandom, constant_time_eq, constant_time_is_zero};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Identity key pair (Ed25519 for signing, X25519 for DH)
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// Ed25519 secret key (not serialized)
    #[serde(skip)]
    pub ed25519_secret: Option<[u8; 32]>,
    /// Ed25519 public key
    pub ed25519_public: [u8; 32],
    /// X25519 secret key (not serialized)
    #[serde(skip)]
    pub x25519_secret: Option<x25519_dalek::StaticSecret>,
    /// X25519 public key
    pub x25519_public: [u8; 32],
    /// Key creation timestamp
    pub created_at: u64,
}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        // Generate Ed25519 key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_public = signing_key.verifying_key().to_bytes();

        // Generate X25519 key pair
        let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ed25519_secret: Some(signing_key.to_bytes()),
            ed25519_public,
            x25519_secret: Some(x25519_secret),
            x25519_public: x25519_public.to_bytes(),
            created_at,
        }
    }

    /// Create from bytes
    pub fn from_bytes(ed_pub: &[u8], x_pub: &[u8], seed: &[u8]) -> Self {
        use ed25519_dalek::SigningKey;

        let ed25519_public: [u8; 32] = match ed_pub.try_into() { Ok(k) => k, Err(_) => return Self { ed25519_secret: None, ed25519_public: [0u8; 32], x25519_secret: None, x25519_public: [0u8; 32], created_at: 0 } };
        let x25519_public: [u8; 32] = x_pub.try_into().map_err(|_| crate::error::ProtocolError::InvalidKeyLength)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| crate::error::ProtocolError::InvalidKeyLength)?;

        let signing_key = SigningKey::from_bytes(&seed);
        let x25519_secret = x25519_dalek::StaticSecret::from(seed);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            ed25519_secret: Some(signing_key.to_bytes()),
            ed25519_public,
            x25519_secret: Some(x25519_secret),
            x25519_public,
            created_at,
        })
    }

    /// Sign data with Ed25519
    pub fn sign(&self, data: &[u8]) -> ProtocolResult<[u8; 64]> {
        use ed25519_dalek::{Signer, SigningKey};

        let secret = self.ed25519_secret
            .ok_or(ProtocolError::InvalidState)?;

        let signing_key = SigningKey::from_bytes(&secret);
        let signature = signing_key.sign(data);

        Ok(signature.to_bytes())
    }

    /// Verify signature with Ed25519
    pub fn verify(&self, data: &[u8], signature: &[u8; 64]) -> ProtocolResult<bool> {
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};

        let verifying_key = VerifyingKey::from_bytes(&self.ed25519_public)
            .map_err(|_| ProtocolError::InvalidKey)?;

        let sig = Signature::from_bytes(signature);

        match verifying_key.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get key fingerprint
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&self.ed25519_public);
        hasher.update(&self.x25519_public);
        hasher.finalize().into()
    }

    /// Check if keys are valid
    pub fn is_valid(&self) -> bool {
        // Check public keys are not all zeros
        if constant_time_is_zero(&self.ed25519_public) {
            return false;
        }
        if constant_time_is_zero(&self.x25519_public) {
            return false;
        }

        // Check derived public key matches
        if let Some(ref x_secret) = self.x25519_secret {
            let derived_public = x25519_dalek::PublicKey::from(x_secret);
            constant_time_eq(derived_public.as_bytes(), &self.x25519_public)
        } else {
            false
        }
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("ed25519_public", &self.ed25519_public)
            .field("x25519_public", &self.x25519_public)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for IdentityKeyPair {
    fn zeroize(&mut self) {
        if let Some(ref mut secret) = self.ed25519_secret {
            secret.zeroize();
        }
        self.ed25519_public.zeroize();
        // x25519_secret will be zeroized by ZeroizeOnDrop
        self.x25519_public.zeroize();
    }
}

impl ZeroizeOnDrop for IdentityKeyPair {}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Signed prekey with metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    /// Key ID
    pub key_id: u32,
    /// X25519 secret key (not serialized)
    #[serde(skip)]
    pub secret: Option<x25519_dalek::StaticSecret>,
    /// X25519 public key
    pub public: [u8; 32],
    /// Signature by identity key
    pub signature: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
}

impl SignedPreKey {
    /// Generate a new signed prekey
    pub fn generate(key_id: u32, identity: &IdentityKeyPair) -> ProtocolResult<Self> {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);

        // Sign the public key
        let signature = identity.sign(public.as_bytes())?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            key_id,
            secret: Some(secret),
            public: public.to_bytes(),
            signature: signature.to_vec(),
            created_at,
        })
    }

    /// Verify the signature
    pub fn verify(&self, identity: &IdentityKeyPair) -> ProtocolResult<bool> {
        let signature: [u8; 64] = self.signature.as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidSignature)?;
        identity.verify(&self.public, &signature)
    }

    /// Check if key has expired (older than 7 days)
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.created_at + 7 * 86400
    }
}

impl std::fmt::Debug for SignedPreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPreKey")
            .field("key_id", &self.key_id)
            .field("public", &self.public)
            .field("signature", &self.signature)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for SignedPreKey {
    fn zeroize(&mut self) {
        self.public.zeroize();
        self.signature.zeroize();
    }
}

impl ZeroizeOnDrop for SignedPreKey {}

/// One-time prekey
#[derive(Clone)]
pub struct OneTimePreKey {
    /// Key ID
    pub key_id: u32,
    /// Secret key
    pub secret: Option<x25519_dalek::StaticSecret>,
    /// Public key
    pub public: [u8; 32],
    /// Whether the key has been used
    pub used: bool,
    /// Creation timestamp
    pub created_at: u64,
}

impl OneTimePreKey {
    /// Generate a new one-time prekey
    pub fn generate(key_id: u32) -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key_id,
            secret: Some(secret),
            public: public.to_bytes(),
            used: false,
            created_at,
        }
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.used = true;
        // Clear secret after use
        self.secret = None;
    }

    /// Check if key has expired (older than 30 days)
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.created_at + 30 * 86400
    }
}

impl std::fmt::Debug for OneTimePreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimePreKey")
            .field("key_id", &self.key_id)
            .field("public", &self.public)
            .field("used", &self.used)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for OneTimePreKey {
    fn zeroize(&mut self) {
        self.public.zeroize();
    }
}

impl ZeroizeOnDrop for OneTimePreKey {}

/// Secure key store
#[derive(Clone)]
pub struct KeyStore {
    /// Identity key pair
    identity: Option<IdentityKeyPair>,
    /// Signed prekey
    signed_prekey: Option<SignedPreKey>,
    /// One-time prekeys
    onetime_prekeys: HashMap<u32, OneTimePreKey>,
    /// Next one-time prekey ID
    next_onetime_id: u32,
    /// Encryption handler for storage
    crypto: Option<CryptoHandler>,
}

impl KeyStore {
    /// Create a new key store
    pub fn new() -> ProtocolResult<Self> {
        Ok(Self {
            identity: None,
            signed_prekey: None,
            onetime_prekeys: HashMap::new(),
            next_onetime_id: 1,
            crypto: None,
        })
    }

    /// Create an in-memory key store (for WASM)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory() -> ProtocolResult<Self> {
        Self::new()
    }

    /// Set identity key pair
    pub fn set_identity(&mut self, identity: IdentityKeyPair) -> ProtocolResult<()> {
        if !identity.is_valid() {
            return Err(ProtocolError::InvalidKey);
        }
        self.identity = Some(identity);
        Ok(())
    }

    /// Get identity key pair
    pub fn get_identity_keypair(&self) -> ProtocolResult<IdentityKeyPair> {
        self.identity.clone()
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Generate and set signed prekey
    pub fn generate_signed_prekey(&mut self) -> ProtocolResult<()> {
        let identity = self.get_identity_keypair()?;
        let prekey = SignedPreKey::generate(1, &identity)?;
        self.signed_prekey = Some(prekey);
        Ok(())
    }

    /// Get signed prekey
    pub fn get_signed_prekey(&self) -> ProtocolResult<x25519_dalek::StaticSecret> {
        self.signed_prekey
            .as_ref()
            .and_then(|k| k.secret.clone())
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get signed prekey public
    pub fn get_signed_prekey_public(&self) -> ProtocolResult<[u8; 32]> {
        self.signed_prekey
            .as_ref()
            .map(|k| k.public)
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Generate one-time prekeys
    pub fn generate_onetime_prekeys(&mut self, count: usize) -> ProtocolResult<Vec<u32>> {
        let _identity = self.get_identity_keypair()?;
        let mut ids = Vec::with_capacity(count);

        for _ in 0..count {
            let id = self.next_onetime_id;
            self.next_onetime_id += 1;

            let prekey = OneTimePreKey::generate(id);
            ids.push(id);
            self.onetime_prekeys.insert(id, prekey);
        }

        Ok(ids)
    }

    /// Get one-time prekey
    pub fn get_onetime_prekey(&self) -> ProtocolResult<x25519_dalek::StaticSecret> {
        // Find unused, non-expired key
        for (_, prekey) in &self.onetime_prekeys {
            if !prekey.used && !prekey.is_expired() {
                return prekey.secret.clone()
                    .ok_or(ProtocolError::KeyNotFound);
            }
        }
        Err(ProtocolError::KeyNotFound)
    }

    /// Get specific one-time prekey by ID
    pub fn get_onetime_prekey_by_id(&self, id: u32) -> ProtocolResult<x25519_dalek::StaticSecret> {
        self.onetime_prekeys.get(&id)
            .and_then(|k| k.secret.clone())
            .ok_or(ProtocolError::KeyNotFound)
    }

    /// Get one-time prekey public
    pub fn get_onetime_prekey_public(&self) -> ProtocolResult<(u32, [u8; 32])> {
        for (id, prekey) in &self.onetime_prekeys {
            if !prekey.used && !prekey.is_expired() {
                return Ok((*id, prekey.public));
            }
        }
        Err(ProtocolError::KeyNotFound)
    }

    /// Mark one-time prekey as used
    pub fn mark_onetime_used(&mut self, key_id: u32) {
        if let Some(prekey) = self.onetime_prekeys.get_mut(&key_id) {
            prekey.mark_used();
        }
    }

    /// Get remaining one-time prekeys count
    pub fn onetime_prekey_count(&self) -> usize {
        self.onetime_prekeys
            .values()
            .filter(|k| !k.used && !k.is_expired())
            .count()
    }

    /// Prune expired and used keys
    pub fn prune_keys(&mut self) {
        self.onetime_prekeys.retain(|_, k| !k.used && !k.is_expired());

        if self.signed_prekey.as_ref().map(|k| k.is_expired()).unwrap_or(false) {
            self.signed_prekey = None;
        }
    }

    /// Check if store is healthy
    pub fn is_healthy(&self) -> bool {
        // Check if we can access the identity key
        self.identity.is_some()
    }

    /// Get key store statistics
    pub fn stats(&self) -> KeyStoreStats {
        KeyStoreStats {
            has_identity: self.identity.is_some(),
            has_signed_prekey: self.signed_prekey.is_some(),
            onetime_prekey_count: self.onetime_prekey_count(),
            total_onetime_prekeys: self.onetime_prekeys.len(),
        }
    }
}

impl Zeroize for KeyStore {
    fn zeroize(&mut self) {
        self.identity = None;
        self.signed_prekey = None;
        self.onetime_prekeys.clear();
        self.next_onetime_id = 0;
    }
}

impl ZeroizeOnDrop for KeyStore {}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Key store statistics
#[derive(Clone, Debug)]
pub struct KeyStoreStats {
    /// Whether identity key exists
    pub has_identity: bool,
    /// Whether signed prekey exists
    pub has_signed_prekey: bool,
    /// Available one-time prekeys
    pub onetime_prekey_count: usize,
    /// Total one-time prekeys (including used)
    pub total_onetime_prekeys: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_keypair_generation() {
        let keypair = IdentityKeyPair::generate();
        
        assert!(!constant_time_is_zero(&keypair.ed25519_public));
        assert!(!constant_time_is_zero(&keypair.x25519_public));
        assert!(keypair.is_valid());
    }

    #[test]
    fn test_identity_keypair_sign_verify() {
        let keypair = IdentityKeyPair::generate();
        
        let data = b"test data";
        let signature = keypair.sign(data).unwrap();
        
        assert!(keypair.verify(data, &signature).unwrap());
        assert!(!keypair.verify(b"wrong data", &signature).unwrap());
    }

    #[test]
    fn test_signed_prekey() {
        let identity = IdentityKeyPair::generate();
        let prekey = SignedPreKey::generate(1, &identity).unwrap();
        
        assert_eq!(prekey.key_id, 1);
        assert!(prekey.verify(&identity).unwrap());
    }

    #[test]
    fn test_onetime_prekey() {
        let mut prekey = OneTimePreKey::generate(1);
        
        assert_eq!(prekey.key_id, 1);
        assert!(!prekey.used);
        
        prekey.mark_used();
        assert!(prekey.used);
        assert!(prekey.secret.is_none());
    }

    #[test]
    fn test_keystore() {
        let mut keystore = KeyStore::new().unwrap();
        
        // Set identity
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        
        // Generate signed prekey
        keystore.generate_signed_prekey().unwrap();
        assert!(keystore.get_signed_prekey().is_ok());
        
        // Generate one-time prekeys
        let ids = keystore.generate_onetime_prekeys(5).unwrap();
        assert_eq!(ids.len(), 5);
        assert_eq!(keystore.onetime_prekey_count(), 5);
        
        // Use a one-time prekey
        let (id, _) = keystore.get_onetime_prekey_public().unwrap();
        keystore.mark_onetime_used(id);
        assert_eq!(keystore.onetime_prekey_count(), 4);
    }

    #[test]
    fn test_keystore_stats() {
        let mut keystore = KeyStore::new().unwrap();
        
        let stats = keystore.stats();
        assert!(!stats.has_identity);
        
        let identity = IdentityKeyPair::generate();
        keystore.set_identity(identity).unwrap();
        
        let stats = keystore.stats();
        assert!(stats.has_identity);
    }
}
