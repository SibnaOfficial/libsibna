//! X3DH Core Implementation - Hardened Edition
//!
//! Low-level X3DH operations with constant-time guarantees.

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::{constant_time_eq, X3dhKdf};
use x25519_dalek::{StaticSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X3DH key agreement result
#[derive(Clone, Debug)]
pub struct X3dhResult {
    /// Shared secret
    pub shared_secret: [u8; 32],
    /// DH results used in derivation
    pub dh_results: Vec<[u8; 32]>,
}

impl X3dhResult {
    /// Create a new X3DH result
    pub fn new(shared_secret: [u8; 32], dh_results: Vec<[u8; 32]>) -> Self {
        Self {
            shared_secret,
            dh_results,
        }
    }

    /// Validate the result
    pub fn validate(&self) -> ProtocolResult<()> {
        // Check shared secret is not all zeros
        if self.shared_secret.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidArgument);
        }

        // Check we have the expected number of DH results
        if self.dh_results.is_empty() || self.dh_results.len() > 4 {
            return Err(ProtocolError::InvalidArgument);
        }

        Ok(())
    }
}

impl Zeroize for X3dhResult {
    fn zeroize(&mut self) {
        self.shared_secret.zeroize();
        for dh in &mut self.dh_results {
            dh.zeroize();
        }
    }
}

impl ZeroizeOnDrop for X3dhResult {}

impl Drop for X3dhResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Perform X3DH key agreement (initiator)
///
/// # Arguments
/// * `our_identity` - Our identity secret key
/// * `our_ephemeral` - Our ephemeral secret key
/// * `peer_identity` - Peer's identity public key
/// * `peer_signed_prekey` - Peer's signed prekey public key
/// * `peer_onetime_prekey` - Peer's one-time prekey public key (optional)
///
/// # Returns
/// X3DH result containing shared secret
pub fn x3dh_initiator(
    our_identity: &StaticSecret,
    our_ephemeral: &StaticSecret,
    peer_identity: &PublicKey,
    peer_signed_prekey: &PublicKey,
    peer_onetime_prekey: Option<&PublicKey>,
) -> ProtocolResult<X3dhResult> {
    // DH1: Our identity + peer's signed prekey
    let dh1 = our_identity.diffie_hellman(peer_signed_prekey);

    // DH2: Our ephemeral + peer's identity
    let dh2 = our_ephemeral.diffie_hellman(peer_identity);

    // DH3: Our ephemeral + peer's signed prekey
    let dh3 = our_ephemeral.diffie_hellman(peer_signed_prekey);

    // DH4: Our ephemeral + peer's one-time prekey (if available)
    let dh4 = peer_onetime_prekey.map(|opk| {
        our_ephemeral.diffie_hellman(opk)
    });

    // Collect DH results
    let mut dh_results = vec![
        dh1.to_bytes(),
        dh2.to_bytes(),
        dh3.to_bytes(),
    ];

    if let Some(ref dh4) = dh4 {
        dh_results.push(dh4.to_bytes());
    }

    // Derive shared secret
    let shared_secret = if let Some(dh4) = dh4 {
        X3dhKdf::derive_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            Some(dh4.as_bytes()),
        )?
    } else {
        X3dhKdf::derive_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            None,
        )?
    };

    let result = X3dhResult::new(*shared_secret, dh_results);
    result.validate()?;

    Ok(result)
}

/// Perform X3DH key agreement (responder)
///
/// # Arguments
/// * `our_identity` - Our identity secret key
/// * `our_signed_prekey` - Our signed prekey secret key
/// * `our_onetime_prekey` - Our one-time prekey secret key (optional)
/// * `peer_identity` - Peer's identity public key
/// * `peer_ephemeral` - Peer's ephemeral public key
///
/// # Returns
/// X3DH result containing shared secret
pub fn x3dh_responder(
    our_identity: &StaticSecret,
    our_signed_prekey: &StaticSecret,
    our_onetime_prekey: Option<&StaticSecret>,
    peer_identity: &PublicKey,
    peer_ephemeral: &PublicKey,
) -> ProtocolResult<X3dhResult> {
    // DH1: Our signed prekey + peer's identity
    let dh1 = our_signed_prekey.diffie_hellman(peer_identity);

    // DH2: Our identity + peer's ephemeral
    let dh2 = our_identity.diffie_hellman(peer_ephemeral);

    // DH3: Our signed prekey + peer's ephemeral
    let dh3 = our_signed_prekey.diffie_hellman(peer_ephemeral);

    // DH4: Our one-time prekey + peer's ephemeral (if available)
    let dh4 = our_onetime_prekey.map(|opk| {
        opk.diffie_hellman(peer_ephemeral)
    });

    // Collect DH results
    let mut dh_results = vec![
        dh1.to_bytes(),
        dh2.to_bytes(),
        dh3.to_bytes(),
    ];

    if let Some(ref dh4) = dh4 {
        dh_results.push(dh4.to_bytes());
    }

    // Derive shared secret
    let shared_secret = if let Some(dh4) = dh4 {
        X3dhKdf::derive_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            Some(dh4.as_bytes()),
        )?
    } else {
        X3dhKdf::derive_shared_secret(
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
            None,
        )?
    };

    let result = X3dhResult::new(*shared_secret, dh_results);
    result.validate()?;

    Ok(result)
}

/// Verify that two X3DH results produce the same shared secret
///
/// # Security
/// Uses constant-time comparison to prevent timing attacks
pub fn verify_shared_secret(a: &X3dhResult, b: &X3dhResult) -> bool {
    constant_time_eq(&a.shared_secret, &b.shared_secret)
}

/// X3DH session keys derived from shared secret
#[derive(Clone, Debug)]
pub struct X3dhSessionKeys {
    /// Encryption key for sending
    pub sending_key: [u8; 32],
    /// Encryption key for receiving
    pub receiving_key: [u8; 32],
    /// Authentication key
    pub auth_key: [u8; 32],
    /// Additional keys for future use
    pub extra_keys: Vec<[u8; 32]>,
}

impl X3dhSessionKeys {
    /// Derive session keys from shared secret
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> ProtocolResult<Self> {
        use crate::crypto::kdf::HkdfKdf;

        let infos: &[&[u8]] = &[
            b"SibnaSendingKey_v8",
            b"SibnaReceivingKey_v8",
            b"SibnaAuthKey_v8",
            b"SibnaExtraKey1_v8",
            b"SibnaExtraKey2_v8",
        ];

        let keys = HkdfKdf::derive_multiple(shared_secret, &[], infos)?;

        if keys.len() < 3 {
            return Err(ProtocolError::KeyDerivationFailed);
        }

        let sending_key = keys[0].as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;
        let receiving_key = keys[1].as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;
        let auth_key = keys[2].as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;

        let extra_keys: ProtocolResult<Vec<[u8; 32]>> = keys[3..].iter()
            .map(|k| k.as_slice().try_into().map_err(|_| ProtocolError::InvalidKeyLength))
            .collect();
        let extra_keys = extra_keys?;

        Ok(Self {
            sending_key,
            receiving_key,
            auth_key,
            extra_keys,
        })
    }
}

impl Zeroize for X3dhSessionKeys {
    fn zeroize(&mut self) {
        self.sending_key.zeroize();
        self.receiving_key.zeroize();
        self.auth_key.zeroize();
        for key in &mut self.extra_keys {
            key.zeroize();
        }
    }
}

impl ZeroizeOnDrop for X3dhSessionKeys {}

impl Drop for X3dhSessionKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_x3dh_initiator_responder() {
        // Generate keys for party A
        let a_identity = StaticSecret::random_from_rng(&mut OsRng);
        let a_identity_public = PublicKey::from(&a_identity);
        let a_ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let a_ephemeral_public = PublicKey::from(&a_ephemeral);

        // Generate keys for party B
        let b_identity = StaticSecret::random_from_rng(&mut OsRng);
        let b_identity_public = PublicKey::from(&b_identity);
        let b_signed_prekey = StaticSecret::random_from_rng(&mut OsRng);
        let b_signed_prekey_public = PublicKey::from(&b_signed_prekey);
        let b_onetime_prekey = StaticSecret::random_from_rng(&mut OsRng);
        let b_onetime_prekey_public = PublicKey::from(&b_onetime_prekey);

        // A performs initiator handshake
        let result_a = x3dh_initiator(
            &a_identity,
            &a_ephemeral,
            &b_identity_public,
            &b_signed_prekey_public,
            Some(&b_onetime_prekey_public),
        ).unwrap();

        // B performs responder handshake
        let result_b = x3dh_responder(
            &b_identity,
            &b_signed_prekey,
            Some(&b_onetime_prekey),
            &a_identity_public,
            &a_ephemeral_public,
        ).unwrap();

        // Shared secrets should match
        assert!(verify_shared_secret(&result_a, &result_b));
    }

    #[test]
    fn test_x3dh_without_onetime_prekey() {
        // Generate keys for party A
        let a_identity = StaticSecret::random_from_rng(&mut OsRng);
        let a_identity_public = PublicKey::from(&a_identity);
        let a_ephemeral = StaticSecret::random_from_rng(&mut OsRng);
        let a_ephemeral_public = PublicKey::from(&a_ephemeral);

        // Generate keys for party B (no one-time prekey)
        let b_identity = StaticSecret::random_from_rng(&mut OsRng);
        let b_identity_public = PublicKey::from(&b_identity);
        let b_signed_prekey = StaticSecret::random_from_rng(&mut OsRng);
        let b_signed_prekey_public = PublicKey::from(&b_signed_prekey);

        // A performs initiator handshake
        let result_a = x3dh_initiator(
            &a_identity,
            &a_ephemeral,
            &b_identity_public,
            &b_signed_prekey_public,
            None,
        ).unwrap();

        // B performs responder handshake
        let result_b = x3dh_responder(
            &b_identity,
            &b_signed_prekey,
            None,
            &a_identity_public,
            &a_ephemeral_public,
        ).unwrap();

        // Shared secrets should match
        assert!(verify_shared_secret(&result_a, &result_b));
    }

    #[test]
    fn test_session_keys_derivation() {
        let shared_secret = [0x42u8; 32];
        
        let session_keys = X3dhSessionKeys::from_shared_secret(&shared_secret).unwrap();
        
        // Keys should be different
        assert_ne!(session_keys.sending_key, session_keys.receiving_key);
        assert_ne!(session_keys.sending_key, session_keys.auth_key);
        assert_ne!(session_keys.receiving_key, session_keys.auth_key);
    }

    #[test]
    fn test_x3dh_result_validation() {
        // Valid result
        let result = X3dhResult::new(
            [0x42u8; 32],
            vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]],
        );
        assert!(result.validate().is_ok());

        // Invalid result (all zeros shared secret)
        let result = X3dhResult::new(
            [0u8; 32],
            vec![[0x01u8; 32]],
        );
        assert!(result.validate().is_err());

        // Invalid result (no DH results)
        let result = X3dhResult::new(
            [0x42u8; 32],
            vec![],
        );
        assert!(result.validate().is_err());
    }
}
