//! Integration Tests for Sibna Protocol v8

use sibna_core::*;

#[test]
fn test_full_session_lifecycle() {
    // Create contexts for Alice and Bob
    let config = Config::default();
    let alice_ctx = SecureContext::new(config.clone(), Some(b"alice_password")).unwrap();
    let bob_ctx = SecureContext::new(config.clone(), Some(b"bob_password")).unwrap();
    
    // Generate identities
    let alice_identity = alice_ctx.generate_identity().unwrap();
    let bob_identity = bob_ctx.generate_identity().unwrap();
    
    // Create sessions
    let alice_session = alice_ctx.create_session(b"bob").unwrap();
    let bob_session = bob_ctx.create_session(b"alice").unwrap();
    
    // Perform handshake (simplified)
    // In real scenario, this would involve X3DH
    
    // Encrypt and decrypt messages
    let plaintext = b"Hello, Bob!";
    let encrypted = alice_ctx.encrypt_message(b"bob", plaintext, None).unwrap();
    let decrypted = bob_ctx.decrypt_message(b"alice", &encrypted, None).unwrap();
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_multiple_messages() {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"password")).unwrap();
    let _identity = ctx.generate_identity().unwrap();
    let _session = ctx.create_session(b"peer").unwrap();
    
    // Send multiple messages
    for i in 0..100 {
        let msg = format!("Message {}", i);
        let encrypted = ctx.encrypt_message(b"peer", msg.as_bytes(), None).unwrap();
        assert!(!encrypted.is_empty());
    }
}

#[test]
fn test_large_message() {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"password")).unwrap();
    let _identity = ctx.generate_identity().unwrap();
    let _session = ctx.create_session(b"peer").unwrap();
    
    // 1 MB message
    let plaintext = vec![0x42u8; 1024 * 1024];
    let encrypted = ctx.encrypt_message(b"peer", &plaintext, None).unwrap();
    
    assert!(!encrypted.is_empty());
    assert!(encrypted.len() > plaintext.len()); // Should include overhead
}

#[test]
fn test_group_messaging() {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"password")).unwrap();
    
    // Create a group
    let group_id = [0x42u8; 32];
    ctx.create_group(group_id).unwrap();
    
    // Add members
    let member1 = [0x01u8; 32];
    let member2 = [0x02u8; 32];
    ctx.add_group_member(&group_id, member1).unwrap();
    ctx.add_group_member(&group_id, member2).unwrap();
    
    // Encrypt group message
    let plaintext = b"Hello, Group!";
    let message = ctx.encrypt_group_message(&group_id, plaintext).unwrap();
    
    assert_eq!(message.group_id, group_id);
}

#[test]
fn test_context_stats() {
    let config = Config::default();
    let ctx = SecureContext::new(config, Some(b"password")).unwrap();
    
    let stats = ctx.stats();
    assert_eq!(stats.session_count, 0);
    assert_eq!(stats.group_count, 0);
    assert_eq!(stats.version, VERSION);
}

#[test]
fn test_rate_limiting() {
    let mut config = Config::default();
    config.enable_rate_limiting = true;
    
    let ctx = SecureContext::new(config, Some(b"password")).unwrap();
    let _identity = ctx.generate_identity().unwrap();
    
    // Should allow normal usage
    for _ in 0..5 {
        let _ = ctx.create_session(b"peer");
    }
}

#[test]
fn test_key_generation() {
    let key1 = crypto::KeyGenerator::generate_key().unwrap();
    let key2 = crypto::KeyGenerator::generate_key().unwrap();
    
    // Keys should be different
    assert_ne!(key1.as_ref(), key2.as_ref());
    
    // Keys should be 32 bytes
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
}

#[test]
fn test_encryption_roundtrip() {
    let key = crypto::KeyGenerator::generate_key().unwrap();
    let handler = crypto::CryptoHandler::new(key.as_ref()).unwrap();
    
    let plaintext = b"Hello, World!";
    let ad = b"associated data";
    
    let ciphertext = handler.encrypt(plaintext, ad).unwrap();
    let decrypted = handler.decrypt(&ciphertext, ad).unwrap();
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_encryption_with_wrong_key() {
    let key1 = crypto::KeyGenerator::generate_key().unwrap();
    let key2 = crypto::KeyGenerator::generate_key().unwrap();
    
    let handler1 = crypto::CryptoHandler::new(key1.as_ref()).unwrap();
    let handler2 = crypto::CryptoHandler::new(key2.as_ref()).unwrap();
    
    let plaintext = b"Hello, World!";
    let ciphertext = handler1.encrypt(plaintext, b"").unwrap();
    
    // Should fail with wrong key
    assert!(handler2.decrypt(&ciphertext, b"").is_err());
}

#[test]
fn test_safety_number() {
    let key1 = [0x42u8; 32];
    let key2 = [0x24u8; 32];
    
    let sn1 = safety::SafetyNumber::calculate(&key1, &key2);
    let sn2 = safety::SafetyNumber::calculate(&key2, &key1);
    
    // Order shouldn't matter
    assert!(sn1.verify(&sn2));
    
    // Should be 60 digits
    let digits: String = sn1.as_string().chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 60);
}

#[test]
fn test_validation() {
    // Valid message
    assert!(validation::validate_message(b"hello").is_ok());
    
    // Empty message
    assert!(validation::validate_message(b"").is_err());
    
    // Valid key
    let key = [0x42u8; 32];
    assert!(validation::validate_key(&key).is_ok());
    
    // All zeros key (weak)
    assert!(validation::validate_key(&[0u8; 32]).is_err());
    
    // Valid password
    assert!(validation::validate_password(b"Password123").is_ok());
    
    // Weak password
    assert!(validation::validate_password(b"weak").is_err());
}

#[test]
fn test_chain_key() {
    let key = [0x42u8; 32];
    let mut chain = ratchet::ChainKey::new(key);
    
    let mk1 = chain.next_message_key().unwrap();
    let mk2 = chain.next_message_key().unwrap();
    
    // Each message key should be different
    assert_ne!(mk1, mk2);
}

#[test]
fn test_sender_key() {
    let mut key = group::SenderKey::new(1).unwrap();
    
    let mk1 = key.next_message_key().unwrap();
    let mk2 = key.next_message_key().unwrap();
    
    assert_ne!(mk1, mk2);
}

#[test]
fn test_random_generation() {
    let mut rng = crypto::SecureRandom::new().unwrap();
    
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    
    rng.fill_bytes(&mut buf1);
    rng.fill_bytes(&mut buf2);
    
    // Should be different (with extremely high probability)
    assert_ne!(buf1, buf2);
}

#[test]
fn test_constant_time_comparison() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];
    
    assert!(crypto::constant_time_eq(&a, &b));
    assert!(!crypto::constant_time_eq(&a, &c));
}

#[test]
fn test_hkdf_derivation() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"info";
    
    let key1 = crypto::kdf::HkdfKdf::derive(ikm, Some(salt), info, 32).unwrap();
    let key2 = crypto::kdf::HkdfKdf::derive(ikm, Some(salt), info, 32).unwrap();
    
    // Should be deterministic
    assert_eq!(key1, key2);
    
    // Different info should give different key
    let key3 = crypto::kdf::HkdfKdf::derive(ikm, Some(salt), b"different", 32).unwrap();
    assert_ne!(key1, key3);
}

#[test]
fn test_prekey_bundle() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    
    // Generate signing key
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_key = signing_key.verifying_key().to_bytes();
    
    // Generate signed prekey
    let signed_prekey_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
    let signed_prekey = x25519_dalek::PublicKey::from(&signed_prekey_secret).to_bytes();
    
    // Sign the prekey
    let signature = signing_key.sign(&signed_prekey).to_bytes();
    
    let bundle = handshake::PreKeyBundle::new(
        identity_key,
        signed_prekey,
        signature,
        None,
    );
    
    assert!(bundle.validate().is_ok());
}

#[test]
fn test_rate_limiter() {
    let limiter = rate_limit::RateLimiter::new();
    
    // Should allow first request
    assert!(limiter.check("decrypt", "client1").is_ok());
    
    // Get remaining quota
    let quota = limiter.remaining("decrypt", "client1").unwrap();
    assert_eq!(quota.per_second, 4);
}
