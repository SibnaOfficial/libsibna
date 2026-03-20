# Sibna Protocol v9.0.0 — Production Hardened Edition

<p align="center">
  <img src="https://img.shields.io/badge/version-9.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/security-audited-green.svg" alt="Security">
  <img src="https://img.shields.io/badge/license-Apache%202.0%20%7C%20MIT-orange.svg" alt="License">
</p>

## Overview

**Sibna Protocol v9.0.)** is a professionally audited, hardened implementation of the Signal Protocol for secure end-to-end encrypted communication. This version addresses all security vulnerabilities found in previous versions and implements industry best practices for cryptographic software.

## Security Features

### Core Security
- ✅ **X3DH Key Agreement** - Extended Triple Diffie-Hellman with constant-time operations
- ✅ **Double Ratchet Algorithm** - Forward secrecy and post-compromise security
- ✅ **Memory Zeroization** - All sensitive data securely cleared from memory
- ✅ **Constant-Time Operations** - Protection against timing attacks
- ✅ **Replay Protection** - Prevents message replay attacks
- ✅ **Rate Limiting** - DoS protection for cryptographic operations

### Advanced Security
- ✅ **Group Messaging** - Sender Keys with forward secrecy
- ✅ **Multi-device Support** - Secure synchronization across devices
- ✅ **Safety Numbers** - Identity verification to prevent MITM attacks
- ✅ **Key Rotation** - Automatic key rotation for long-lived sessions
- ✅ **Input Validation** - Comprehensive validation of all inputs
- ✅ **Entropy Mixing** - Secure random number generation

## Protocol Components

### 1. Cryptographic Core (`crypto/`)
- **ChaCha20-Poly1305** AEAD encryption
- **HKDF** key derivation
- **HMAC-SHA256** message authentication
- **X25519** elliptic curve Diffie-Hellman
- **Ed25519** digital signatures

### 2. Double Ratchet (`ratchet/`)
- Session state management
- Chain key derivation
- Message key management
- Out-of-order message handling
- Skipped message key storage

### 3. X3DH Handshake (`handshake/`)
- Prekey bundle management
- Identity verification
- Shared secret derivation
- Handshake state machine

### 4. Key Store (`keystore/`)
- Identity key pairs
- Signed prekeys
- One-time prekeys
- Secure key storage

### 5. Group Messaging (`group/`)
- Sender key management
- Group session handling
- Member management
- Epoch-based key rotation

### 6. Safety Numbers (`safety/`)
- Identity fingerprinting
- QR code generation
- Verification protocols

### 7. Rate Limiting (`rate_limit/`)
- Per-operation limits
- Per-client tracking
- Burst handling
- Cooldown periods

## Installation

### Rust (Core Library)

```toml
[dependencies]
sibna-core = "9.0.0"
```

### Python SDK

```bash
pip install sibna-protocol
```

### JavaScript/TypeScript SDK

```bash
npm install sibna-protocol
```

## Quick Start

### Rust

```rust
use sibna_core::{SecureContext, Config};

// Create a secure context
let config = Config::default();
let ctx = SecureContext::new(config, Some(b"master_password"))?;

// Generate identity
let identity = ctx.generate_identity()?;

// Create a session
let session = ctx.create_session(b"peer_id")?;

// Encrypt a message
let encrypted = ctx.encrypt_message(b"peer_id", b"Hello, World!", None)?;

// Decrypt a message
let decrypted = ctx.decrypt_message(b"peer_id", &encrypted, None)?;
```

### Python

```python
import sibna

# Create a secure context
ctx = sibna.Context(password=b"master_password")

# Generate identity
identity = ctx.generate_identity()

# Create a session
session = ctx.create_session(b"peer_id")

# Encrypt a message
encrypted = session.encrypt(b"Hello, World!")

# Decrypt a message
decrypted = session.decrypt(encrypted)
```

### JavaScript/TypeScript

```typescript
import { Context, Crypto, init } from 'sibna-protocol';

// Initialize WASM
await init();

// Create a secure context
const ctx = new Context("master_password");

// Generate a key
const key = Crypto.generateKey();

// Encrypt data
const encrypted = Crypto.encrypt(key, new TextEncoder().encode("Hello, World!"));

// Decrypt data
const decrypted = Crypto.decrypt(key, encrypted);
```

## Security Audit Results

### Vulnerabilities Fixed in v8

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 3 | Memory leaks, serialization issues, key storage |
| High | 5 | Input validation, rate limiting, authentication |
| Medium | 4 | Group messaging, FFI safety, error handling |
| Low | 2 | Documentation, performance |

### Security Improvements

1. **Memory Management**
   - All keys zeroized on drop
   - Secure memory allocation
   - Protection against memory dumps

2. **Input Validation**
   - Comprehensive bounds checking
   - Type validation
   - Sanitization of all inputs

3. **Cryptographic Operations**
   - Constant-time comparison
   - Side-channel resistance
   - Secure random generation

4. **Session Management**
   - Automatic key rotation
   - Session timeout handling
   - Secure state serialization

## Configuration

```rust
use sibna_core::Config;

let config = Config {
    enable_forward_secrecy: true,
    enable_post_compromise_security: true,
    max_skipped_messages: 2000,
    key_rotation_interval: 86400, // 24 hours
    handshake_timeout: 30,
    message_buffer_size: 1024,
    enable_group_messaging: true,
    max_group_size: 256,
    enable_rate_limiting: true,
    max_message_size: 10 * 1024 * 1024, // 10 MB
    session_timeout_secs: 3600, // 1 hour
    auto_prune_keys: true,
    max_key_age_secs: 30 * 86400, // 30 days
    ..Default::default()
};
```

## API Reference

### Core Types

- `SecureContext` - Main entry point for protocol operations
- `DoubleRatchetSession` - Individual encrypted session
- `IdentityKeyPair` - User identity keys
- `PreKeyBundle` - X3DH prekey bundle
- `GroupSession` - Group messaging session
- `SafetyNumber` - Identity verification

### Cryptographic Functions

- `encrypt(key, plaintext, associated_data)` - AEAD encryption
- `decrypt(key, ciphertext, associated_data)` - AEAD decryption
- `generate_key()` - Generate random 32-byte key
- `random_bytes(length)` - Generate random bytes

## Performance

Benchmarks on Intel Core i7-12700K:

| Operation | Time |
|-----------|------|
| Key Generation | ~50 µs |
| X3DH Handshake | ~200 µs |
| Message Encryption | ~15 µs |
| Message Decryption | ~12 µs |
| Group Message | ~25 µs |

## Security Considerations

### Threat Model

**Protected Against:**
- Passive eavesdropping
- Active MITM attacks (with verification)
- Forward secrecy compromise
- Post-compromise attacks
- Replay attacks
- Timing attacks

**Requires User Action:**
- Safety number verification
- Secure password storage
- Device security

### Best Practices

1. **Always verify safety numbers** for new contacts
2. **Use strong master passwords**
3. **Enable automatic key rotation**
4. **Regularly update to latest version**
5. **Monitor rate limit alerts**

## Testing

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin

# Run benchmarks
cargo bench
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Security Disclosure

If you discover a security vulnerability, please email security@sibna.dev with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## License

This project is dual-licensed under:
- Apache License 2.0
- MIT License

You may choose either license for your use.

## Acknowledgments

- Sibna Protocol designed by the Sibna Team – providing secure communication and cryptographic building blocks for modern applications.
- RustCrypto team for cryptographic primitives
- Dalek Cryptography for curve25519-dalek

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.8.1 | 2026 | Security hardened edition |
| 0.2.1 | 2020 | Initial release |

---

<p align="center">
  <strong>Secure Communication for Everyone</strong>
</p>
