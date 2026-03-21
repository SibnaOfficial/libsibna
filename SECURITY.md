# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 9.0.x | ✅ |
| 8.x | ❌ — contains critical vulnerabilities, upgrade immediately |
| < 8.0 | ❌ |

---

## Audit status

Sibna Protocol has undergone **internal security hardening** in v9, which resolved 16 issues across critical, high, and medium severity. This is **not** an independent external audit.

An external audit by a specialized cryptography firm has **not yet been conducted**. This is a known gap. Until an external audit is complete, do not use this library in production systems handling sensitive data.

---

## Reporting a vulnerability

**Do not open public GitHub issues for security reports.**

Email: [security@sibna.dev](mailto:security@sibna.dev)

Please include:

- A clear description of the vulnerability and the component affected
- Step-by-step reproduction instructions with a minimal code example
- Your assessment of the severity and potential impact
- A suggested fix if you have one (optional)

### Response timeline

| Stage | Timeline |
|---|---|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

We follow coordinated disclosure. We will credit reporters in the changelog unless they prefer to remain anonymous.

---

## Security properties

### What the protocol provides

- **Forward secrecy** — Double Ratchet rotates keys on every message. Compromise of the current state does not expose past messages.
- **Post-compromise security** — A new DH ratchet step after compromise re-establishes security.
- **AEAD encryption** — ChaCha20-Poly1305 with unique nonces. Any ciphertext modification is detected and rejected.
- **Replay protection** — Per-session message counters prevent replay of old ciphertexts.
- **Identity verification** — 80-digit safety numbers allow out-of-band verification against MITM.
- **Memory zeroization** — All key material is zeroed on drop via `ZeroizeOnDrop`. No keys linger in heap memory after use.
- **Constant-time comparisons** — Authentication tag comparison and safety number verification use constant-time operations.
- **DoS protection** — Every cryptographic entry point is rate-limited per operation and per client.

### What is outside the threat model

- **Device-level compromise** — An OS or hardware attacker with access to process memory breaks all guarantees.
- **Metadata** — The protocol does not hide who communicates, when, or how often. Metadata protection requires a separate transport layer.
- **Safety number verification skipped** — MITM attacks are only prevented if users verify safety numbers out-of-band. The protocol cannot enforce this.
- **No external audit** — Internal hardening is not a substitute for review by an independent cryptography firm.

### Known limitations

- **Side channels** — Constant-time operations are implemented in software. Hardware-level side channels (power analysis, acoustic analysis) are not addressed and are hardware-dependent.
- **Cache timing** — Mitigated but not fully eliminated on all microarchitectures.

---

## Security hardening — v9

The following issues were resolved in v9 during internal code review:

| Severity | Count | Examples |
|---|---|---|
| Critical | 5 | `mac_key` leaked in QR payload · `shared_secret` returned to API caller · HKDF `expand()` called twice on same PRK · `keystore::from_bytes` panicked on invalid input · `derive_key` used `?` in non-Result return type |
| High | 6 | Group decrypt DoS via unbounded skip (`MAX_SKIP_GROUP=500` added) · `Encryptor` counter initialized to `u64::MAX` · 4 production panics in `skip_message_keys` · `add_group_member` silently ignored error · `builder.rs` production `unwrap()` · `constant_time_cmp` documented as non-constant-time |
| Medium | 5 | `MAX_AD_LEN` mismatch between validation (1024) and crypto (256) layers · FFI `last_error` always returned generic string · `burst_tokens=100` initialization bypassed rate limiter · X3DH empty HKDF salt · 30 debug log files in repository |

**Result:** zero `.unwrap()` or `.expect()` in production code paths. All error handling propagates via `Result`.

All HKDF domain separation constants use `_v9` suffix throughout. Sessions established with v8 are **not** compatible with v9 — this break is intentional, because v8 contained critical vulnerabilities.

Full details in [CHANGELOG.md](CHANGELOG.md).

---

## For developers integrating Sibna

- Use the official SDKs (`sdks/flutter`, `sdks/python`, `sdks/javascript`, `sdks/cpp`)
- Do not log key material, plaintext, or safety numbers
- Always verify safety numbers through an out-of-band channel before trusting a session
- Handle all errors — the SDK returns `Result` everywhere, do not silently ignore failures
- Run `cargo audit` regularly against the upstream advisory database
- Subscribe to this repository's security advisories on GitHub

### Deployment checklist

- [ ] Rate limiting is enabled in `Config`
- [ ] `max_skipped_messages` is bounded (default: 500)
- [ ] Passwords meet the minimum requirements (uppercase + lowercase + digit, ≥ 8 chars)
- [ ] Safety number verification is implemented in your UI
- [ ] Sensitive data is not written to logs
- [ ] Dependencies are up to date (`cargo audit`, `cargo deny check`)
- [ ] An external security audit has been completed before handling sensitive production data

---

## Contact

- Security reports: [security@sibna.dev](mailto:security@sibna.dev)
- General inquiries: [info@sibna.dev](mailto:info@sibna.dev)
- GitHub security advisories: [github.com/SibnaOfficial/sibna-protc/security](https://github.com/SibnaOfficial/sibna-protc/security)

---

*Last updated: March 2026*
