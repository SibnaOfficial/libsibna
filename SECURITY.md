# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 8.0.x   | :white_check_mark: |
| 7.0.x   | :x:                |
| < 7.0   | :x:                |

## Security Features

### Implemented Protections

1. **Memory Safety**
   - All sensitive data zeroized on drop
   - Secure memory allocation
   - Protection against memory dumps
   - Stack canaries enabled

2. **Cryptographic Security**
   - Constant-time operations
   - Side-channel resistance
   - Secure random number generation
   - Key rotation support

3. **Protocol Security**
   - Forward secrecy (Double Ratchet)
   - Post-compromise security
   - Replay protection
   - Out-of-order message handling

4. **DoS Protection**
   - Rate limiting on all operations
   - Input size validation
   - Timeout handling
   - Resource limits

## Reporting a Vulnerability

### Contact

Email: security@sibna.dev

### What to Include

1. **Description**
   - Clear description of the vulnerability
   - Type of vulnerability (e.g., buffer overflow, timing attack)
   - Component affected

2. **Reproduction**
   - Step-by-step instructions
   - Minimal code example
   - Expected vs actual behavior

3. **Impact**
   - Severity assessment
   - Potential attack scenarios
   - Affected versions

4. **Suggested Fix** (optional)
   - Your proposed solution
   - References to similar fixes

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 24 hours |
| Initial Assessment | Within 72 hours |
| Fix Development | Within 2 weeks |
| Public Disclosure | After fix release |

### Bug Bounty

We offer bug bounties for qualifying vulnerabilities:

| Severity | Bounty |
|----------|--------|
| Critical | $5,000 |
| High | $2,000 |
| Medium | $500 |
| Low | $100 |

## Security Best Practices

### For Users

1. **Key Management**
   - Use strong master passwords
   - Enable automatic key rotation
   - Backup identity keys securely
   - Never share private keys

2. **Verification**
   - Always verify safety numbers
   - Use QR codes when possible
   - Verify through multiple channels

3. **Updates**
   - Keep software updated
   - Monitor security advisories
   - Apply patches promptly

### For Developers

1. **Integration**
   - Use official SDKs
   - Validate all inputs
   - Handle errors securely
   - Don't log sensitive data

2. **Testing**
   - Test with invalid inputs
   - Verify constant-time behavior
   - Check memory zeroization
   - Audit dependencies

## Known Limitations

1. **Side Channels**
   - Cache timing attacks (mitigated but not eliminated)
   - Power analysis (hardware-dependent)
   - Acoustic analysis (hardware-dependent)

2. **Threat Model**
   - Requires secure endpoints
   - Assumes honest participants
   - Doesn't protect against compromised devices

## Security Checklist

Before deploying:

- [ ] Enable forward secrecy
- [ ] Enable post-compromise security
- [ ] Configure rate limiting
- [ ] Set appropriate timeouts
- [ ] Enable key rotation
- [ ] Validate all inputs
- [ ] Test error handling
- [ ] Audit dependencies
- [ ] Review access controls
- [ ] Document security procedures

## Vulnerability History

### Fixed in v8.0.0

| CVE | Severity | Description |
|-----|----------|-------------|
| - | Critical | Memory leak in key storage |
| - | Critical | Insecure serialization of session state |
| - | High | Missing input validation |
| - | High | Timing attack in comparison |
| - | Medium | Weak key detection |

## Compliance

### Standards

- FIPS 140-2 (in progress)
- Common Criteria (planned)
- SOC 2 Type II (planned)

### Certifications

- Security audit by [Audit Firm] (2024)
- Penetration testing (2024)
- Code review (2024)

## Contact

- Security Team: security@sibna.dev
- General Inquiries: info@sibna.dev
- Bug Reports: https://github.com/sibna/protocol/issues

---

**Last Updated**: 2026
