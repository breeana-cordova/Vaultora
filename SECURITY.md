# 🔒 Security Policy — Vaultora

Security is at the core of Vaultora.  
We follow a **zero-knowledge, end-to-end encryption** model to ensure that your sensitive data remains yours — always.

---

## 📢 Reporting a Vulnerability

If you discover a security issue in Vaultora:

1. **Do NOT** open a public GitHub issue.
2. Email us at: **security@vaultora.dev**
3. Include:
   - A clear description of the vulnerability.
   - Steps to reproduce the issue.
   - Any relevant logs, screenshots, or proof-of-concept code.

We will:
- Acknowledge your report within **48 hours**.
- Provide a status update within **5 business days**.
- Work with you on a safe timeline for public disclosure.

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure) practices.

---

## 🛡️ Security Principles

- **Zero-Knowledge Architecture:** We never store your master password or unencrypted data.
- **Client-Side Encryption:** All vault data is encrypted before leaving your device.
- **Strong Key Derivation:** Argon2id with unique per-user salts.
- **Secure Authentication:** Master password hashes stored with bcrypt/Argon2.
- **Transport Security:** TLS 1.3 for all network traffic.
- **Defense-in-Depth:** Multiple layers of protection including rate limiting, suspicious activity alerts, and vault auto-lock.

---

## 🧪 Security Testing

We regularly:
- Perform **static code analysis**.
- Run **dependency scanning** with Dependabot and npm audit.
- Conduct **penetration tests** before major releases.
- Monitor public CVE databases for vulnerabilities affecting dependencies.

---

## 🤝 Security Researchers

We value contributions from the security community.  
If your report is valid and leads to a confirmed fix, we may publicly acknowledge your work in our **Security Hall of Fame** (with your consent).

---

<p align="center"><sub>© 2025 Vaultora — Secure by Design</sub></p>
