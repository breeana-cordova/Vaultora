<p align="center">
  <img src="docs/logo-placeholder.svg" alt="Vaultora Logo" width="120" height="120" />
</p>

<h1 align="center">🔐 Vaultora</h1>
<p align="center">
  A zero-knowledge, end-to-end encrypted password manager that keeps your secrets safe on any device.
</p>

<p align="center">
  <a href="https://github.com/yourusername/vaultora/actions"><img src="https://img.shields.io/github/actions/workflow/status/yourusername/vaultora/ci.yml?branch=main&label=Build" alt="Build Status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License" /></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-responsible%20disclosure-brightgreen" alt="Security Policy" /></a>
</p>

---

## 📜 Overview
Vaultora is a **modern password manager** built with a **zero-knowledge architecture**, meaning only *you* can access your vault — not even our servers can decrypt it.  
All encryption and decryption happen **client-side**, using **AES-256-GCM** and keys derived with **Argon2id**.

## ✨ Features
- **🔐 Zero-knowledge security** — only you hold the keys
- **⚡ Client-side AES-256-GCM encryption**
- **🛡️ Argon2id key derivation** for strong protection
- **📱 Cross-platform** — designed for web, desktop, and mobile
- **🔑 Two-factor authentication (TOTP)**
- **☁️ Encrypted cloud sync** with TLS 1.3
- **🔍 Suspicious login detection & alerts**

## 🛠️ Tech Stack
- **Frontend:** React + TypeScript + Web Crypto API
- **Backend:** Node.js + Express + PostgreSQL
- **Crypto:** Web Crypto API (AES-GCM), Argon2id (WASM)
- **CI/CD:** GitHub Actions + Dependabot + CodeQL
- **Security Auditing:** OWASP ZAP, Trivy

## 🚀 Getting Started

### 1️⃣ Clone the repo
```bash
git clone https://github.com/yourusername/vaultora.git
cd vaultora
