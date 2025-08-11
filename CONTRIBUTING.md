# 🤝 Contributing to Vaultora

We welcome contributions that improve Vaultora’s security, performance, and usability.  
Please follow these guidelines to keep our project safe and maintainable.

---

## 📌 How to Contribute

1. **Fork** the repository.  
2. **Clone** your fork:
   ```bash
   git clone https://github.com/your-username/vaultora.git
   ```
3. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-new-feature
   ```
4. **Make your changes** (ensure all tests pass).
5. **Commit your changes:**
   ```bash
   git commit -m "feat: add my new feature"
   ```
6. **Push your branch and open a Pull Request.**

---

## 🔒 Security Considerations

- **Never commit secrets or sensitive data.**
- Avoid introducing dependencies with known vulnerabilities (`npm audit`).
- Follow our [SECURITY.md](./SECURITY.md) for responsible disclosure.

---

## ✅ Code Style

- Use Prettier and ESLint rules configured in the repo.
- Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format:
  - `feat`: new features
  - `fix`: bug fixes
  - `chore`: maintenance tasks

---

## 🧪 Testing

- All new code **must include unit tests**.
- Run tests before submitting a PR:
  ```bash
  npm test
  ```

---

## 📜 License

By contributing, you agree your code will be licensed under the same license as Vaultora (MIT unless otherwise specified).
