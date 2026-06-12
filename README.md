# 🔐 Vault — Password Wallet

A **beautiful, secure, single-file** web-based password manager built entirely with Python's standard library. No pip installs. No external dependencies. Just one `.py` file.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)

---

## ✨ Features

- **Zero dependencies** — pure Python stdlib only (`http.server`, `hashlib`, `hmac`, `secrets`)
- **Master password protection** — PBKDF2-HMAC-SHA256 with 200,000 iterations
- **Encrypted storage** — all entries are encrypted at rest with a HMAC-verified XOR stream cipher derived from your master password
- **Password generator** — configurable length (8–64), uppercase, lowercase, digits, symbols
- **Password strength meter** — live visual feedback as you type
- **Categories** — Web, Finance, Email, Social, Work, Other
- **Search & filter** — instant search across titles, usernames, and URLs
- **Copy to clipboard** — one-click copy for usernames, passwords, and URLs
- **Dark vault UI** — modern dark-mode interface with no external CSS or JS frameworks
- **Auto-opens browser** — launches `http://localhost:5743` automatically on start
- **Single file** — everything (HTML, CSS, JS, Python server, crypto) lives in `password_wallet.py`

---

## 🚀 Quick Start

```bash
# Clone or download
git clone https://github.com/your-username/vault-password-wallet.git
cd vault-password-wallet

# Run — no installation needed
python password_wallet.py
```

Then open **http://localhost:5743** in your browser (it opens automatically).

> **Requirements:** Python 3.7 or higher. That's it.

---

## 🔒 Security Model

| Layer | Implementation |
|---|---|
| Key derivation | PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte random salt per entry |
| Encryption | XOR stream cipher with SHA-256 block chain (key + IV per entry) |
| Integrity | HMAC-SHA256 tag appended to every ciphertext — tamper detection |
| Master password | Stored only as a PBKDF2 verifier hash, never in plaintext |
| In-memory only | Decrypted entries live only in your browser's JS memory, never written to disk in plaintext |

> **Note:** The encryption scheme is implemented from scratch using Python's `hashlib` and `hmac` modules, with no third-party crypto libraries required. For environments with extremely sensitive data, consider auditing the crypto logic or switching to a library like `cryptography` (AES-GCM).

---

## 📁 Project Structure

```
vault-password-wallet/
├── password_wallet.py   # The entire application (server + UI + crypto)
└── wallet.json          # Auto-created on first run — your encrypted vault
```

**`wallet.json`** stores only:
- A PBKDF2 verifier of your master password
- Encrypted blobs (one per entry) — unreadable without the master password

---

## 🖥️ Usage

### First Run
1. Run `python password_wallet.py`
2. Set a **master password** (minimum 6 characters — choose something strong and memorable)
3. Your vault is created. Start adding entries.

### Adding an Entry
1. Click **+ Add** in the sidebar
2. Fill in the title, username, password, URL, and notes
3. Use the built-in **Password Generator** to create a strong password
4. Click **Save Entry**

### Locking the Vault
Click the **🔒 Lock** button in the top-right corner. All decrypted data is cleared from memory immediately.

### Generating a Password
Inside the Add/Edit modal, the **⚡ Generate** button creates a random password based on your chosen options. Click **↑ Use this password** to apply it to the entry.

---

## 📸 Screenshot

> Dark vault UI with sidebar entry list, detail panel, strength meter, and password generator.

---

## 🛠️ Configuration

| Setting | Default | Description |
|---|---|---|
| Host | `127.0.0.1` | Localhost only (not exposed to network) |
| Port | `5743` | Web server port |
| Data file | `wallet.json` | Encrypted vault file location |

To change the port, edit the `HOST, PORT` line near the bottom of `password_wallet.py`:

```python
HOST, PORT = "127.0.0.1", 5743
```

---

## ⚠️ Backup Your Vault

`wallet.json` contains all your passwords in encrypted form. **Back it up regularly.** If you lose it — or forget your master password — your data cannot be recovered.

```bash
# Simple backup example
cp wallet.json wallet_backup_$(date +%Y%m%d).json
```

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Jafar Tavana**
📧 [powerinfossl@gmail.com](mailto:powerinfossl@gmail.com)

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

*Built with ❤️ and zero dependencies.*
