# Sirr – Lightweight EC Encryption Tool in Python


**Sirr** is a minimalistic Python implementation inspired by the `Sirr.app`. It enables elliptic curve key generation, encrypted key storage, and secure message encryption/decryption using ephemeral ECDH and AES-GCM. Perfect for simple privacy-focused workflows, local message sharing, and understanding ECC-based encryption.

---

## ✨ Features

- EC key generation (P-256 curve)
- Optional password-based encryption for private keys
- Encoded armored key export (`-----BEGIN KEY-----`)
- Ephemeral ECDH message encryption with AES-128-GCM
- Secure key derivation using PBKDF2 (100,000 iterations)
- Base64-encoded encrypted messages
- File-based key management

---

## 📦 Requirements

- Python 3.7+
- [`cryptography`](https://pypi.org/project/cryptography/)

Install the required package:


🔐 Generate Keys

    Choose to protect your private key with a password (recommended).

    Your keys will be displayed in armored format:

        -----BEGIN PUBLIC KEY-----

        -----BEGIN PRIVATE KEY-----

    Optionally, save them to disk in:

        ./Public_keys/

        ./Private_keys/

🛡 Encrypt Message

    Select a public key file from ./Public_keys/

    Type your message

    Get a base64-encoded encrypted string to share

🔓 Decrypt Message

    Select your private key from ./Private_keys/

    Provide the password (if used)

    Paste the encrypted message to reveal the original text

.
├── sirr.py
├── Public_keys/
└── Private_keys/


🔐 Security Notes

    Uses Elliptic Curve Diffie-Hellman (ECDH) over SECP256R1

    Symmetric encryption with AES-128-GCM

    Private key encryption uses PBKDF2 with 100,000 iterations

    No external communication: all operations are local

    Do not share your private key

    Passwords are never shown on screen
