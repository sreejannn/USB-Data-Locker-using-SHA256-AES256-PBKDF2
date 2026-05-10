# USB Data Locker using AES-256, PBKDF2 & SHA-256

A desktop-based file encryption tool developed in Python to securely protect sensitive files stored on USB drives or local systems.

This project was built as part of our B.Tech major project with the objective of creating a practical and lightweight encryption utility that combines modern cryptographic techniques with a simple user-friendly interface. Unlike traditional full-disk encryption tools, this application focuses on securing individual files using password-based encryption.

The project uses:
- AES-256-GCM for encryption
- PBKDF2-HMAC-SHA256 for secure key derivation
- SHA-256 based hashing concepts
- Secure overwrite deletion
- PyQt5 for the graphical user interface

---

# Why This Project?

USB drives are still widely used for storing:
- academic documents
- project files
- backups
- confidential data

The issue is that most removable storage devices are used without any protection. If the USB drive is lost or accessed by someone else, the data can easily be exposed.

This project was developed to provide:
- strong encryption
- password-based protection
- secure file handling
- an easy-to-use desktop interface

without making the workflow complicated for normal users.

---

# Features

- AES-256-GCM based file encryption
- Password-derived key generation using PBKDF2
- Drag-and-drop file support
- Multi-threaded encryption & decryption workflow
- Secure file decryption
- Optional self-destruct mode after multiple failed attempts
- Secure overwrite deletion
- Hidden file support after encryption
- Progress tracking and activity logs
- Cross-platform implementation using Python
- Executable packaging using PyInstaller

---

# Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core application development |
| PyQt5 | Desktop GUI |
| cryptography | AES & PBKDF2 implementation |
| hashlib | SHA-256 hashing support |
| PyInstaller | Executable generation |
| os / subprocess | File handling and hiding |

---

# How the Encryption Works

```text
User Password
      ↓
PBKDF2 Key Derivation
      ↓
256-bit AES Key Generated
      ↓
AES-256 Encryption
      ↓
Encrypted .cl File
