# 🔐 File Encryption & Decryption Tool

A command-line C program that encrypts and decrypts files **in-place** using three different cipher methods: Caesar, XOR, and AES-128. Includes password protection, strength validation, and a security question-based password recovery system.

---

## 📋 Features

- **Three encryption methods:**
  - Caesar Cipher — educational, simple shift cipher (very weak)
  - XOR Cipher — moderate security, key derived from password
  - AES-128 — strong encryption with PKCS#7 padding (recommended)
- **Password protection** with DJB2 hashing
- **Password strength checker** (requires uppercase + digit + min 6 chars)
- **Security question & answer** for password recovery
- **In-place file modification** — overwrites the original file
- **Encryption log** written to `encrypt.log`
- **Masked password input** using `getch()` (displays `*`)

---

## 📁 Project Structure

```
PSP_CP.C          # Main source file (all logic in one file)
encrypt.log       # Auto-generated log of encrypt/decrypt events
README.md         # This file
```

---

## 🛠️ Build Instructions

### Requirements
- C compiler (GCC, MSVC, or Turbo C)
- `<conio.h>` — **Windows / DOS only** (used for `getch()`)

> ⚠️ This program uses `<conio.h>` which is **not available on Linux/macOS** without a compatibility layer. It is designed for **Windows** or **Turbo C / DOS** environments.

### Compile with GCC (Windows / MinGW)
```bash
gcc PSP_CP.C -o encrypt.exe
```

### Compile with MSVC
```bash
cl PSP_CP.C
```

---

## 🚀 Usage

Run the compiled executable:
```bash
./encrypt.exe      # Windows
```

You will be presented with a menu:
```
<---------------------------------------------------------->
          FILE ENCRYPTION & DECRYPTION TOOL
         Caesar | XOR | AES-128  Encryption
<---------------------------------------------------------->

  Main Menu
------------------------------------------------------
    1. Encrypt a file (in-place)
    2. Decrypt a file (in-place)
    3. Exit
```

### Encrypting a File
1. Choose **option 1**
2. Enter the file path to encrypt
3. Choose an encryption method (1 = Caesar, 2 = XOR, 3 = AES-128)
4. If Caesar: enter a shift value (1–25)
5. Enter and confirm a password
6. Set up a security question for recovery
7. The file is encrypted **in-place** (original is overwritten)

### Decrypting a File
1. Choose **option 2**
2. Enter the path of the encrypted file
3. If Caesar: enter the shift value used during encryption
4. Enter the password
5. If the password is wrong, you may attempt recovery via security question
6. The file is decrypted **in-place** (restored to original content)

---

## 🔒 Encryption Details

### File Format (Encrypted)
Encrypted files begin with a custom binary header:

| Field           | Type            | Size     | Description                        |
|-----------------|-----------------|----------|------------------------------------|
| Magic           | `char[4]`       | 4 bytes  | `"FENC"` — identifies encrypted files |
| Method          | `int`           | 4 bytes  | 1 = Caesar, 2 = XOR, 3 = AES-128  |
| Password Hash   | `unsigned int`  | 4 bytes  | DJB2 hash of password              |
| Original Size   | `long`          | 4/8 bytes| Original file size before padding  |
| Security Q Index| `int`           | 4 bytes  | Index of chosen security question  |
| Security A Hash | `unsigned int`  | 4 bytes  | DJB2 hash of security answer       |
| Stored Password | `unsigned char[64]` | 64 bytes | XOR-scrambled password (for recovery) |
| Encrypted Data  | `unsigned char*`| variable | The actual encrypted file content  |

### AES-128 Implementation
- Custom from-scratch AES-128 implementation (no external library)
- Uses standard AES S-box, inverse S-box, and round constants
- Key derived from password via XOR folding + chaining
- PKCS#7 padding applied before encryption
- ECB mode (each 16-byte block encrypted independently)

### XOR Cipher
- Each byte of the file is XOR'd with the corresponding byte of the password (cyclic)

### Caesar Cipher
- Shifts alphabetic characters by the given shift value
- Non-alphabetic characters are left unchanged

---

## ⚠️ Limitations & Notes

- **ECB mode for AES** — identical plaintext blocks produce identical ciphertext blocks. Not recommended for production use.
- **Password stored in header** (XOR-scrambled) — an attacker with access to the security answer can recover the password.
- **`<conio.h>` dependency** — limits portability to Windows/DOS.
- **In-place encryption** — if interrupted, the file may be partially overwritten and unrecoverable. Always keep a backup.
- This tool is intended for **educational/academic purposes**.

---

## 📝 Log File

All encrypt and decrypt events are appended to `encrypt.log` in the working directory:
```
[2025-06-01 14:32:10] ENCRYPT  File: secret.txt  Method: AES-128
[2025-06-01 14:35:22] DECRYPT  File: secret.txt  Method: AES-128
```

---

## 👤 Author

Built as a C programming project demonstrating file I/O, symmetric encryption algorithms, and interactive console applications.
"# FileEncryption-DecryptionTool" 
