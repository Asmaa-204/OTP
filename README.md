# Secure Communication System using One-Time Pad Stream Cipher

![Cryptography](https://img.shields.io/badge/Cryptography-Secure-green) 
![Python](https://img.shields.io/badge/Python-3.x-blue)

## Overview
A secure communication system implementing a one-time pad stream cipher with Diffie-Hellman key exchange, AES-256 seed encryption, and HMAC-SHA256 authentication.

## Features
- 🔒 End-to-end encrypted communication
- ⚡ Diffie-Hellman key exchange (2048-bit)
- 🔑 AES-256 encrypted seed transmission
- ✔️ HMAC-SHA256 message authentication
- 🔄 Linear Congruential Generator (LCG) for keystream
- 📦 Chunked data transmission

## Protocol Flow

```diff
+ Sender                               Receiver
|--- Generate key pair                 |--- Generate key pair
|<-- Exchange public keys ------------>|
|--- Derive shared secret key          | shared secret key

+ Seed Exchange:
|--- Generate random seed              |
|--- Encrypt seed with AES-256         |
|--- Generate HMAC-SHA256              |
|-- Send encrypted seed + HMAC ------->|
                                       |--- Verify HMAC
                                       |--- Decrypt seed

+ Message Exchange:
|--- Generate keystream (LCG)          |
|--- Encrypt message in chunks         |
|-- Send encrypted chunks -->          |
                                       |--- Decrypt chunks
                                       |--- Reconstruct message

```



## Quick Start

1. Install dependencies:
```bash
pip install cryptography
```

2. Start the receiver first:
```bash
python main.py
# Choose 'r' for receiver
```

3. Start the sender in a new terminal:
```bash
python main.py
# Choose 's' for sender
```

## Requirements

- Python 3.7+
- cryptography package
- Linux/Unix environment

## Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/shehab299">
        <img src="https://github.com/shehab299.png" width="100px;" alt="Contributor 1"/><br />
        <sub><b>Shehab Khaled</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/asmaa-204">
        <img src="https://github.com/asmaa-204.png" width="100px;" alt="Contributor 2"/><br />
        <sub><b>Asmaa Abozaid</b></sub>
      </a>
    </td>
  </tr>
</table>