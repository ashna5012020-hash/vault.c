# Password Vault in C

A console-based password vault implemented in C that securely stores credentials using a master password.

## Features
- Master password protected using SHA-256 hashing
- XOR-based encryption for stored credentials
- File-based persistent storage
- Console-driven menu system

## Technologies Used
- C
- OpenSSL (SHA-256)
- File I/O

## How to Compile
```bash
gcc vault.c -o vault -lcrypto
