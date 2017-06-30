# Encryption-Suite
An aggregation of different cryptographic primitives. DO NOT USE IN PRODUCTION!

## Features

- Encryption and decryption of files with one or more **elliptic curves** (at the moment only brainpoolP320r1)
- Decryption is only possible with a NitroKey HSM **private key can not leave HSM at any time**  
  (No software-based elliptic curve handling is implemented)
- Encryption with **AES-256**, ENCRYPT-THAN-MAC (HMAC SHA512), Derived Secret hashed with SHA 512 against weak bits

## file format encryption

| Name           | Length   |
| -------------- | -------- |
| file signature | 8        |
| version        | 2        |
| HAMC           | 64       |
| Meta Length    | 4        |
| Meta           | variable |
| Content        | variable |
