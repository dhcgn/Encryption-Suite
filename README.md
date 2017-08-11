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
| HMAC           | 64       |
| Meta Length    | 4        |
| MetaInfo       | variable |
| Content        | variable |

### meta proto description

```proto
message MetaInformation {
   optional PasswordDerivationSettings PasswordDerivationSettings = 1;
   optional bytes SecretInformationEncrypted = 2;
   optional EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation = 3;
}

	message PasswordDerivationSettings {
	   required bytes Salt = 1;
	   required int32 Iterations = 2;
	}

	// Encrypted bytes set to SecretInformationEncrypted
	message SecretInformation {
	   optional string Filename = 1;
	}

	message EllipticCurveEncryptionInformation {
	   repeated DerivedSecret DerivedSecrets = 1;
	   required EcKeyPair EphemeralKey = 2;
	}

		message DerivedSecret {
		   required bytes PublicKeyHash = 1;
		   required bytes PublicKeyHashSalt = 2;
		   required bytes EncryptedSharedSecret = 3;
		}

		message EcKeyPair {
		   optional bytes PrivateKey = 1;
		   required PublicKey PublicKey = 2;
		}

			message PublicKey {
			   required bytes Qx = 1;
			   required bytes Qy = 2;
			}
```

See https://developers.google.com/protocol-buffers/docs/proto