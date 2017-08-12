# Encryption-Suite
An aggregation of different cryptographic primitives. DO NOT USE IN PRODUCTION YET!

## Features

- Encryption and decryption of files with one or more **elliptic curves** (at the moment only brainpoolP320r1)
- Decryption is only possible with a NitroKey HSM **private key can not leave HSM at any time**  
  (No software-based elliptic curve handling is implemented)
- Encryption with **AES-256**, ENCRYPT-THAN-MAC (HMAC SHA512), Derived Secret hashed with SHA 512 against weak bits

## Simple Sample

### Symmetric Encryption

```c#
var pwd = "MyPassword";
File.WriteAllText(this.InputFile, "My Stuff");

SymmetricEncryption.Encrypt(this.InputFile, this.EncryptedFile, pwd);
var info = SymmetricEncryption.Decrypt(this.EncryptedFile, this.PlainFile, pwd);

Console.Out.WriteLine(info.FileName);
Console.Out.WriteLine(File.ReadAllText(this.PlainFile));
```

### Hybrid Encryption

```c#
File.WriteAllText(this.InputFile, "My Stuff");

var encryptionParameter = new HybridEncryption.EncryptionParameter
{
	PublicKeys = new[] { myPrivateKey.ExportPublicKey(), bobPublicAns1Key.ExportPublicKey() },
};

HybridEncryption.Encrypt(this.InputFile, this.EncryptedFile, encryptionParameter);

var decryptionParameter = new HybridEncryption.DecryptionParameter
{
	PrivateKey = myPrivateKey,
};
var info = HybridEncryption.Decrypt(this.EncryptedFile, this.PlainFile, decryptionParameter);

Console.Out.WriteLine(info.FileName);
Console.Out.WriteLine(File.ReadAllText(this.PlainFile));
```

## file format encryption

| Name           | Length   |
| -------------- | -------- |
| file signature | 8        |
| version        | 2        |
| HMAC           | 64       |
| Meta Length    | 4        |
| MetaInfo       | variable |
| Content        | variable |

### MetaInfo proto

![Class Diagram MetaInformation](/docs/ClassDiagramMetaInformation.png)

```proto
message MetaInformation {
   optional PasswordDerivationSettings PasswordDerivationSettings = 1;
   optional bytes SecretInformationEncrypted = 2;
   optional EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation = 3;
}
```

#### MetaInformation types

```proto
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
```

#### EllipticCurveEncryptionInformation types

```proto
message DerivedSecret {
	required bytes PublicKeyHash = 1;
	required bytes PublicKeyHashSalt = 2;
	required bytes EncryptedSharedSecret = 3;
}

message EcKeyPair {
	optional bytes PrivateKey = 1;
	required PublicKey PublicKey = 2;
}
```

#### EcKeyPair type

```proto
message PublicKey {
	required bytes Qx = 1;
	required bytes Qy = 2;
}
```

See https://developers.google.com/protocol-buffers/docs/proto
