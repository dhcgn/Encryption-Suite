﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using EncryptionSuite.Contract;
using EncryptionSuite.Encryption.MetaTypes;
using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    public class SymmetricEncryption
    {
        public const int AesKeyLength = 256 / 8;
        public const int HmacKeyLength = 256 / 8;

        #region Public

        public static DecryptInfo Decrypt(Stream input, Stream output, byte[] secret)
        {
            return DecryptInternal(input, output, secret, null, null);
        }

        public static DecryptInfo Decrypt(Stream input, Stream output, string password)
        {
            return DecryptInternal(input, output, null, password, null);
        }

        public static void Encrypt(Stream input, Stream output, string password, string filename = null)
        {
            var derivationSettings = PasswordDerivationSettings.Create();
            var secretKey = Hasher.CreateAesKeyFromPassword(password, derivationSettings.Salt, derivationSettings.Iterations);
            var parameter = new EncryptInternalParameter
            {
                Filename = filename,
                PasswordDerivationSettings = derivationSettings,
                EllipticCurveEncryptionInformation = null,
            };
            EncryptInternal(input, output, secretKey, parameter);
        }

        public static void Encrypt(Stream input, Stream output, byte[] secret, string filename = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            var parameter = new EncryptInternalParameter
            {
                Filename = filename,
                PasswordDerivationSettings = null,
                EllipticCurveEncryptionInformation = null,
            };
            EncryptInternal(input, output, secret, parameter);
        }

        #endregion

        internal static DecryptInfo DecryptInternal(Stream input, Stream output, byte[] secret, string password, DecryptInternalParameter parameter)
        {
            var tempFileName = Path.GetTempFileName();
            InformationContainer informationContainer;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                informationContainer = SeparateFromInput(tempFileStream, input);
            }

            if (password!=null)
                secret = Hasher.CreateAesKeyFromPassword(password, informationContainer.DerivationSettings.Salt, informationContainer.DerivationSettings.Iterations);

            if (parameter?.EllipticCurveDeriveKeyAction != null)
                secret = parameter?.EllipticCurveDeriveKeyAction(informationContainer.EllipticCurveEncryptionInformation);

            SecretInformation decryptedSecretInfo = null;
            if (informationContainer.SecretInformationData != null)
            {
                var memoryStream = new MemoryStream();
                DecryptInternal(new MemoryStream(informationContainer.SecretInformationData), memoryStream, secret, null, null);
                decryptedSecretInfo = SecretInformation.FromProtoBufData(memoryStream.ToArray());
            }

            using (var tempFileStream = File.OpenRead(tempFileName))
            {
                DecryptRaw(tempFileStream, output, secret, informationContainer.PublicInformation);
            }

            return new DecryptInfo
            {
                FileName = decryptedSecretInfo?.Filename,
            };
        }

        internal class EncryptInternalParameter
        {
            public PasswordDerivationSettings PasswordDerivationSettings { get; set; }
            public string Filename { get; set; }
            public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
        }

        internal static void EncryptInternal(Stream input, Stream output, byte[] secretKey, EncryptInternalParameter parameter=null)
        {
            var tempFileName = Path.GetTempFileName();

            PublicInformation publicInformation;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                publicInformation = EncryptRaw(input, tempFileStream, secretKey);
            }

            byte[] secretInformationData = null;
            if (parameter?.Filename != null)
            {
                var secretInformation = new SecretInformation
                {
                    Filename = parameter.Filename,
                };
                var secretInformationPlainData = secretInformation.ToProtoBufData();
                var encrypted = new MemoryStream();
                EncryptInternal(new MemoryStream(secretInformationPlainData), encrypted, secretKey);
                secretInformationData = encrypted.ToArray();
            }

            var fileMetaInfo = new InformationContainer
            {
                PublicInformation = publicInformation,
                DerivationSettings = parameter?.PasswordDerivationSettings,
                SecretInformationData = secretInformationData,
                EllipticCurveEncryptionInformation = parameter?.EllipticCurveEncryptionInformation,
            };

            JoinToOutput(File.OpenRead(tempFileName), output, fileMetaInfo);
        }

        private static void DecryptRaw(Stream input, Stream output, byte[] secret, PublicInformation publicInformation)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            var keyAes = secret.Take(AesKeyLength).ToArray();
            var hmacKey = keyAes.Skip(AesKeyLength).Take(HmacKeyLength).ToArray();

            // Todo remove
            Console.Out.WriteLine("keyAes: " + Convert.ToBase64String(keyAes));

            byte[] hmacHash;

            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.IV = publicInformation.IV;

                using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    var hmacsha512 = new HMACSHA512(hmacKey);

                    using (var aesStream = new CryptoStream(output, encryptor, CryptoStreamMode.Write))
                    using (var hmacStream = new CryptoStream(aesStream, hmacsha512, CryptoStreamMode.Write))
                    {
                        input.CopyTo(hmacStream);
                    }
                    hmacHash = hmacsha512.Hash;
                }
            }

            if (!publicInformation.HmacHash.SequenceEqual(hmacHash))
                throw new CryptographicException("HMAC Hash not as expected");
        }

        internal static PublicInformation EncryptRaw(Stream input, Stream output, byte[] secret)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            var result = new PublicInformation();

            var keyAes = secret.Take(AesKeyLength).ToArray();
            var hmacKey = keyAes.Skip(AesKeyLength).Take(HmacKeyLength).ToArray();

            // Todo remove
            Console.Out.WriteLine("keyAes: " + Convert.ToBase64String(keyAes));


            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.GenerateIV();
                result.IV = aes.IV;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    var hmacsha512 = new HMACSHA512(hmacKey);
                    using (var hmacStream = new CryptoStream(output, hmacsha512, CryptoStreamMode.Write))
                    using (var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                    {
                        input.CopyTo(aesStream);
                    }
                    result.HmacHash = hmacsha512.Hash;
                }
            }
            return result;
        }

        private static InformationContainer SeparateFromInput(FileStream tempFileStream, Stream input)
        {
            byte[] magicData = new byte[CryptoFileInfo.MagicNumber.Count];
            input.Read(magicData, 0, magicData.Length);

            if (!magicData.SequenceEqual(CryptoFileInfo.MagicNumber))
                throw new Exception("File header does not match");

            byte[] intData = new byte[4];
            input.Read(intData, 0, intData.Length);
            int intValue = BitConverter.ToInt32(intData, 0);

            var protoDate = new byte[intValue];
            input.Read(protoDate, 0, intValue);

            input.CopyTo(tempFileStream);

            return InformationContainer.FromProtoBufData(protoDate);
        }

        private static void JoinToOutput(Stream tempinputStream, Stream output, InformationContainer informationContainer)
        {
            var cryptoFileInfoDate = informationContainer.ToProtoBufData();

            new MemoryStream(CryptoFileInfo.MagicNumber.ToArray()).CopyTo(output);
            new MemoryStream(BitConverter.GetBytes(cryptoFileInfoDate.Length)).CopyTo(output);
            new MemoryStream(cryptoFileInfoDate).CopyTo(output);
            tempinputStream.CopyTo(output);
        }


        #region Private Types

        [ProtoContract]
        internal class InformationContainer : ProtoBase<InformationContainer>
        {
            [ProtoMember(1)]
            public PublicInformation PublicInformation { get; set; }

            [ProtoMember(2)]
            public PasswordDerivationSettings DerivationSettings { get; set; }

            [ProtoMember(3)]
            public byte[] SecretInformationData { get; set; }

            [ProtoMember(4)]
            public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
        }

        [ProtoContract]
        internal class SecretInformation : ProtoBase<SecretInformation>
        {
            [ProtoMember(1)]
            public string Filename { get; set; }
        }

        [ProtoContract]
        internal class PublicInformation
        {
            [ProtoMember(1)]
            public byte[] IV { get; set; }

            [ProtoMember(2)]
            public byte[] HmacHash { get; set; }
        }

        [ProtoContract]
        internal class PasswordDerivationSettings
        {
            public static PasswordDerivationSettings Create()
            {
                return new PasswordDerivationSettings
                {
#if DEBUG
                    Iterations = 100,
#else
                   terations = 100_000;
#endif
                    Salt = RandomHelper.GetRandomData(128),
                };
            }

            [ProtoMember(1)]
            public byte[] Salt { get; internal set; }

            [ProtoMember(2)]
            public int Iterations { get; internal set; }
        }

        [ProtoContract]
        public class DerivedSecret
        {
            [ProtoMember(1)]
            public EcKeyPair PublicKey { get; set; }

            [ProtoMember(2)]
            public byte[] EncryptedSharedSecret { get; set; }
        }

        [ProtoContract]
        public class EllipticCurveEncryptionInformation : ProtoBase<EllipticCurveEncryptionInformation>
        {
            [ProtoIgnore] public static readonly IReadOnlyList<byte> MagicNumber = new[] {(byte) 154, (byte) 65, (byte) 243, (byte) 167, (byte) 5, (byte) 63, (byte) 211};

            [ProtoMember(1)]
            public List<DerivedSecret> DerivedSecrets { get; set; }

            [ProtoMember(2)]
            public EcKeyPair EphemeralKey { get; set; }

            public static EllipticCurveEncryptionInformation Create(EcKeyPair[] publicKeys, byte[] secretKey)
            {
                var ephemeralKey = EllipticCurveCryptographer.CreateKeyPair(true);

                var result = new EllipticCurveEncryptionInformation()
                {
                    EphemeralKey = ephemeralKey.ExportPublicKey(),
                };

                result.DerivedSecrets = new List<DerivedSecret>();
                foreach (var publicKey in publicKeys)
                {
                    var deriveSecret = EllipticCurveCryptographer.DeriveSecret(ephemeralKey, publicKey);

                    var input = new MemoryStream(secretKey);
                    var output = new MemoryStream();
                    SymmetricEncryption.Encrypt(input, output, deriveSecret);

                    var derivedSecret = new DerivedSecret()
                    {
                        PublicKey = publicKey.ExportPublicKey(),
                        EncryptedSharedSecret = output.ToArray()
                    };
                    result.DerivedSecrets.Add(derivedSecret);
                }
                return result;
            }
        }
        internal class DecryptInternalParameter
        {
            public Func<EllipticCurveEncryptionInformation, byte[]> EllipticCurveDeriveKeyAction { get; set; }
        }

        #endregion


    }
}