using System;
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
            return DecryptInternal(input, output, secret, null);
        }

        public static DecryptInfo Decrypt(Stream input, Stream output, string password)
        {
            return DecryptInternal(input, output, null, password);
        }

        public static void Encrypt(Stream input, Stream output, string password, string filename = null)
        {
            var derivationSettings = PasswordDerivationSettings.Create();
            var secretKey = Hasher.CreateAesKeyFromPassword(password, derivationSettings.Salt, derivationSettings.Iterations);

            EncryptInternal(input, output, secretKey, derivationSettings, filename);
        }

        public static void Encrypt(Stream input, Stream output, byte[] secret, string filename = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            EncryptInternal(input, output, secret, null, filename);
        }

        #endregion

        private static DecryptInfo DecryptInternal(Stream input, Stream output, byte[] secret, string password)
        {
            var tempFileName = Path.GetTempFileName();
            InformationContainer informationContainer;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                informationContainer = SeparateFromInput(tempFileStream, input);
            }

            if (secret == null)
                secret = Hasher.CreateAesKeyFromPassword(password, informationContainer.DerivationSettings.Salt, informationContainer.DerivationSettings.Iterations);

            SecretInformation decryptedSecretInfo = null;
            if (informationContainer.SecretInformationData != null)
            {
                var memoryStream = new MemoryStream();
                DecryptInternal(new MemoryStream(informationContainer.SecretInformationData), memoryStream, secret, null);
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

        private static void EncryptInternal(Stream input, Stream output, byte[] secretKey, PasswordDerivationSettings derivationSettings, string filename)
        {
            var tempFileName = Path.GetTempFileName();

            PublicInformation publicInformation;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                publicInformation = EncryptRaw(input, tempFileStream, secretKey);
            }

            byte[] secretInformationData = null;
            if (filename != null)
            {
                var secretInformation = new SecretInformation()
                {
                    Filename = filename,
                };
                var secretInformationPlainData = secretInformation.ToProtoBufData();
                var encrypted = new MemoryStream();
                EncryptInternal(new MemoryStream(secretInformationPlainData), encrypted, secretKey, null, null);
                secretInformationData = encrypted.ToArray();
            }

            var fileMetaInfo = new InformationContainer
            {
                PublicInformation = publicInformation,
                DerivationSettings = derivationSettings,
                SecretInformationData = secretInformationData,
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

        #endregion
    }
}