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
            var tempFileName = Path.GetTempFileName();
            FileMetaInfo fileMetaInfo;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                fileMetaInfo = SeparateFromInput(tempFileStream, input);
            }

            using (var tempFileStream = File.OpenRead(tempFileName))
            {
                DecryptRaw(tempFileStream, output, secret, fileMetaInfo.EncryptionResult);
            }

            return null;
        }

        public static DecryptInfo Decrypt(Stream input, Stream output, string password)
        {
            var tempFileName = Path.GetTempFileName();
            FileMetaInfo fileMetaInfo;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                fileMetaInfo = SeparateFromInput(tempFileStream, input);
            }

            var secret = Hasher.CreateAesKeyFromPassword(password, fileMetaInfo.DerivationSettings.Salt, fileMetaInfo.DerivationSettings.Iterations);

            using (var tempFileStream = File.OpenRead(tempFileName))
            {
                DecryptRaw(tempFileStream, output, secret, fileMetaInfo.EncryptionResult);
            }

            return null;
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

        private static void DecryptRaw(Stream input, Stream output, byte[] secret, EncryptionResult encryptionResult)
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
                aes.IV = encryptionResult.IV;

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

            if (!encryptionResult.HmacHash.SequenceEqual(hmacHash))
                throw new CryptographicException("HMAC Hash not as expected");
        }


        private static void EncryptInternal(Stream input, Stream output, byte[] secretKey, PasswordDerivationSettings derivationSettings, string filename)
        {
            var tempFileName = Path.GetTempFileName();

            EncryptionResult encryptionResult;
            using (var tempFileStream = File.OpenWrite(tempFileName))
            {
                encryptionResult = EncryptRaw(input, tempFileStream, secretKey);
            }



            var fileMetaInfo = new FileMetaInfo
            {
                EncryptionResult = encryptionResult,
                DerivationSettings = derivationSettings,
            };

            JoinToOutput(File.OpenRead(tempFileName), output, fileMetaInfo);
        }

        private static FileMetaInfo SeparateFromInput(FileStream tempFileStream, Stream input)
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

            return FileMetaInfo.FromProtoBufData(protoDate);
        }

        private static void JoinToOutput(Stream tempinputStream, Stream output, FileMetaInfo fileMetaInfo)
        {
            var cryptoFileInfoDate = fileMetaInfo.ToProtoBufData();

            new MemoryStream(CryptoFileInfo.MagicNumber.ToArray()).CopyTo(output);
            new MemoryStream(BitConverter.GetBytes(cryptoFileInfoDate.Length)).CopyTo(output);
            new MemoryStream(cryptoFileInfoDate).CopyTo(output);
            tempinputStream.CopyTo(output);
        }


        [ProtoContract]
        internal class FileMetaInfo : ProtoBase<FileMetaInfo>
        {
            [ProtoMember(1)]
            public EncryptionResult EncryptionResult { get; set; }

            [ProtoMember(2)]
            public PasswordDerivationSettings DerivationSettings { get; set; }
        }

        [ProtoContract]
        internal class EncryptionResult
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

        internal static EncryptionResult EncryptRaw(Stream input, Stream output, byte[] secret)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            var result = new EncryptionResult();

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
    }


    public class MetaDataFactory
    {
        public static byte[] CreateEncryptedMetaData(byte[] secretKey, string filename)
        {
            var metaData = MetaData.CreateFromFilePath(filename);
            var protoBufData = metaData.ToProtoBufData();
            var resultStream = new MemoryStream();
            Encryption.SymmetricEncryption.Encrypt(new MemoryStream(protoBufData), resultStream, secretKey);
            return resultStream.ToArray();
        }

        public static MetaData ExtractFroCryptoFileInfom(byte[] secretKey, byte[] encryptedMetaData)
        {
            var resultStream = new MemoryStream();
            Encryption.SymmetricEncryption.Decrypt(new MemoryStream(encryptedMetaData), resultStream, secretKey);
            return MetaData.FromProtoBufData(resultStream.ToArray());
        }
    }

    public class MyCryptoFileInfo : CryptoFileInfo
    {
        public static CryptoFileInfo Create()
        {
#if DEBUG
            var iterations = 100;
#else
            var iterations = 100000;
#endif

            var iv = RandomHelper.GetRandomData(128);
            var salt = RandomHelper.GetRandomData(128);


            var cryptoFileInfo = new CryptoFileInfo
            {
                Iv = iv,
                Salt = salt,
                Iterations = iterations,
                Hmac = null,
            };
            return cryptoFileInfo;
        }
    }
}