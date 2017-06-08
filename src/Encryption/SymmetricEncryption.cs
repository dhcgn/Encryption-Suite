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

        public static DecryptInfo Decrypt(Stream input, Stream output, byte[] secretKey)
        {
            if(secretKey.Length != AesKeyLength+ HmacKeyLength)
                throw new Exception("Key must be 512 bit long");

            return DecryptInternal(input, output, null, secretKey);
        }

        public static DecryptInfo Decrypt(Stream input, Stream output, string password)
        {
           
            return DecryptInternal(input, output, password, null);
        }

        private static DecryptInfo DecryptInternal(Stream input, Stream output, string password, byte[] secretKey)
        {
            var result = new DecryptInfo();

            byte[] hmacHash;

            // BUG: NO file io!
            var tempPath = Path.GetTempFileName();
            CryptoFileInfo cryptoFileInfo;
            using (var rawfile = File.Create(tempPath))
            {
                cryptoFileInfo = CryptoFileInfo.LoadFromDisk(input, rawfile);
            }

            var secret = password != null
                ? Hasher.CreateAesKeyFromPassword(password, cryptoFileInfo.Salt, cryptoFileInfo.Iterations)
                : secretKey;

            var keyAes = secret.Take(AesKeyLength).ToArray();
            var hmacKey = keyAes.Skip(AesKeyLength).Take(HmacKeyLength).ToArray();

            if (cryptoFileInfo.EncryptedMetaData != null)
            {
                var meta = MetaDataFactory.ExtractFroCryptoFileInfom(secret, cryptoFileInfo.EncryptedMetaData);
                result.FileName = meta.Filename;
            }

            using (var tempFile = File.OpenRead(tempPath))
            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.IV = cryptoFileInfo.Iv;

                using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    var hmacsha512 = new HMACSHA512(hmacKey);
                    using (var aesStream = new CryptoStream(output, encryptor, CryptoStreamMode.Write))
                    using (var hmacStream = new CryptoStream(aesStream, hmacsha512, CryptoStreamMode.Write))
                    {
                        tempFile.CopyTo(hmacStream);
                    }
                    hmacHash = hmacsha512.Hash;
                }
            }

            if (!cryptoFileInfo.Hmac.SequenceEqual(hmacHash))
                throw new CryptographicException("HMAC Hash not as expected");

            File.Delete(tempPath);

            return result;
        }

        public static void Encrypt(Stream input, Stream output, string password, string filename = null)
        {
            var cryptoFileInfo = MyCryptoFileInfo.Create();
            var secretKey = Hasher.CreateAesKeyFromPassword(password, cryptoFileInfo.Salt, cryptoFileInfo.Iterations);

            byte[] encryptedMetaData = null;
            if (filename != null)
            {
                encryptedMetaData = MetaDataFactory.CreateEncryptedMetaData(secretKey, filename);
            }

            cryptoFileInfo.EncryptedMetaData = encryptedMetaData;

            EncryptInternal(input, output, secretKey, cryptoFileInfo);
        }

        public static void Encrypt(Stream input, Stream output, byte[] secretKey, string filename = null)
        {
            if (secretKey.Length != 512 / 8)
                throw new Exception("Key must be 512 bit long");

            var cryptoFileInfo = MyCryptoFileInfo.Create();

            byte[] encryptedMetaData = null;
            if (filename != null)
            {
                encryptedMetaData = MetaDataFactory.CreateEncryptedMetaData(secretKey, filename);
            }

            cryptoFileInfo.EncryptedMetaData = encryptedMetaData;

            EncryptInternal(input, output, secretKey, cryptoFileInfo);
        }

        public static void EncryptInternal(Stream input, Stream output, byte[] secret, CryptoFileInfo cryptoFileInfo)
        {
            var keyAes = secret.Take(AesKeyLength).ToArray();
            var hmacKey = keyAes.Skip(AesKeyLength).Take(HmacKeyLength).ToArray();

            // BUG: NO file io!
            var tempPath = Path.GetTempFileName();
            using (var tempFile = File.Create(tempPath))
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = keyAes;
                    aes.IV = cryptoFileInfo.Iv;

                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        var hmacsha512 = new HMACSHA512(hmacKey);
                        using (var hmacStream = new CryptoStream(tempFile, hmacsha512, CryptoStreamMode.Write))
                        using (var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                        {
                            input.CopyTo(aesStream);
                        }
                        cryptoFileInfo.Hmac = hmacsha512.Hash;
                    }
                }
            }

            using (var tempStream = File.OpenRead(tempPath))
            {
                CryptoFileInfo.WriteToDisk(cryptoFileInfo, output, tempStream);
            }
            File.Delete(tempPath);
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