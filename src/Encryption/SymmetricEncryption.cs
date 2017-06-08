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
        public static DecryptInfo Decrypt(Stream input, Stream output, byte[] secretKey)
        {
            return DecryptInternal(input, output, null, secretKey.Take(256 / 8).ToArray());
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

            var keyAes = password != null
                ? Hasher.CreateAesKeyFromPassword(password, cryptoFileInfo.Salt, cryptoFileInfo.Iterations)
                : secretKey;

            if (cryptoFileInfo.EncryptedMetaData != null)
            {
                var meta = MetaDataFactory.ExtractFroCryptoFileInfom(keyAes, cryptoFileInfo.EncryptedMetaData);
                result.FileName = meta.Filename;
            }

            using (var tempFile = File.OpenRead(tempPath))
            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.IV = cryptoFileInfo.Iv;

                using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    var hmacsha512 = new HMACSHA512(keyAes);
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
            var cryptoFileInfo = MyCryptoFileInfo.Create();

            byte[] encryptedMetaData = null;
            if (filename != null)
            {
                encryptedMetaData = MetaDataFactory.CreateEncryptedMetaData(secretKey, filename);
            }

            cryptoFileInfo.EncryptedMetaData = encryptedMetaData;

            EncryptInternal(input, output, secretKey, cryptoFileInfo);
        }

        public static void EncryptInternal(Stream input, Stream output, byte[] keyAes, CryptoFileInfo cryptoFileInfo)
        {
            keyAes = keyAes.Take(256 / 8).ToArray();

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
                        var hmacsha512 = new HMACSHA512(keyAes);
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