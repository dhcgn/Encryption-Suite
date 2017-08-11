using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace EncryptionSuite.Encryption
{
    public class SymmetricEncryption
    {
        public const int AesKeyLength = 256 / 8;
        public const int HmacKeyLength = 256 / 8;
        internal const int BufferSize = 81920;

        #region Public

        public static DecryptInfo Decrypt(Stream input, Stream output, byte[] secret, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            var decryptInternalParameter = new DecryptInternalParameter
            {
                Progress = progress,
                IsCanceled = isCanceled,
            };
            return DecryptInternal(input, output, secret, null, decryptInternalParameter);
        }

        public static DecryptInfo Decrypt(Stream input, Stream output, string password, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            var decryptInternalParameter = new DecryptInternalParameter
            {
                Progress = progress,
                IsCanceled = isCanceled,
            };
            return DecryptInternal(input, output, null, password, decryptInternalParameter);
        }

        public static void Encrypt(string inputPath, string outputPath, string password, string filename = null, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            var derivationSettings = PasswordDerivationSettings.Create();
            var secretKey = Hasher.CreateAesKeyFromPassword(password, derivationSettings.Salt, derivationSettings.Iterations);
            var parameter = new EncryptInternalParameter
            {
                Filename = filename,
                PasswordDerivationSettings = derivationSettings,
                EllipticCurveEncryptionInformation = null,
                Progress = progress,
                IsCanceled = isCanceled,
            };

            using (var input = File.OpenRead(inputPath))
            using (var output = File.Open(outputPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                EncryptInternal(input, output, secretKey, parameter);
            }
        }


        public static void Encrypt(Stream input, Stream output, string password, string filename = null, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            var derivationSettings = PasswordDerivationSettings.Create();
            var secretKey = Hasher.CreateAesKeyFromPassword(password, derivationSettings.Salt, derivationSettings.Iterations);
            var parameter = new EncryptInternalParameter
            {
                Filename = filename,
                PasswordDerivationSettings = derivationSettings,
                EllipticCurveEncryptionInformation = null,
                Progress = progress,
                IsCanceled = isCanceled,
            };
            EncryptInternal(input, output, secretKey, parameter);
        }

        public static void Encrypt(Stream input, Stream output, byte[] secret, string filename = null, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            if (!(output.CanRead && output.CanWrite))
                throw new Exception("Strean must support read and write operations");

            var parameter = new EncryptInternalParameter
            {
                Filename = filename,
                PasswordDerivationSettings = null,
                EllipticCurveEncryptionInformation = null,
                Progress = progress,
                IsCanceled = isCanceled,
            };
            EncryptInternal(input, output, secret, parameter);
        }

        public static void Encrypt(string inputPath, string outputPath, byte[] secret, string filename = null, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            var parameter = new EncryptInternalParameter
            {
                Filename = filename,
                PasswordDerivationSettings = null,
                EllipticCurveEncryptionInformation = null,
                Progress = progress,
                IsCanceled = isCanceled,
            };

            using (var input = File.OpenRead(inputPath))
            using (var output = File.Open(outputPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                EncryptInternal(input, output, secret, parameter);
            }
        }

        #endregion

        internal static DecryptInfo DecryptInternal(Stream input, Stream output, byte[] secret, string password, DecryptInternalParameter parameter)
        {
            if(!RawFileAccessor.Verify(input))
                throw new CryptographicException("File signature is wrong");

            var fileCargo = RawFileAccessor.ReadMeta(input);

            if (password != null)
                secret = Hasher.CreateAesKeyFromPassword(password, fileCargo.PasswordDerivationSettings.Salt, fileCargo.PasswordDerivationSettings.Iterations);

            if (parameter?.EllipticCurveDeriveKeyAction != null)
                secret = parameter?.EllipticCurveDeriveKeyAction(fileCargo.EllipticCurveEncryptionInformation);

            SecretInformation decryptedSecretInfo = null;
            if (fileCargo.SecretInformationEncrypted != null)
            {
                var memoryStream = new MemoryStream();
                DecryptInternal(new MemoryStream(fileCargo.SecretInformationEncrypted), memoryStream, secret, null, null);
                decryptedSecretInfo = SecretInformation.FromProtoBufData(memoryStream.ToArray());
            }

            var iv = RawFileAccessor.Read(input, RawFileAccessor.Field.InitializationVector);
            var hmac = RawFileAccessor.Read(input, RawFileAccessor.Field.Hmac);
            (byte[] hmac, byte[] iv) param = (hmac, iv);

            RawFileAccessor.SeekToMainData(input);
            DecryptRaw(input, output, secret, param, parameter?.Progress, parameter?.IsCanceled);

            return new DecryptInfo
            {
                FileName = decryptedSecretInfo?.Filename,
            };
        }

        internal static void EncryptInternal(Stream input, Stream output, byte[] secretKey, EncryptInternalParameter parameter = null)
        {
            byte[] secretInformationEncryptedData = null;
            if (parameter?.Filename != null)
            {
                var secretInformation = new SecretInformation
                {
                    Filename = parameter.Filename,
                };

                secretInformationEncryptedData = secretInformation.ToEncyptedData(secretKey);
            }
            var metaInformation = new MetaInformation
            {
                PasswordDerivationSettings = parameter?.PasswordDerivationSettings,
                SecretInformationEncrypted = secretInformationEncryptedData,
                EllipticCurveEncryptionInformation = parameter?.EllipticCurveEncryptionInformation,
            };

            RawFileAccessor.Init(output);
            RawFileAccessor.WriteMeta(output, metaInformation);
            RawFileAccessor.SeekToMainData(output);

            var result = EncryptRaw(input, output, secretKey, parameter?.Progress, parameter?.IsCanceled);

            RawFileAccessor.Write(output, result.iv, RawFileAccessor.Field.InitializationVector);
            RawFileAccessor.Write(output, result.hmacHash, RawFileAccessor.Field.Hmac);

            output.Dispose();
        }

        internal static void DecryptRaw(Stream input, Stream output, byte[] secret, (byte[] hmacHash, byte[] iv) parameter, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            if (parameter.iv.Length != 128 / 8)
                throw new Exception($"length of IV must be {128 / 8} but was {parameter.iv.Length}.");

            if (parameter.hmacHash.Length != 512 / 8)
                throw new Exception($"length of HMAC must be {512 / 8} but was {parameter.hmacHash.Length}.");

            if (isCanceled == null)
                isCanceled = () => false;

            var keyAes = secret.Take(AesKeyLength).ToArray();
            var hmacKey = secret.Skip(AesKeyLength).Take(HmacKeyLength).ToArray();

            byte[] hmacHash;

            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.IV = parameter.iv;

#if DEBUG
                Console.WriteLine("DecryptRaw");

                Console.WriteLine($"AES Key:  {Convert.ToBase64String(aes.Key)}");
                Console.WriteLine($"AES IV:   {Convert.ToBase64String(aes.IV)}");
                Console.WriteLine($"HMAC Key: {Convert.ToBase64String(hmacKey)}");

                Console.WriteLine($"Output Position: {output.Position}");
                Console.WriteLine($"Input Position:  {input.Position}");
#endif


                using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var hmacsha512 = new HMACSHA512(hmacKey))
                    {
                        using (var aesStream = new CryptoStream(output, encryptor, CryptoStreamMode.Write))
                        using (var hmacStream = new CryptoStream(aesStream, hmacsha512, CryptoStreamMode.Write))
                        {
                            byte[] buffer = new byte[BufferSize];
                            int read;
                            while ((read = input.Read(buffer, 0, buffer.Length)) > 0 && !isCanceled())
                            {
                                hmacStream.Write(buffer, 0, read);

                                progress?.Invoke((double) input.Position / input.Length * 100);
                            }

                            input.CopyTo(hmacStream);
                        }
                        hmacHash = CreateOverallHmacHash(hmacKey, hmacsha512.Hash, aes.IV);
                    }
                }
            }

            if (!parameter.hmacHash.SequenceEqual(hmacHash))
                throw new CryptographicException("HMAC Hash not as expected", 
                    $"{Convert.ToBase64String(parameter.hmacHash)} not equal to {Convert.ToBase64String(hmacHash)}");
        }

        internal static (byte[] hmacHash, byte[] iv) EncryptRaw(Stream input, Stream output, byte[] secret, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

            if (isCanceled == null)
                isCanceled = () => false;

            var keyAes = secret.Take(AesKeyLength).ToArray();
            var hmacKey = secret.Skip(AesKeyLength).Take(HmacKeyLength).ToArray();

            byte[] iv = null;
            byte[] hmacHash = null;

            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.GenerateIV();
                iv = aes.IV;

#if DEBUG
                Console.WriteLine("EncryptRaw");

                Console.WriteLine($"AES Key:  {Convert.ToBase64String(aes.Key)}");
                Console.WriteLine($"AES IV:   {Convert.ToBase64String(aes.IV)}");
                Console.WriteLine($"HMAC Key: {Convert.ToBase64String(hmacKey)}");

                Console.WriteLine($"Output Position: {output.Position}");
                Console.WriteLine($"Input Position:  {input.Position}");
#endif

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var hmacsha512 = new HMACSHA512(hmacKey))
                    {
                        var hmacStream = new CryptoStream(output, hmacsha512, CryptoStreamMode.Write);
                        var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write);
                        {
                            byte[] buffer = new byte[BufferSize];
                            int read;
                            while ((read = input.Read(buffer, 0, buffer.Length)) > 0 && !isCanceled())
                            {
                                aesStream.Write(buffer, 0, read);

                                progress?.Invoke((double) input.Position / input.Length * 100);
                            }
                        }
                        aesStream.FlushFinalBlock();
                        hmacHash = CreateOverallHmacHash(hmacKey, hmacsha512.Hash, aes.IV);
                    }
                }
            }
            return (hmacHash, iv);
        }

        private static byte[] CreateOverallHmacHash(byte[] hmacKey, byte[] hmacsha512Hash, byte[] iv)
        {
            byte[] hash;
            var output = new MemoryStream();
            using (var hmacsha512 = new HMACSHA512(hmacKey))
            {
                using (var hmacStream = new CryptoStream(output, hmacsha512, CryptoStreamMode.Write))
                {
                    new MemoryStream(hmacsha512Hash).CopyTo(hmacStream);
                    new MemoryStream(iv).CopyTo(hmacStream);
                }
                hash = hmacsha512.Hash;
            }

#if DEBUG
            Console.Out.WriteLine($"CreateOverallHmacHash:\r\n" +
                                  $"Input Key:   {Convert.ToBase64String(hmacKey)}\r\n" +
                                  $"Input Hash:  {Convert.ToBase64String(hmacsha512Hash)}\r\n" +
                                  $"Input IV:    {Convert.ToBase64String(iv)}\r\n\r\n" +
                                  $"Result Hash: {Convert.ToBase64String(hash)}\r\n");
#endif

            return hash;
        }

    }
}