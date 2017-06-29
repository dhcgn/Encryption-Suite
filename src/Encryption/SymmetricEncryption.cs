using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using EncryptionSuite.Contract;
using ProtoBuf;

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

        #endregion

        internal static DecryptInfo DecryptInternal(Stream input, Stream output, byte[] secret, string password, DecryptInternalParameter parameter)
        {
            InformationContainer informationContainer = SymmetricEncryption.FileformatHelper.ReadMeta(input);

            if (password != null)
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

            var iv = FileformatHelper.Read(input, FileformatHelper.Field.InitializationVector);
            var hmac = FileformatHelper.Read(input, FileformatHelper.Field.Hmac);
            (byte[] Iv, byte[] HmacExptected) param = ValueTuple.Create(iv, hmac);

            FileformatHelper.SeekToMainData(input);

           // var fs = (output as FileStream).

            DecryptRaw(input, output, secret, param, parameter?.Progress, parameter?.IsCanceled);

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
            public Action<double> Progress { get; set; }
            public Func<bool> IsCanceled { get; set; }
        }

        internal class FileformatHelper
        {
            internal enum Field
            {
                FileSignature = 0,
                Version = 1,
                Hmac = 2,
                InitializationVector = 3,
                MetaLength = 4,
            }

            internal static Dictionary<Field, (int begin, int length)> Positions = new Dictionary<Field, (int begin, int length)>()
            {
                {Field.FileSignature, ValueTuple.Create(0, 8)},
                {Field.Version, ValueTuple.Create(8, 16 / 8)},
                {Field.Hmac, ValueTuple.Create(10, 512 / 8)},
                {Field.InitializationVector, ValueTuple.Create(74, 128 / 8)},
                {Field.MetaLength, ValueTuple.Create(90, 32 / 8)},
            };


            internal static void Write(Stream output, byte[] data, Field field)
            {
                var valueTuple = Positions[field];
                WriteInternal(output, data, valueTuple);
            }

            private static void WriteInternal(Stream output, byte[] data, ValueTuple<int, int> valueTuple)
            {
                if (data.Length != valueTuple.Item2)
                    throw new Exception($"File length {valueTuple.Item2} expeted but was {data.Length}.");

                output.Seek(valueTuple.Item1, SeekOrigin.Begin);
                output.Write(data, 0, valueTuple.Item2);
            }

            internal static byte[] Read(Stream input, Field field)
            {
                var valueTuple = Positions[field];
                return ReadInternal(input, valueTuple);
            }

            private static byte[] ReadInternal(Stream input, ValueTuple<int, int> valueTuple)
            {
                input.Seek(valueTuple.Item1, SeekOrigin.Begin);
                byte[] data = new byte[valueTuple.Item2];
                input.Read(data, 0, valueTuple.Item2);
                return data;
            }

            internal static void SeekToMainData(Stream input)
            {
                var positonMetaData = Positions.Sum(pair => pair.Value.length);
                var metaDataLength = Read(input, Field.MetaLength);
                var length = BitConverter.ToInt32(metaDataLength, 0);

                input.Seek(length + positonMetaData, SeekOrigin.Begin);
            }

            internal static void Init(Stream output)
            {
                new MemoryStream(Constants.MagicNumberSymmetric.ToArray()).CopyTo(output);
            }

            internal static bool Verify(Stream input)
            {
                input.Seek(0, SeekOrigin.Begin);

                byte[] magicData = new byte[Constants.MagicNumberSymmetric.Length];
                input.Read(magicData, 0, magicData.Length);

                return Constants.MagicNumberSymmetric.SequenceEqual(magicData);
            }

            public static InformationContainer ReadMeta(Stream input)
            {
                var metaDataLength = Read(input, Field.MetaLength);
                var length = BitConverter.ToInt32(metaDataLength, 0);
                var positonMetaData = Positions.Sum(pair => pair.Value.length);

                var data = ReadInternal(input, ValueTuple.Create(positonMetaData, length));

                return InformationContainer.FromProtoBufData(data);
            }

            public static void WriteMeta(Stream output, InformationContainer fileMetaInfo)
            {
                var metaData = fileMetaInfo.ToProtoBufData();
                var metaDataLength = BitConverter.GetBytes(metaData.Length);
                Write(output, metaDataLength, Field.MetaLength);

                var positonMetaData = Positions.Sum(pair => pair.Value.length);

                WriteInternal(output, metaData, ValueTuple.Create(positonMetaData, metaData.Length));
            }
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
            var fileMetaInfo = new InformationContainer
            {
                DerivationSettings = parameter?.PasswordDerivationSettings,
                SecretInformationData = secretInformationEncryptedData,
                EllipticCurveEncryptionInformation = parameter?.EllipticCurveEncryptionInformation,
            };

            FileformatHelper.Init(output);
            FileformatHelper.WriteMeta(output, fileMetaInfo);
            FileformatHelper.SeekToMainData(output);

            var result = EncryptRaw(input, output, secretKey, parameter?.Progress, parameter?.IsCanceled);

            // to InformationContainer
            FileformatHelper.Write(output, result.iv, FileformatHelper.Field.InitializationVector);
            FileformatHelper.Write(output, result.hmacHash, FileformatHelper.Field.Hmac);

            output.Dispose();
        }

        internal static void DecryptRaw(Stream input, Stream output, byte[] secret, (byte[] hmacHash, byte[] iv) parameter, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            if (secret.Length < AesKeyLength + HmacKeyLength)
                throw new Exception($"length of secret must be {AesKeyLength + HmacKeyLength} or more.");

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

                                progress?.Invoke((double)input.Position / input.Length * 100);
                            }

                            input.CopyTo(hmacStream);
                        }
                        hmacHash = CreateOverallHmacHash(hmacKey, hmacsha512.Hash, aes.IV);
                    }
                }
            }

            if (!parameter.hmacHash.SequenceEqual(hmacHash))
                throw new CryptographicException("HMAC Hash not as expected");
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
                        using (var hmacStream = new CryptoStream(output, hmacsha512, CryptoStreamMode.Write))
                        using (var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] buffer = new byte[BufferSize];
                            int read;
                            while ((read = input.Read(buffer, 0, buffer.Length)) > 0 && !isCanceled())
                            {
                                aesStream.Write(buffer, 0, read);

                                progress?.Invoke((double)input.Position / input.Length * 100);
                            }
                        }
                        hmacHash = CreateOverallHmacHash(hmacKey, hmacsha512.Hash, aes.IV);
                    }
                }
            }
            return (hmacHash, iv);
        }

        private static byte[] CreateOverallHmacHash(byte[] hmacKey, byte[] hmacsha512Hash, byte[] aesIv)
        {
            byte[] hash;
            var output = new MemoryStream();
            using (var hmacsha512 = new HMACSHA512(hmacKey))
            {
                using (var hmacStream = new CryptoStream(output, hmacsha512, CryptoStreamMode.Write))
                {
                    new MemoryStream(hmacsha512Hash).CopyTo(hmacStream);
                    new MemoryStream(aesIv).CopyTo(hmacStream);
                }
                hash = hmacsha512.Hash;
            }
            return hash;
        }


        internal static InformationContainer SeparateFromInput(Stream ouput, Stream input)
        {
            byte[] magicData = new byte[Constants.MagicNumberSymmetric.Length];
            input.Read(magicData, 0, magicData.Length);

            if (!magicData.SequenceEqual(Constants.MagicNumberSymmetric))
                throw new Exception("File header does not match");

            byte[] intData = new byte[4];
            input.Read(intData, 0, intData.Length);
            int intValue = BitConverter.ToInt32(intData, 0);

            var protoDate = new byte[intValue];
            input.Read(protoDate, 0, intValue);

            input.CopyTo(ouput);

            return InformationContainer.FromProtoBufData(protoDate);
        }

        internal static void JoinToOutput(Stream input, Stream output, InformationContainer informationContainer)
        {
            var cryptoFileInfoDate = informationContainer.ToProtoBufData();

            new MemoryStream(Constants.MagicNumberSymmetric.ToArray()).CopyTo(output);
            new MemoryStream(BitConverter.GetBytes(cryptoFileInfoDate.Length)).CopyTo(output);
            new MemoryStream(cryptoFileInfoDate).CopyTo(output);
            input.CopyTo(output);
        }


#region Private Types

        [ProtoContract]
        internal class InformationContainer : ProtoBase<InformationContainer>
        {
            [ProtoMember(1)]
            public PasswordDerivationSettings DerivationSettings { get; set; }

            [ProtoMember(2)]
            public byte[] SecretInformationData { get; set; }

            [ProtoMember(3)]
            public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
        }

        [ProtoContract]
        internal class SecretInformation : ProtoBase<SecretInformation>
        {
            [ProtoMember(1)]
            public string Filename { get; set; }

            internal byte[] ToEncyptedData(byte[] secretKey)
            {
                var secretInformationPlainData = this.ToProtoBufData();
                var encrypted = new MemoryStream();
                EncryptInternal(new MemoryStream(secretInformationPlainData), encrypted, secretKey);

                return encrypted.ToArray();
            }
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
                    Iterations = 100_000,
#endif
                    Salt = Random.CreateData(128 / 8),
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
            public byte[] PublicKeyHash { get; set; }

            [ProtoMember(2)]
            public byte[] PublicKeyHashSalt { get; set; }

            [ProtoMember(3)]
            public byte[] EncryptedSharedSecret { get; set; }
        }

        [ProtoContract]
        public class EllipticCurveEncryptionInformation : ProtoBase<EllipticCurveEncryptionInformation>
        {
            [ProtoMember(1)]
            public List<DerivedSecret> DerivedSecrets { get; set; }

            [ProtoMember(2)]
            public EcKeyPair EphemeralKey { get; set; }

            public static EllipticCurveEncryptionInformation Create(IEnumerable<EcKeyPair> publicKeys, byte[] secretKey)
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

                    var saltedHash = publicKey.GetPublicKeySaltedHash();

                    var derivedSecret = new DerivedSecret()
                    {
                        PublicKeyHash = saltedHash.hash,
                        PublicKeyHashSalt = saltedHash.salt,
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
            public Action<double> Progress { get; set; }
            public Func<bool> IsCanceled { get; set; }
        }

        public class DecryptInfo
        {
            public string FileName { get; set; }
        }

#endregion
    }
}