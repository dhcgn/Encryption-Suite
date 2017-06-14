using System;
using System.IO;
using System.Security.Cryptography;
using EncryptionSuite.Contract;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class SymmetricEncryptionTest : TestBase
    {
        [Test]
        public void GetRandomDataTest()
        {
            var bits = 128;
            var result = RandomHelper.GetRandomData(bits);

            Assert.That(result, Is.Not.Null);
            Assert.That(result, Has.Length.EqualTo(bits / 8));
        }

        [Test]
        [TestCase(EncryptionSecret.Key, true)]
        [TestCase(EncryptionSecret.Password, true)]
        [TestCase(EncryptionSecret.Key, false)]
        [TestCase(EncryptionSecret.Password, false)]
        public void EncryptTest(EncryptionSecret secretType, bool withFilename)
        {
            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512 / 8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        if (withFilename)
                            SymmetricEncryption.Encrypt(input, output, pwd, filename);
                        else
                            SymmetricEncryption.Encrypt(input, output, pwd);
                        break;
                    case EncryptionSecret.Key:
                        if (withFilename)
                            SymmetricEncryption.Encrypt(input, output, key, filename);
                        else
                            SymmetricEncryption.Encrypt(input, output, key);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(secretType), secretType, null);
                }
            }
            Assert.That(data, Is.Not.EquivalentTo(File.ReadAllBytes(this.OutputFile)));
            Assert.That(data.Length, Is.LessThan(File.ReadAllBytes(this.OutputFile).Length));
        }

        public enum EncryptionSecret
        {
            Password,
            Key
        }

        [Test(Description = "Encrypt and Decrypt to and from FileStream")]
        [TestCase(EncryptionSecret.Key, true)]
        [TestCase(EncryptionSecret.Password, true)]
        [TestCase(EncryptionSecret.Key, false)]
        [TestCase(EncryptionSecret.Password, false)]
        public void EncryptAndDecryptTest(EncryptionSecret secretType, bool withFilename)
        {
            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512 / 8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        if (withFilename)
                            SymmetricEncryption.Encrypt(input, output, pwd, filename);
                        else
                            SymmetricEncryption.Encrypt(input, output, pwd);
                        break;
                    case EncryptionSecret.Key:
                        if (withFilename)
                            SymmetricEncryption.Encrypt(input, output, key, filename);
                        else
                            SymmetricEncryption.Encrypt(input, output, key);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(secretType), secretType, null);
                }
            }

            SymmetricEncryption.DecryptInfo info;
            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        info = SymmetricEncryption.Decrypt(input, output, pwd);
                        break;
                    case EncryptionSecret.Key:
                        info = SymmetricEncryption.Decrypt(input, output, key);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(secretType), secretType, null);
                }
            }

            if (withFilename)
            {
                Assert.That(info?.FileName, Is.EqualTo(filename), "Filename is correct decrypted.");
            }
            else
            {
                Assert.That(info.FileName, Is.Null, "Filename is Null.");
            }

            Assert.That(data, Is.Not.EquivalentTo(File.ReadAllBytes(this.OutputFile)));
            Assert.That(data.Length, Is.LessThan(File.ReadAllBytes(this.OutputFile).Length));
            Assert.That(data, Is.EquivalentTo(File.ReadAllBytes(this.ResultFile)));
        }

        [Test(Description = "Encrypt and Decrypt to and from MemoryStream")]
        [TestCase(EncryptionSecret.Key, true)]
        [TestCase(EncryptionSecret.Password, true)]
        [TestCase(EncryptionSecret.Key, false)]
        [TestCase(EncryptionSecret.Password, false)]
        public void EncryptAndDecrypt_MemoryStream_Test(EncryptionSecret secretType, bool withFilename)
        {
            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512 / 8);

            var outputEncrypted = new MemoryStream();
            using (var input = new MemoryStream(File.ReadAllBytes(this.InputFile)))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        if (withFilename)
                            SymmetricEncryption.Encrypt(input, outputEncrypted, pwd, filename);
                        else
                            SymmetricEncryption.Encrypt(input, outputEncrypted, pwd);
                        break;
                    case EncryptionSecret.Key:
                        if (withFilename)
                            SymmetricEncryption.Encrypt(input, outputEncrypted, key, filename);
                        else
                            SymmetricEncryption.Encrypt(input, outputEncrypted, key);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(secretType), secretType, null);
                }
            }

            var outputPlain = new MemoryStream();
            SymmetricEncryption.DecryptInfo info;
            using (var input = new MemoryStream(outputEncrypted.ToArray()))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        info = SymmetricEncryption.Decrypt(input, outputPlain, pwd);
                        break;
                    case EncryptionSecret.Key:
                        info = SymmetricEncryption.Decrypt(input, outputPlain, key);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(secretType), secretType, null);
                }
            }

            if (withFilename)
            {
                Assert.That(info?.FileName, Is.EqualTo(filename), "Filename is correct decrypted.");
            }
            else
            {
                Assert.That(info.FileName, Is.Null, "Filename is Null.");
            }

            Assert.That(data, Is.Not.EquivalentTo(outputEncrypted.ToArray()));
            Assert.That(data.Length, Is.LessThan(outputEncrypted.ToArray().Length));
            Assert.That(data, Is.EquivalentTo(outputPlain.ToArray()));
        }

        public enum TamperEnum
        {
            AesKey,
            HmacHash,
            Iv,
            File,
            Nothing
        }

        [TestCase(TamperEnum.AesKey, TestName = "Tamper AES Key")]
        [TestCase(TamperEnum.HmacHash, TestName = "Tamper HMAC hash")]
        [TestCase(TamperEnum.Iv, TestName = "Tamper IV")]
        [TestCase(TamperEnum.File, TestName = "Tamper encrypted file")]
        [TestCase(TamperEnum.Nothing, TestName = "Tamper nothing")]
        public void TamperTest(TamperEnum tamperEnum)
        {
            var key = Encryption.Random.CreateData(512 / 8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.EncryptInternal(input, output, key);
            }

            SymmetricEncryption.InformationContainer informationContainer;
            byte[] file = null;
            using (var input = File.OpenRead(this.OutputFile))
            {
                var output = new MemoryStream();
                informationContainer = SymmetricEncryption.SeparateFromInput(output, input);
                file = output.ToArray();
            }

            switch (tamperEnum)
            {
                case TamperEnum.AesKey:
                    key[0] ^= key[0];
                    break;
                case TamperEnum.HmacHash:
                    informationContainer.PublicInformation.HmacHash[0] ^= informationContainer.PublicInformation.HmacHash[0];
                    break;
                case TamperEnum.Iv:
                    informationContainer.PublicInformation.IV[0] ^= informationContainer.PublicInformation.IV[0];
                    break;
                case TamperEnum.File:
                    file[0] ^= file[0];
                    break;
                case TamperEnum.Nothing:
                    break;
            }

            var memoryStream = new MemoryStream();
            SymmetricEncryption.JoinToOutput(new MemoryStream(file), memoryStream, informationContainer);
            var tampertFile = memoryStream.ToArray();

            using (var input = new MemoryStream(tampertFile))
            using (var output = File.Create(this.ResultFile))
            {
                switch (tamperEnum)
                {
                    case TamperEnum.AesKey:
                    case TamperEnum.HmacHash:
                    case TamperEnum.Iv:
                    case TamperEnum.File:
                        var ex = Assert.Throws<CryptographicException>(() => SymmetricEncryption.DecryptInternal(input, output, key, null, null));
                        Console.Out.WriteLine($"Exception: {ex.GetType().Name}, Message: {ex.Message}");
                        break;
                    case TamperEnum.Nothing:
                        Assert.DoesNotThrow(() => SymmetricEncryption.DecryptInternal(input, output, key, null, null));
                        break;
                }
            }

            if (tamperEnum == TamperEnum.Nothing)
            {
                Assert.That(File.ReadAllBytes(this.InputFile), Is.EquivalentTo(File.ReadAllBytes(this.ResultFile)));
            }
        }
    }
}