using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class SymmetricEncryptionTest : TestBase
    {
        [Test]
        [TestCase(EncryptionSecret.Key, true)]
        [TestCase(EncryptionSecret.Password, true)]
        [TestCase(EncryptionSecret.Key, false)]
        [TestCase(EncryptionSecret.Password, false)]
        public void EncryptTest(EncryptionSecret secretType, bool withFilename)
        {
            #region Arrange

            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

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

            #endregion

            #region Assert

            Assert.That(data, Is.Not.EquivalentTo(File.ReadAllBytes(this.OutputFile)));
            Assert.That(data.Length, Is.LessThan(File.ReadAllBytes(this.OutputFile).Length));
            Assert.That(FileOperation.HasFileSignature(this.OutputFile), "HasFileSignature");

            #endregion
        }

        [Test]
        public void Encrypt_Progress_Test()
        {
            #region Arrange

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();

            var progressValues = new List<double>();

            var multiplier = 10;

            #endregion

            #region Act

            using (var input = new MemoryStream(new byte[SymmetricEncryption.BufferSize * multiplier]))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.Encrypt(input, output, pwd, filename, d => { progressValues.Add(d); }, () => false);
            }

            #endregion

            #region Assert

            Assert.That(progressValues.Count, Is.EqualTo(multiplier));
            Assert.That(progressValues, Is.Ordered);
            Assert.That(progressValues, Is.Unique);
            Assert.That(progressValues, Has.None.GreaterThan(100));
            Assert.That(progressValues, Has.None.LessThan(0));

            #endregion
        }

        [Test]
        public void Decrypt_Progress_Test()
        {
            #region Arrange

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();

            var progressValues = new List<double>();

            var multiplier = 10;

            #endregion

            #region Act

            using (var input = new MemoryStream(new byte[SymmetricEncryption.BufferSize * multiplier]))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.Encrypt(input, output, pwd, filename);
            }

            SymmetricEncryption.DecryptInfo info;
            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                info = SymmetricEncryption.Decrypt(input, output, pwd, d => { progressValues.Add(d); }, () => false);
            }

            #endregion

            #region Assert

            Assert.That(progressValues.Count, Is.EqualTo(multiplier + 1));
            Assert.That(progressValues, Is.Ordered);
            Assert.That(progressValues, Is.Unique);
            Assert.That(progressValues, Has.None.GreaterThan(100));
            Assert.That(progressValues, Has.None.LessThan(0));

            #endregion
        }

        [Test]
        public void Encrypt_Cancel_Test()
        {
            #region Arrange

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();

            int progressCounter = 0;

            #endregion

            #region Act

            using (var input = new MemoryStream(new byte[SymmetricEncryption.BufferSize * 10]))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.Encrypt(input, output, pwd, filename, d => progressCounter++, () => true);
            }

            #endregion

            #region Assert

            Assert.That(progressCounter, Is.EqualTo(0));

            #endregion
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
            #region Arrange

            var data = Encryption.Random.CreateData(128 / 8);
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

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

            byte[] dataContent;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.SeekToMainData(stream);
                var ms = new MemoryStream();
                stream.CopyTo(ms);
                dataContent = ms.ToArray();
            }
            Console.Out.WriteLine("Encrypted Content: " + Convert.ToBase64String(dataContent));

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

            #endregion

            #region Assert

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
            Assert.That(FileOperation.HasFileSignature(this.OutputFile), "HasFileSignature");

            Assert.That(File.ReadAllBytes(this.ResultFile), Is.EquivalentTo(data), "Plaindata is equal after decryption");

            #endregion
        }

        [Test(Description = "Encrypt and Decrypt to and from MemoryStream")]
        [TestCase(EncryptionSecret.Key, true)]
        [TestCase(EncryptionSecret.Password, true)]
        [TestCase(EncryptionSecret.Key, false)]
        [TestCase(EncryptionSecret.Password, false)]
        public void EncryptAndDecrypt_MemoryStream_Test(EncryptionSecret secretType, bool withFilename)
        {
            #region Arrange

            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var filename = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

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

            #endregion

            #region Assert

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

            #endregion
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
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
            }

            SymmetricEncryption.InformationContainer informationContainer;
            byte[] file = null;
            using (var input = File.OpenRead(this.OutputFile))
            {
                var output = new MemoryStream();
                informationContainer = SymmetricEncryption.SeparateFromInput(output, input);
                file = output.ToArray();
            }

            #endregion

            #region Act

            switch (tamperEnum)
            {
                case TamperEnum.AesKey:
                    secret[0] ^= secret[0];
                    break;
                case TamperEnum.HmacHash:
                    Assert.Fail();
                    //informationContainer.PublicInformation.HmacHash[0] ^= informationContainer.PublicInformation.HmacHash[0];
                    break;
                case TamperEnum.Iv:
                    Assert.Fail();
                    // informationContainer.PublicInformation.IV[0] ^= informationContainer.PublicInformation.IV[0];
                    break;
                case TamperEnum.File:
                    file[0] ^= file[0];
                    break;
                case TamperEnum.Nothing:
                    break;
            }

            #endregion

            #region Assert

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
                        var ex = Assert.Throws<CryptographicException>(() => SymmetricEncryption.DecryptInternal(input, output, secret, null, null));
                        Console.Out.WriteLine($"Exception: {ex.GetType().Name}, Message: {ex.Message}");
                        break;
                    case TamperEnum.Nothing:
                        Assert.DoesNotThrow(() => SymmetricEncryption.DecryptInternal(input, output, secret, null, null));
                        break;
                }
            }

            if (tamperEnum == TamperEnum.Nothing)
            {
                Assert.That(File.ReadAllBytes(this.InputFile), Is.EquivalentTo(File.ReadAllBytes(this.ResultFile)));
            }

            #endregion
        }
    }
}