using System;
using System.IO;
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
            var key = Encryption.Random.CreateData(512/8);

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

        [Test]
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
            var key = Encryption.Random.CreateData(512/8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        if(withFilename)
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

            DecryptInfo info;
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
            
            Assert.That(data, Is.Not.EquivalentTo(File.ReadAllBytes(this.OutputFile)));
            Assert.That(data.Length, Is.LessThan(File.ReadAllBytes(this.OutputFile).Length));
            Assert.That(data, Is.EquivalentTo(File.ReadAllBytes(this.ResultFile)));
        }
    }


}