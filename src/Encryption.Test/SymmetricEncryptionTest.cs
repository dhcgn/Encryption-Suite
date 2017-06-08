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
        [TestCase(EncryptionSecret.Key)]
        [TestCase(EncryptionSecret.Password)]
        public void EncryptTest(EncryptionSecret secretType)
        {
            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            var pwd = Guid.NewGuid().ToString();
            var key = Encryption.Random.CreateData(512/8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                switch (secretType)
                {
                    case EncryptionSecret.Password:
                        SymmetricEncryption.Encrypt(input, output, pwd);
                        break;
                    case EncryptionSecret.Key:
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
        [TestCase(EncryptionSecret.Key)]
        [TestCase(EncryptionSecret.Password)]
        public void EncryptAndDecryptTest(EncryptionSecret secretType)
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
                        SymmetricEncryption.Encrypt(input, output, pwd, filename);
                        break;
                    case EncryptionSecret.Key:
                        SymmetricEncryption.Encrypt(input, output, key, filename);
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

            Assert.That(info?.FileName, Is.EqualTo(filename), "Filename is correct decrypted.");

            Assert.That(data, Is.Not.EquivalentTo(File.ReadAllBytes(this.OutputFile)));
            Assert.That(data.Length, Is.LessThan(File.ReadAllBytes(this.OutputFile).Length));
            Assert.That(data, Is.EquivalentTo(File.ReadAllBytes(this.ResultFile)));
        }
    }


}