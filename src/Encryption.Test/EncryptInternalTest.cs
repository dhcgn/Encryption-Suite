using System;
using System.IO;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class EncryptInternalTest : TestBase
    {
        [Test]
        public void EncryptAndDecrypt_FileStream()
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Open(this.OutputFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
            }

            Console.Out.WriteLine("Encrypted content: " + Convert.ToBase64String(File.ReadAllBytes(this.OutputFile)));

            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                SymmetricEncryption.DecryptInternal(input, output, secret, null, new DecryptInternalParameter());
            }

            #endregion

            #region Assert

            Assert.That(File.ReadLines(this.InputFile), Is.EquivalentTo(File.ReadLines(this.ResultFile)));

            #endregion
        }

        [Test]
        public void EncryptAndDecrypt_MemoryStream()
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);
            var data = Encryption.Random.CreateData(512);

            #endregion

            #region Act

            MemoryStream output;
            using (var input = new MemoryStream(data))
            using (output = new MemoryStream())
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
            }

            var encryptedData = output.ToArray();

            Console.Out.WriteLine("Encrypted content: " + Convert.ToBase64String(encryptedData));

            MemoryStream decrypted;
            using (var input = new MemoryStream(encryptedData))
            using (decrypted = new MemoryStream())
            {
                SymmetricEncryption.DecryptInternal(input, decrypted, secret, null, new DecryptInternalParameter());
            }

            #endregion

            #region Assert

            Assert.That(data, Is.EquivalentTo(decrypted.ToArray()));

            #endregion
        }

        [Test]
        public void EncryptAndDecryptWithFilename()
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Open(this.OutputFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                SymmetricEncryption.EncryptInternal(input, output, secret, new EncryptInternalParameter()
                {
                    Filename = Guid.NewGuid().ToString()
                });
            }

            Console.Out.WriteLine("Encrypted content: " + Convert.ToBase64String(File.ReadAllBytes(this.OutputFile)));

            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                SymmetricEncryption.DecryptInternal(input, output, secret, null, new DecryptInternalParameter());
            }

            #endregion

            #region Assert

            Assert.That(File.ReadLines(this.InputFile), Is.EquivalentTo(File.ReadLines(this.ResultFile)));

            #endregion
        }

        [Test]
        public void FileformatHelper_FileStream()
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Open(this.OutputFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
            }

            Console.Out.WriteLine("Encrypted content: " + Convert.ToBase64String(File.ReadAllBytes(this.OutputFile)));

            byte[] iv;
            byte[] hmac;
            using (var input = File.OpenRead(this.OutputFile))
            {
                iv = RawFileAccessor.Read(input, RawFileAccessor.Field.InitializationVector);
                hmac = RawFileAccessor.Read(input, RawFileAccessor.Field.Hmac);
            }

            #endregion

            #region Assert

            Assert.That(iv, Is.Not.Null);
            Assert.That(hmac, Is.Not.Null);

            Assert.That(iv, Has.Length.EqualTo(128 / 8));
            Assert.That(hmac, Has.Length.EqualTo(512 / 8));

            Assert.That(iv, Has.Some.Not.EqualTo(0));
            Assert.That(hmac, Has.Some.Not.EqualTo(0));

            #endregion
        }
        [Test]
        public void FileformatHelper_MemoryStream()
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);
            var data = Guid.NewGuid().ToByteArray();

            #endregion

            #region Act

            byte[] encryptedData = null;
            using (var input = new MemoryStream(data))
            using (var output = new MemoryStream())
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
                encryptedData = output.ToArray();
            }

            Console.Out.WriteLine("Encrypted content: " + Convert.ToBase64String(File.ReadAllBytes(this.OutputFile)));

            byte[] iv;
            byte[] hmac;
            using (var input = new MemoryStream(encryptedData))
            {
                iv = RawFileAccessor.Read(input, RawFileAccessor.Field.InitializationVector);
                hmac = RawFileAccessor.Read(input, RawFileAccessor.Field.Hmac);
            }

            #endregion

            #region Assert

            Assert.That(iv, Is.Not.Null);
            Assert.That(hmac, Is.Not.Null);

            Assert.That(iv, Has.Length.EqualTo(128 / 8));
            Assert.That(hmac, Has.Length.EqualTo(512 / 8));

            Assert.That(iv, Has.Some.Not.EqualTo(0));
            Assert.That(hmac, Has.Some.Not.EqualTo(0));

            #endregion
        }
    }
}