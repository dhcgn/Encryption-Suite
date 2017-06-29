using System;
using System.IO;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class EncryptRawTest : TestBase
    {
        [Test]
        public void EncryptAndDecrypt()
        {
            #region Arrange

            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);

            byte[] secret = Random.CreateData(512 / 8);

            (byte[] hmacHash, byte[] iv) parameter;

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                parameter = SymmetricEncryption.EncryptRaw(input, output, secret);
            }

            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                SymmetricEncryption.DecryptRaw(input, output, secret, parameter);
            }

            #endregion

            #region Assert

            Assert.That(File.ReadLines(this.InputFile), Is.EquivalentTo(File.ReadLines(this.ResultFile)));

            #endregion
        }
    }
}