using System.IO;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class EncryptInternalTest : TestBase
    {
        public void EncryptAndDecrypt()
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
            }

            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                SymmetricEncryption.DecryptInternal(input, output, secret, null, new SymmetricEncryption.DecryptInternalParameter());
            }

            #endregion

            #region Assert

            Assert.That(File.ReadLines(this.InputFile), Is.EquivalentTo(File.ReadLines(this.ResultFile)));

            #endregion
        }
    }
}