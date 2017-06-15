using System.IO;
using System.Linq;
using EncryptionSuite.TestHelper;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Hybrid.Test
{
    [TestFixture]
    public class HybridEncryptionNitrokeyTest : TestBase
    {
        [Test]
        public void EncryptMultipleKeys()
        {
            #region Arrange

            var ecKeyPairInfos = Encryption.NitroKey.EllipticCurveCryptographer.GetEcKeyPairInfos();
            var encryptionParameter = new HybridEncryption.EncryptionParameter
            {
                PublicKeys = ecKeyPairInfos.Select(info => info.PublicKey.ExportPublicKey()),
            };

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                HybridEncryption.Encrypt(input, output, encryptionParameter);
            }

            #endregion

            #region Assert

            Assert.Pass("No Exception occur");

            #endregion
        }

        [Test]
        public void EncryptAndDecryptMultipleKeys()
        {
            #region Arrange

            var ecKeyPairInfos = Encryption.NitroKey.EllipticCurveCryptographer.GetEcKeyPairInfos().First();
            var encryptionParameter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] {ecKeyPairInfos.PublicKey.ExportPublicKey()}
            };
            var decrptionParameter = new HybridEncryption.DecryptionParameter
            {
                Password = Constants.TestPin
            };

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                
                HybridEncryption.Encrypt(input, output, encryptionParameter);
            }

            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                HybridEncryption.Decrypt(input, output, decrptionParameter);
            }

            #endregion

            #region Assert

            var inputData = File.ReadAllBytes(this.InputFile);
            var outputData = File.ReadAllBytes(this.OutputFile);
            var resultData = File.ReadAllBytes(this.ResultFile);

            Assert.That(inputData.Length, Is.LessThan(outputData.Length), "Input file is smaller than output file");
            Assert.That(outputData, Is.Not.EquivalentTo(resultData), "Encrypted file is not equal to plain file");
            Assert.That(inputData.Length, Is.EqualTo(resultData.Length), "size of plain file is equal to encrypted file");
            Assert.That(inputData, Is.EquivalentTo(resultData), "plain file is equal to encrypted file");

            #endregion
        }
    }
}