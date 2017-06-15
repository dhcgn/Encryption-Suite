using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Hybrid.Test
{
    [TestFixture]
    public class HybridEncryptionTest : TestBase
    {
        [Test]
        public void EncryptMultipleKeys()
        {
            #region Arrange

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);
            var bob = EllipticCurveCryptographer.CreateKeyPair(true);
            var guenther = EllipticCurveCryptographer.CreateKeyPair(true);

            var paramter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] {alice, bob, guenther}
            };

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                HybridEncryption.Encrypt(input, output, paramter);
            }

            #endregion

            #region Assert

            Assert.That(FileOperation.HasFileSignature(this.OutputFile), "HasFileSignature");
            Assert.Pass("No Exception occur");

            #endregion
        }

        [Test]
        public void EncryptWithProgress()
        {
            #region Arrange 

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);

            var progressValues = new List<double>();
            var multiplier = 10;

            var paramter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] {alice},
                Progress = d => progressValues.Add(d),
                IsCanceled = () => false,
            };

            #endregion

            #region Act 

            using (var input = new MemoryStream(new byte[SymmetricEncryption.BufferSize * multiplier]))
            using (var output = File.Create(this.OutputFile))
            {
                HybridEncryption.Encrypt(input, output, paramter);
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
        public void EncryptIsCanceled()
        {
            #region Arrange

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);

            var progressValues = new List<double>();
            var multiplier = 10;

            var paramter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] { alice },
                Progress = d => progressValues.Add(d),
                IsCanceled = () => true,
            };

            #endregion

            #region Act

            using (var input = new MemoryStream(new byte[SymmetricEncryption.BufferSize * multiplier]))
            using (var output = File.Create(this.OutputFile))
            {
                HybridEncryption.Encrypt(input, output, paramter);
            }

            #endregion

            #region Assert

            Assert.That(progressValues.Count, Is.EqualTo(0));

            #endregion
        }

        [Test]
        public void EncryptAndDecrypt()
        {
            #region Arrange

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);

            var encryptionParameter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] { alice.ExportPublicKey() },
            };

            var decryptionParameter = new HybridEncryption.DecryptionParameter()
            {
                PrivateKey = alice,
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
                HybridEncryption.Decrypt(input, output, decryptionParameter);
            }

            #endregion

            #region Assert

            var inputData = File.ReadAllBytes(this.InputFile);
            var outputData = File.ReadAllBytes(this.OutputFile);
            var resultData = File.ReadAllBytes(this.ResultFile);

            Assert.That(FileOperation.HasFileSignature(this.OutputFile), "HasFileSignature");
            Assert.That(inputData.Length, Is.LessThan(outputData.Length), "Input file is smaller than output file");
            Assert.That(outputData, Is.Not.EquivalentTo(resultData), "Encrypted file is not equal to plain file");
            Assert.That(inputData.Length, Is.EqualTo(resultData.Length), "size of plain file is equal to encrypted file");
            Assert.That(inputData, Is.EquivalentTo(resultData), "plain file is equal to encrypted file");

            #endregion
        }

        [Test]
        public void EncryptAndDecryptWithFilename()
        {
            #region Arrange

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);

            var encryptionParameter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] { alice.ExportPublicKey() },
                Filename = Guid.NewGuid().ToString(),
            };

            var decryptionParameter = new HybridEncryption.DecryptionParameter()
            {
                PrivateKey = alice,
            };

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                HybridEncryption.Encrypt(input, output, encryptionParameter);
            }

            SymmetricEncryption.DecryptInfo info;
            using (var input = File.OpenRead(this.OutputFile))
            using (var output = File.Create(this.ResultFile))
            {
                info = HybridEncryption.Decrypt(input, output, decryptionParameter);
            }

            #endregion

            #region Assert

            Assert.That(encryptionParameter.Filename, Is.EqualTo(info.FileName), "is decrypted filename equal to input filename");

            #endregion
        }

        [Test]
        public void EncryptAndDecryptMultipleKeys()
        {
            #region Arrange

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);
            var bob = EllipticCurveCryptographer.CreateKeyPair(true);
            var guenther = EllipticCurveCryptographer.CreateKeyPair(true);

            var encryptionParameter = new HybridEncryption.EncryptionParameter()
            {
                PublicKeys = new[] { alice.ExportPublicKey(), bob.ExportPublicKey(),guenther.ExportPublicKey() },
            };

            #endregion

            #region Act

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                HybridEncryption.Encrypt(input, output, encryptionParameter);
            }

            #endregion

            foreach (var ecKeyPair in new[] { alice, bob, guenther})
            {
                #region Arrange

                var decryptionParameter = new HybridEncryption.DecryptionParameter()
                {
                    PrivateKey = ecKeyPair,
                };

                #endregion

                #region Act

                using (var input = File.OpenRead(this.OutputFile))
                using (var output = File.Create(this.ResultFile))
                {
                    HybridEncryption.Decrypt(input, output, decryptionParameter);
                }

                #endregion

                #region Assert

                var inputData = File.ReadAllBytes(this.InputFile);
                var outputData = File.ReadAllBytes(this.OutputFile);
                var resultData = File.ReadAllBytes(this.ResultFile);

                Assert.That(FileOperation.HasFileSignature(this.OutputFile), "HasFileSignature");
                Assert.That(inputData.Length, Is.LessThan(outputData.Length), "Input file is smaller than output file");
                Assert.That(outputData, Is.Not.EquivalentTo(resultData), "Encrypted file is not equal to plain file");
                Assert.That(inputData.Length, Is.EqualTo(resultData.Length), "size of plain file is equal to encrypted file");
                Assert.That(inputData, Is.EquivalentTo(resultData), "plain file is equal to encrypted file");

                #endregion
            }
        }
    }
}