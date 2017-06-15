using System;
using System.IO;
using EncryptionSuite.Contract;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class FileOperationTest : TestBase
    {
        [Test]
        public void HasFileSignature_MagicNumberHybrid()
        {
            #region Arrange

            File.WriteAllBytes(this.InputFile, Constants.MagicNumberHybrid);

            #endregion

            #region Act

            var hasFileSignature = FileOperation.HasFileSignature(this.InputFile);

            #endregion

            #region Assert

            Assert.That(hasFileSignature);

            #endregion
        }

        [Test]
        public void HasFileSignature_MagicNumberSymmetric()
        {
            #region Arrange

            File.WriteAllBytes(this.InputFile, Constants.MagicNumberSymmetric);

            #endregion

            #region Act

            var hasFileSignature = FileOperation.HasFileSignature(this.InputFile);

            #endregion

            #region Assert

            Assert.That(hasFileSignature);

            #endregion
        }

        [Test]
        public void HasFileSignature_NotMatch()
        {
            #region Arrange

            File.WriteAllBytes(this.InputFile, Guid.NewGuid().ToByteArray());

            #endregion

            #region Act

            var hasFileSignature = FileOperation.HasFileSignature(this.InputFile);

            #endregion

            #region Assert

            Assert.That(hasFileSignature, Is.False);

            #endregion
        }
        [Test]
        public void HasFileSignature_NotFile()
        {
            #region Arrange

            string filepath = null;

            #endregion

            #region Act

            var hasFileSignature = FileOperation.HasFileSignature(filepath);

            #endregion

            #region Assert

            Assert.That(hasFileSignature, Is.False);

            #endregion
        }

        [Test]
        public void HasFileSignature_NotExistingFile()
        {
            #region Arrange

            string filepath = @"C:\" + Guid.NewGuid();

            #endregion

            #region Act

            var hasFileSignature = FileOperation.HasFileSignature(filepath);

            #endregion

            #region Assert

            Assert.That(hasFileSignature, Is.False);

            #endregion
        }
    }
}