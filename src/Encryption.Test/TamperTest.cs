using System.IO;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    public class TamperTest : TestBase
    {

        [TestCase(SymmetricEncryptionTest.TamperEnum.AesKey, TestName = "Tamper AES Key")]
        [TestCase(SymmetricEncryptionTest.TamperEnum.HmacHash, TestName = "Tamper HMAC hash")]
        [TestCase(SymmetricEncryptionTest.TamperEnum.Iv, TestName = "Tamper IV")]
        [TestCase(SymmetricEncryptionTest.TamperEnum.File, TestName = "Tamper encrypted file")]
        [TestCase(SymmetricEncryptionTest.TamperEnum.Nothing, TestName = "Tamper nothing")]
        public void Tamper(SymmetricEncryptionTest.TamperEnum tamperEnum)
        {
            #region Arrange

            var secret = Encryption.Random.CreateData(512 / 8);

            using (var input = File.OpenRead(this.InputFile))
            using (var output = File.Create(this.OutputFile))
            {
                SymmetricEncryption.EncryptInternal(input, output, secret);
            }

            #endregion

            #region Act

            switch (tamperEnum)
            {
                case SymmetricEncryptionTest.TamperEnum.AesKey:
                    Assert.Fail("Not Implemented");
                    break;
                case SymmetricEncryptionTest.TamperEnum.HmacHash:
                    Assert.Fail("Not Implemented");
                    //informationContainer.PublicInformation.HmacHash[0] ^= informationContainer.PublicInformation.HmacHash[0];
                    break;
                case SymmetricEncryptionTest.TamperEnum.Iv:
                    Assert.Fail("Not Implemented");
                    // informationContainer.PublicInformation.IV[0] ^= informationContainer.PublicInformation.IV[0];
                    break;
                case SymmetricEncryptionTest.TamperEnum.File:
                    Assert.Fail("Not Implemented");
                    break;
                case SymmetricEncryptionTest.TamperEnum.Nothing:
                    break;
            }

            #endregion

            #region Assert

            Assert.Fail("Not Implemented");

            #endregion
        }
    }
}