using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using EncryptionSuite.Encryption;
using NUnit.Framework;

namespace EncryptionSuite.Contract.Test
{
    [TestFixture]
    public class EcKeyPairTest
    {
        private string testKey01Json = @"{""PrivateKey"":""NHRNbQQqo+6zz4tZTKbZYh7Nwri4x7cL0A2GyTRhojNMdhgBwAnJqg=="",""PublicKey"":{""Qx"":""AucN0sIniGKdewmEG8JSbVXMPw9k5cNUJU9Pczk0AWErw5UidNy39g=="",""Qy"":""UbP1iY8+EUpH3jRXmk3SIOOzcXirBTmyirPamzrcZgDqrm/zlVMqZg=="",""Version"":0},""Version"":0,""InculdePrivateKey"":true}";
        private byte[] testKey01Ans1 = Convert.FromBase64String("BFEEAucN0sIniGKdewmEG8JSbVXMPw9k5cNUJU9Pczk0AWErw5UidNy39lGz9YmPPhFKR940V5pN0iDjs3F4qwU5soqz2ps63GYA6q5v85VTKmY=");
        private byte[] testKey01Dre = Convert.FromBase64String("BALnDdLCJ4hinXsJhBvCUm1VzD8PZOXDVCVPT3M5NAFhK8OVInTct/ZRs/WJjz4RSkfeNFeaTdIg47NxeKsFObKKs9qbOtxmAOqub/OVUypm");

        [Test]
        public void GetPublicKeySaltedHash()
        {
            #region Arrange

            var keyPair = EllipticCurveCryptographer.CreateKeyPair(false);

            #endregion

            #region Act

            var result = keyPair.GetPublicKeySaltedHash();

            #endregion

            #region Assert

            Assert.That(result.hash, Is.Not.Null);
            Assert.That(result.salt, Is.Not.Null);

            Assert.That(result.hash, Has.Length.EqualTo(256 / 8));
            Assert.That(result.salt, Has.Length.EqualTo(256 / 8));

            #endregion
        }

        [Test]
        public void CheckHash()
        {
            #region Arrange

            var keyPair = EllipticCurveCryptographer.CreateKeyPair(false);
            var saltedHash = keyPair.GetPublicKeySaltedHash();

            #endregion

            #region Act

            var correctHash = keyPair.CheckPublicKeyHash(saltedHash.hash, saltedHash.salt);

            #endregion

            #region Assert

            Assert.That(correctHash, Is.True);

            #endregion
        }

        [Test]
        public void ToAns1()
        {
            #region Arrange

            var keyPair = EcKeyPair.FromJson(this.testKey01Json);

            #endregion

            #region Act

            var result = keyPair.ToAns1();

            #endregion

            #region Assert

            Assert.That(result, Is.EquivalentTo(this.testKey01Ans1));

            #endregion
        }

        [Test]
        public void ToDre()
        {
            #region Arrange

            var keyPair = EcKeyPair.FromJson(this.testKey01Json);

            #endregion

            #region Act

            var result = keyPair.ToDre();

            #endregion

            #region Assert

            Assert.That(result, Is.EquivalentTo(this.testKey01Dre));

            #endregion
        }
    }
}