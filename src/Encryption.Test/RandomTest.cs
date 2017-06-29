using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class RandomTest 
    {
        [Test]
        public void CreateData()
        {
            #region Arrange

            var bits = 128;

            #endregion

            #region Act

            var result = Random.CreateData(bits / 8);

            #endregion

            #region Assert

            Assert.That(result, Is.Not.Null);
            Assert.That(result, Has.Length.EqualTo(bits / 8));

            #endregion
        }
    }
}