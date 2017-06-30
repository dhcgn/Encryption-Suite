using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using NUnit.Framework.Internal;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture()]
    class SecretInformationTest
    {
        [Test]
        public void ToEncyptedData()
        {
            #region Arrange

            var si = new SecretInformation()
            {
                Filename = Guid.NewGuid().ToString()
            };

            var secret = Random.CreateData(512 / 8);
            var result = new MemoryStream();

            #endregion

            #region Act

            var encyptedData = si.ToEncyptedData(secret);

            #endregion

            #region Assert

            Assert.That(encyptedData, Is.Not.Null);

            #endregion
        }

        [Test]
        public void ToEncyptedDataAndDecryptInternal()
        {
            #region Arrange

            var si = new SecretInformation()
            {
                Filename = Guid.NewGuid().ToString()
            };

            var secret = Random.CreateData(512 / 8);
            var result = new MemoryStream();

            #endregion

            #region Act

            var encyptedData = si.ToEncyptedData(secret);
            SymmetricEncryption.DecryptInternal(new MemoryStream(encyptedData), result, secret, null, null);
            var secretInformation = SecretInformation.FromProtoBufData(result.ToArray());

            #endregion

            #region Assert

            Assert.That(secretInformation.Filename, Is.EqualTo(si.Filename));

            #endregion
        }
    }
}