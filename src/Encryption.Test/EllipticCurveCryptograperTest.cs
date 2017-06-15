using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using EncryptionSuite.Contract;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class EllipticCurveCryptograperTest : TestHelper.Helper
    {
        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Thread.CurrentThread.CurrentUICulture = new CultureInfo("en-us");
        }

        [Test]

        public void SignDataAndVerifyData()
        {
            #region Arrange

            var plainMsg = Encoding.UTF8.GetBytes("Hello World");
            var keyPair = EllipticCurveCryptographer.CreateKeyPair(true);
            
            #endregion

            #region Act

            var signature1 = EllipticCurveCryptographer.SignData(keyPair, plainMsg);
            var signature2 = EllipticCurveCryptographer.SignData(keyPair, plainMsg);

            #endregion

            #region Assert

            Assert.That(signature1, Is.Not.EquivalentTo(signature2), "Signature #1 and #2 are NOT equal");

            Assert.That(EllipticCurveCryptographer.VerifyData(keyPair.ExportPublicKey(), plainMsg, signature1), "Signature of #1 is valid");
            Assert.That(EllipticCurveCryptographer.VerifyData(keyPair.ExportPublicKey(), plainMsg, signature2), "Signature of #2 is valid");

            #endregion
        }

        [Test]
        [TestCase(true, Description = "Include Private Key")]
        [TestCase(false, Description = "Include no Private Key")]
        public void CreateKeyPair(bool includePrivateParameters)
        {
            #region Arrange

            // See method arguments

            #endregion

            #region Act

            var keyPair = EllipticCurveCryptographer.CreateKeyPair(includePrivateParameters);

            #endregion

            #region Assert

            Console.Out.WriteLine($"----------- json ({keyPair.ToJson.Length})------------");
            Console.Out.WriteLine(keyPair.ToJson);
            Console.Out.WriteLine($"----------- raw ({Convert.ToBase64String(keyPair.ToProtoBufData()).Length})------------");
            Console.Out.WriteLine(Convert.ToBase64String(keyPair.ToProtoBufData()));
            Console.Out.WriteLine($"----------- armor ({keyPair.ToArmor().Length})------------");
            Console.Out.WriteLine(keyPair.ToArmor());
            Console.Out.WriteLine($"----------- ToAns1 ({keyPair.ToAns1().Length})------------");
            Console.Out.WriteLine(base.ToHexString(keyPair.ToAns1()));
            Console.Out.WriteLine($"----------- ToDre ({keyPair.ToDre().Length})------------");
            Console.Out.WriteLine(base.ToHexString(keyPair.ToDre()));

            Assert.Pass("No Exception");

            #endregion
        }

        [Test]
        [TestCase(true, Description = "Include Private Key")]
        [TestCase(false, Description = "Include no Private Key")]
        public void CreateKeyPair_FromJson(bool includePrivateParameters)
        {
            #region Arrange

            // See method arguments

            #endregion

            #region Act

            var keyPair = EllipticCurveCryptographer.CreateKeyPair(includePrivateParameters);
            var fromJson = EcKeyPair.FromJson(keyPair.ToJson);
            
            #endregion

            #region Assert

            Console.Out.WriteLine(fromJson.ToJson);
            Assert.Pass("No Exception");

            #endregion
        }

        [Test]
        public void DeriveSecret()
        {
            #region Arrange

            var alice = EllipticCurveCryptographer.CreateKeyPair(true);
            var bob = EllipticCurveCryptographer.CreateKeyPair(true);

            var salt = Random.CreateSalt();
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(salt);
            }

            #endregion

            #region Act

            var derivedSecret1 = EllipticCurveCryptographer.DeriveSecret(alice, bob.ExportPublicKey());
            var derivedSecret2 = EllipticCurveCryptographer.DeriveSecret(bob, alice.ExportPublicKey());

            #endregion

            #region Assert

            Console.Out.WriteLine($"derivedSecret length: {derivedSecret1?.Length * 8} bit");

            Console.Out.WriteLine($"derivedSecret1 : {Convert.ToBase64String(derivedSecret1).Substring(0, 16)} ...");
            Console.Out.WriteLine($"derivedSecret2 : {Convert.ToBase64String(derivedSecret2).Substring(0, 16)} ...");

            Assert.That(derivedSecret1, Has.Length.GreaterThan(0));
            Assert.That(derivedSecret2, Has.Length.GreaterThan(0));

            Assert.That(derivedSecret1, Is.EquivalentTo(derivedSecret2));
            
            #endregion
        }
    }
}