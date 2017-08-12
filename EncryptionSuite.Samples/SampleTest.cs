using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionSuite.Contract;
using EncryptionSuite.Encryption;
using EncryptionSuite.Encryption.Hybrid;

namespace EncryptionSuite.Samples
{
    [TestFixture]
    public class SampleTest
    {
        [SetUp]
        public void Setup()
        {
            this.InputFile = Path.GetTempFileName();
            this.EncryptedFile = Path.GetTempFileName();
            this.PlainFile = Path.GetTempFileName();

            File.WriteAllBytes(this.InputFile, Guid.NewGuid().ToByteArray());
        }

        [Test]
        public void SymmetricEncryption_FilePath()
        {
            var pwd = "MyPassword";
            File.WriteAllText(this.InputFile, "My Stuff");

            SymmetricEncryption.Encrypt(this.InputFile, this.EncryptedFile, pwd);
            var info = SymmetricEncryption.Decrypt(this.EncryptedFile, this.PlainFile, pwd);

            Console.Out.WriteLine(info.FileName);
            Console.Out.WriteLine(File.ReadAllText(this.PlainFile));
        }

        [Test]
        public void HybridEncryption_FilePath()
        {
            var myPrivateKeyJson = @"
{
   ""PrivateKey"":""NquxhQX9cmWkyDulDIm6OEzty5roXQHApdJInL4gPQbmkXqrVBHhkA=="",
   ""PublicKey"":{
      ""Qx"":""tS37fNpfdy5diNusCoalxUn0HOdjqJk2OybUA9jy8HnzCSg0rFi3bA=="",
      ""Qy"":""sYIRXtP1j3tspMyJOeuCDdG4Ifm3DKC+yIHOFyLUTt8R4z0OxWpLqg==""
   },
   ""InculdePrivateKey"":true
}
";
            var myPrivateKey = EcKeyPair.FromJson(myPrivateKeyJson);
            var bobPublicAns1Key = EcKeyPair.CreateFromAnsi(Convert.FromBase64String("BFEECnHOtY1L3He8vwsH0ahiDZZzavjxZzciXYXrzaNP1Zn/x1sL+4lvOpktdaZSjgWH/X2JI1rAqBVl7NO3R0UWJ4WtKnrGa5IhSiW0oC7s2lU="));

            File.WriteAllText(this.InputFile, "My Stuff");

            var encryptionParameter = new HybridEncryption.EncryptionParameter
            {
                PublicKeys = new[] { myPrivateKey.ExportPublicKey(), bobPublicAns1Key.ExportPublicKey() },
            };

            HybridEncryption.Encrypt(this.InputFile, this.EncryptedFile, encryptionParameter);

            var decryptionParameter = new HybridEncryption.DecryptionParameter
            {
                PrivateKey = myPrivateKey,
            };
            var info = HybridEncryption.Decrypt(this.EncryptedFile, this.PlainFile, decryptionParameter);

            Console.Out.WriteLine(info.FileName);
            Console.Out.WriteLine(File.ReadAllText(this.PlainFile));
        }

        public string EncryptedFile { get; set; }

        public string InputFile { get; set; }

        public string PlainFile { get; set; }
    }
}
