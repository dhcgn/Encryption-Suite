using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionSuite.Encryption;

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

        public string EncryptedFile { get; set; }

        public string InputFile { get; set; }

        public string PlainFile { get; set; }
    }
}
