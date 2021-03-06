using System;
using System.IO;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Hybrid.Test
{
    public class TestBase
    {
        internal string InputFile;
        internal string OutputFile;
        internal string ResultFile;
        internal string RawFile;

        [SetUp]
        public void Setup()
        {
            var isOpenScInstalled = Encryption.NitroKey.EllipticCurveCryptographer.OpenSCIsInstalled();
            if (!isOpenScInstalled)
                Assert.Inconclusive("OpenSC is not installed");

            var tokenPresent = Encryption.NitroKey.EllipticCurveCryptographer.TokenPresent();
            if (!tokenPresent)
                Assert.Inconclusive("No NitroKey token present");

            this.InputFile = Path.GetTempFileName();
            this.OutputFile = Path.GetTempFileName();
            this.ResultFile = Path.GetTempFileName();
            this.RawFile = Path.GetTempFileName();

            var data = Guid.NewGuid().ToByteArray();
            File.WriteAllBytes(this.InputFile, data);
        }


        [TearDown]
        public void TearDown()
        {
            foreach (var file in new[] { this.InputFile, this.OutputFile, this.ResultFile, this.RawFile })
            {
                try
                {
                    if (File.Exists(file))
                        File.Delete(file);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }
    }
}