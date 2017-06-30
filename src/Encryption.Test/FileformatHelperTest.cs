using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionSuite.Contract;
using Newtonsoft.Json;
using NUnit.Framework;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class FileformatHelperTest : TestBase
    {
        [Test]
        public void Init()
        {
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.Init(stream);
            }
        }

        [Test]
        public void InitVerify()
        {
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.Init(stream);
            }

            bool verify;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                verify = SymmetricEncryption.FileformatHelper.Verify(stream);
            }
            Assert.That(verify);
        }

        [Test]
        public void SeekToMainData()
        {
            long position = 0;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.SeekToMainData(stream);
                position = stream.Position;
            }

            var sum = SymmetricEncryption.FileformatHelper.Positions.Sum(pair => pair.Value.length);
            Assert.That(position, Is.EqualTo(sum));
        }

        [Test]
        public void SeekToMainDataWithData()
        {
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                foreach (var value in SymmetricEncryption.FileformatHelper.Positions.Keys)
                {
                    var inputData = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[value].length);
                    SymmetricEncryption.FileformatHelper.Write(stream, inputData, value);
                }
            }
            var fileMetaInfo = new SymmetricEncryption.InformationContainer
            {
                DerivationSettings = SymmetricEncryption.PasswordDerivationSettings.Create(),
                EllipticCurveEncryptionInformation = null,
                SecretInformationData = Random.CreateData(1024)
            };

            using (var output = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.WriteMeta(output, fileMetaInfo);
            }

            int metaPosition = 0;
            using (var output = File.OpenRead(this.OutputFile))
            {
                var data = SymmetricEncryption.FileformatHelper.Read(output, SymmetricEncryption.FileformatHelper.Field.MetaLength);
                metaPosition = BitConverter.ToInt32(data, 0);
            }


            long position = 0;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.SeekToMainData(stream);
                position = stream.Position;
            }

            var sum = SymmetricEncryption.FileformatHelper.Positions.Sum(pair => pair.Value.length);
            Assert.That(position, Is.EqualTo(sum + metaPosition));
        }

        [Test]
        public void Workflow()
        {
            #region Arrange

            var testData = new
            {
                Iv = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[SymmetricEncryption.FileformatHelper.Field.InitializationVector].length),
                Hmac = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[SymmetricEncryption.FileformatHelper.Field.Hmac].length),
                Version = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[SymmetricEncryption.FileformatHelper.Field.Version].length),
                Data = Random.CreateData(1024),
                InformationContainer = new SymmetricEncryption.InformationContainer
                {
                    DerivationSettings = SymmetricEncryption.PasswordDerivationSettings.Create(),
                    EllipticCurveEncryptionInformation = null,
                    SecretInformationData = Random.CreateData(8)
                }
            };

            using (var stream = File.Open(this.OutputFile, FileMode.OpenOrCreate))
            {
                SymmetricEncryption.FileformatHelper.Init(stream);
                SymmetricEncryption.FileformatHelper.WriteMeta(stream, testData.InformationContainer);
                SymmetricEncryption.FileformatHelper.SeekToMainData(stream);
                new MemoryStream(testData.Data).CopyTo(stream);
                SymmetricEncryption.FileformatHelper.Write(stream, testData.Iv, SymmetricEncryption.FileformatHelper.Field.InitializationVector);
                SymmetricEncryption.FileformatHelper.Write(stream, testData.Hmac, SymmetricEncryption.FileformatHelper.Field.Hmac);
            }

            #endregion

            #region Act

            byte[] iv;
            byte[] hmac;
            byte[] data;
            SymmetricEncryption.InformationContainer informationContainer;
            using (var stream = File.Open(this.OutputFile, FileMode.OpenOrCreate))
            {
                informationContainer = SymmetricEncryption.FileformatHelper.ReadMeta(stream);
                iv = SymmetricEncryption.FileformatHelper.Read(stream, SymmetricEncryption.FileformatHelper.Field.InitializationVector);
                hmac = SymmetricEncryption.FileformatHelper.Read(stream, SymmetricEncryption.FileformatHelper.Field.Hmac);
                SymmetricEncryption.FileformatHelper.SeekToMainData(stream);
                var ms = new MemoryStream();
                stream.CopyTo(ms);
                ;
                data = ms.ToArray();
            }

            #endregion

            #region Assert

            Assert.That(iv, Is.EquivalentTo(testData.Iv));
            Assert.That(hmac, Is.EquivalentTo(testData.Hmac));
            Assert.That(data, Is.EquivalentTo(testData.Data));

            Assert.That(JsonConvert.SerializeObject(informationContainer), Is.EquivalentTo(JsonConvert.SerializeObject(testData.InformationContainer)));

            #endregion
        }

        [Test]
        public void WriteMeta()
        {
            EllipticCurveCryptographer.CreateKeyPair(false);

            var fileMetaInfo = new SymmetricEncryption.InformationContainer
            {
                DerivationSettings = SymmetricEncryption.PasswordDerivationSettings.Create(),
                EllipticCurveEncryptionInformation = null,
                SecretInformationData = Random.CreateData(1024)
            };

            using (var output = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.WriteMeta(output, fileMetaInfo);
            }
        }


        [Test]
        public void ReadMeta()
        {
            EllipticCurveCryptographer.CreateKeyPair(false);

            var fileMetaInfo = new SymmetricEncryption.InformationContainer
            {
                DerivationSettings = SymmetricEncryption.PasswordDerivationSettings.Create(),
                EllipticCurveEncryptionInformation = null,
                SecretInformationData = Random.CreateData(1024)
            };

            using (var output = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.WriteMeta(output, fileMetaInfo);
            }

            SymmetricEncryption.InformationContainer result;
            using (var output = File.OpenRead(this.OutputFile))
            {
                result = SymmetricEncryption.FileformatHelper.ReadMeta(output);
            }

            Assert.That(JsonConvert.SerializeObject(fileMetaInfo), Is.EqualTo(JsonConvert.SerializeObject(result)));
        }

        [Test]
        public void EncryptInternal_MemoryStream()
        {
            var data = Guid.NewGuid().ToByteArray();
            var secret = Random.CreateData(512 / 8);

            MemoryStream newStream;
            using (var encrypted = new MemoryStream())
            {
                SymmetricEncryption.EncryptInternal(new MemoryStream(data), encrypted, secret);
                newStream = new MemoryStream(encrypted.ToArray());
            }

            Assert.That(SymmetricEncryption.FileformatHelper.Verify(newStream), "verify file signature");

            var iv = SymmetricEncryption.FileformatHelper.Read(newStream, SymmetricEncryption.FileformatHelper.Field.InitializationVector);
            Assert.That(iv, Has.Some.Not.EqualTo(0), "InitializationVector");

            var hmac = SymmetricEncryption.FileformatHelper.Read(newStream, SymmetricEncryption.FileformatHelper.Field.Hmac);
            Assert.That(hmac, Has.Some.Not.EqualTo(0), "Hmac");
        }

        [Test]
        public void EncryptInternal_FileStream()
        {
            var data = Guid.NewGuid().ToByteArray();
            var secret = Random.CreateData(512 / 8);

            using (var output = File.Open(this.OutputFile,FileMode.Open,FileAccess.ReadWrite,FileShare.ReadWrite))
            {
                SymmetricEncryption.EncryptInternal(new MemoryStream(data), output, secret);
            }

            var newStream = File.OpenRead(this.OutputFile);

            Assert.That(SymmetricEncryption.FileformatHelper.Verify(newStream));

            var iv = SymmetricEncryption.FileformatHelper.Read(newStream, SymmetricEncryption.FileformatHelper.Field.InitializationVector);
            Assert.That(iv, Has.All.Not.EqualTo(0), "InitializationVector");

            var hmac = SymmetricEncryption.FileformatHelper.Read(newStream, SymmetricEncryption.FileformatHelper.Field.Hmac);
            Assert.That(hmac, Has.Some.Not.EqualTo(0), "Hmac");
        }

        [Test]
        [TestCase("Hmac")]
        [TestCase("FileSignature")]
        [TestCase("Version")]
        [TestCase("MetaLength")]
        [TestCase("InitializationVector")]
        public void Write(string name)
        {
            var field = (SymmetricEncryption.FileformatHelper.Field) Enum.Parse(typeof(SymmetricEncryption.FileformatHelper.Field), name);

            var inputData = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[field].length);
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.Write(stream, inputData, field);
            }

            Assert.Pass();
        }


        [Test]
        [TestCase("Hmac")]
        [TestCase("FileSignature")]
        [TestCase("Version")]
        [TestCase("MetaLength")]
        [TestCase("InitializationVector")]
        public void Read_FileStream(string name)
        {
            var field = (SymmetricEncryption.FileformatHelper.Field) Enum.Parse(typeof(SymmetricEncryption.FileformatHelper.Field), name);

            var inputData = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[field].length);
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                SymmetricEncryption.FileformatHelper.Write(stream, inputData, field);
            }


            byte[] readData;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                readData = SymmetricEncryption.FileformatHelper.Read(stream, field);
            }

            Assert.That(inputData, Is.EquivalentTo(readData));
        }

        [Test]
        [TestCase("Hmac")]
        [TestCase("FileSignature")]
        [TestCase("Version")]
        [TestCase("MetaLength")]
        [TestCase("InitializationVector")]
        public void Read_MemoryStream(string name)
        {
            var field = (SymmetricEncryption.FileformatHelper.Field) Enum.Parse(typeof(SymmetricEncryption.FileformatHelper.Field), name);

            var inputData = Random.CreateData(SymmetricEncryption.FileformatHelper.Positions[field].length);
            MemoryStream inputStream;
            using (inputStream = new MemoryStream())
            {
                SymmetricEncryption.FileformatHelper.Write(inputStream, inputData, field);
            }


            byte[] readData;
            using (var stream = new MemoryStream(inputStream.ToArray()))
            {
                readData = SymmetricEncryption.FileformatHelper.Read(stream, field);
            }

            Assert.That(inputData, Is.EquivalentTo(readData));
        }
    }
}