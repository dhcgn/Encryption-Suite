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
                RawFileAccessor.Init(stream);
            }
        }

        [Test]
        public void InitVerify()
        {
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                RawFileAccessor.Init(stream);
            }

            bool verify;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                verify = RawFileAccessor.Verify(stream);
            }
            Assert.That(verify);
        }

        [Test]
        public void SeekToMainData()
        {
            long position = 0;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                RawFileAccessor.SeekToMainData(stream);
                position = stream.Position;
            }

            var sum = RawFileAccessor.Positions.Sum(pair => pair.Value.length);
            Assert.That(position, Is.EqualTo(sum));
        }

        [Test]
        public void SeekToMainDataWithData()
        {
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                foreach (var value in RawFileAccessor.Positions.Keys)
                {
                    var inputData = Random.CreateData(RawFileAccessor.Positions[value].length);
                    RawFileAccessor.Write(stream, inputData, value);
                }
            }
            var fileMetaInfo = new FileCargo
            {
                DerivationSettings = PasswordDerivationSettings.Create(),
                EllipticCurveEncryptionInformation = null,
                SecretInformationData = Random.CreateData(1024)
            };

            using (var output = File.OpenWrite(this.OutputFile))
            {
                RawFileAccessor.WriteMeta(output, fileMetaInfo);
            }

            int metaPosition = 0;
            using (var output = File.OpenRead(this.OutputFile))
            {
                var data = RawFileAccessor.Read(output, RawFileAccessor.Field.MetaLength);
                metaPosition = BitConverter.ToInt32(data, 0);
            }


            long position = 0;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                RawFileAccessor.SeekToMainData(stream);
                position = stream.Position;
            }

            var sum = RawFileAccessor.Positions.Sum(pair => pair.Value.length);
            Assert.That(position, Is.EqualTo(sum + metaPosition));
        }

        [Test]
        public void Workflow()
        {
            #region Arrange

            var testData = new
            {
                Iv = Random.CreateData(RawFileAccessor.Positions[RawFileAccessor.Field.InitializationVector].length),
                Hmac = Random.CreateData(RawFileAccessor.Positions[RawFileAccessor.Field.Hmac].length),
                Version = Random.CreateData(RawFileAccessor.Positions[RawFileAccessor.Field.Version].length),
                Data = Random.CreateData(1024),
                InformationContainer = new FileCargo
                {
                    DerivationSettings = PasswordDerivationSettings.Create(),
                    EllipticCurveEncryptionInformation = null,
                    SecretInformationData = Random.CreateData(8)
                }
            };

            using (var stream = File.Open(this.OutputFile, FileMode.OpenOrCreate))
            {
                RawFileAccessor.Init(stream);
                RawFileAccessor.WriteMeta(stream, testData.InformationContainer);
                RawFileAccessor.SeekToMainData(stream);
                new MemoryStream(testData.Data).CopyTo(stream);
                RawFileAccessor.Write(stream, testData.Iv, RawFileAccessor.Field.InitializationVector);
                RawFileAccessor.Write(stream, testData.Hmac, RawFileAccessor.Field.Hmac);
            }

            #endregion

            #region Act

            byte[] iv;
            byte[] hmac;
            byte[] data;
            FileCargo fileCargo;
            using (var stream = File.Open(this.OutputFile, FileMode.OpenOrCreate))
            {
                fileCargo = RawFileAccessor.ReadMeta(stream);
                iv = RawFileAccessor.Read(stream, RawFileAccessor.Field.InitializationVector);
                hmac = RawFileAccessor.Read(stream, RawFileAccessor.Field.Hmac);
                RawFileAccessor.SeekToMainData(stream);
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

            Assert.That(JsonConvert.SerializeObject(fileCargo), Is.EquivalentTo(JsonConvert.SerializeObject(testData.InformationContainer)));

            #endregion
        }

        [Test]
        public void WriteMeta()
        {
            EllipticCurveCryptographer.CreateKeyPair(false);

            var fileMetaInfo = new FileCargo
            {
                DerivationSettings = PasswordDerivationSettings.Create(),
                EllipticCurveEncryptionInformation = null,
                SecretInformationData = Random.CreateData(1024)
            };

            using (var output = File.OpenWrite(this.OutputFile))
            {
                RawFileAccessor.WriteMeta(output, fileMetaInfo);
            }
        }


        [Test]
        public void ReadMeta()
        {
            EllipticCurveCryptographer.CreateKeyPair(false);

            var fileMetaInfo = new FileCargo
            {
                DerivationSettings = PasswordDerivationSettings.Create(),
                EllipticCurveEncryptionInformation = null,
                SecretInformationData = Random.CreateData(1024)
            };

            using (var output = File.OpenWrite(this.OutputFile))
            {
                RawFileAccessor.WriteMeta(output, fileMetaInfo);
            }

           FileCargo result;
            using (var output = File.OpenRead(this.OutputFile))
            {
                result = RawFileAccessor.ReadMeta(output);
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

            Assert.That(RawFileAccessor.Verify(newStream), "verify file signature");

            var iv = RawFileAccessor.Read(newStream, RawFileAccessor.Field.InitializationVector);
            Assert.That(iv, Has.Some.Not.EqualTo(0), "InitializationVector");

            var hmac = RawFileAccessor.Read(newStream, RawFileAccessor.Field.Hmac);
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

            Assert.That(RawFileAccessor.Verify(newStream));

            var iv = RawFileAccessor.Read(newStream, RawFileAccessor.Field.InitializationVector);
            Assert.That(iv, Has.Some.Not.EqualTo(0), "InitializationVector");

            var hmac = RawFileAccessor.Read(newStream, RawFileAccessor.Field.Hmac);
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
            var field = (RawFileAccessor.Field) Enum.Parse(typeof(RawFileAccessor.Field), name);

            var inputData = Random.CreateData(RawFileAccessor.Positions[field].length);
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                RawFileAccessor.Write(stream, inputData, field);
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
            var field = (RawFileAccessor.Field) Enum.Parse(typeof(RawFileAccessor.Field), name);

            var inputData = Random.CreateData(RawFileAccessor.Positions[field].length);
            using (var stream = File.OpenWrite(this.OutputFile))
            {
                RawFileAccessor.Write(stream, inputData, field);
            }


            byte[] readData;
            using (var stream = File.OpenRead(this.OutputFile))
            {
                readData = RawFileAccessor.Read(stream, field);
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
            var field = (RawFileAccessor.Field) Enum.Parse(typeof(RawFileAccessor.Field), name);

            var inputData = Random.CreateData(RawFileAccessor.Positions[field].length);
            MemoryStream inputStream;
            using (inputStream = new MemoryStream())
            {
                RawFileAccessor.Write(inputStream, inputData, field);
            }


            byte[] readData;
            using (var stream = new MemoryStream(inputStream.ToArray()))
            {
                readData = RawFileAccessor.Read(stream, field);
            }

            Assert.That(inputData, Is.EquivalentTo(readData));
        }
    }
}