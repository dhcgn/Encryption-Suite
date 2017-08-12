using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionSuite.Contract;
using NUnit.Framework;
using ProtoBuf;

namespace EncryptionSuite.Encryption.Test
{
    [TestFixture]
    public class GetProtoTest
    {
        [Test]
        public void GetProto_MetaInformation()
        {
            var proto = ProtoBuf.Serializer.GetProto<MetaInformation>();
            Console.Out.WriteLine(proto);
        }

        [Test]
        public void GetProto_SecretInformation()
        {
            var proto = ProtoBuf.Serializer.GetProto<SecretInformation>();
            Console.Out.WriteLine(proto);
        }
    }
}
