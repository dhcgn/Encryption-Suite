using System.IO;
using ProtoBuf;

namespace EncryptionSuite.Contract
{
    public abstract class ProtoBase<T>
    {
        public byte[] ToProtoBufData()
        {
            var protoStream = new MemoryStream();
            Serializer.Serialize(protoStream, this);
            return protoStream.ToArray();
        }

        public static T FromProtoBufData(byte[] data)
        {
            var protoStream = new MemoryStream(data);
            return Serializer.Deserialize<T>(protoStream);
        }
    }
}