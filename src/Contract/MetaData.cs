using ProtoBuf;

namespace EncryptionSuite.Contract
{
    [ProtoContract]
    public class MetaData : ProtoBase<MetaData>
    {
        [ProtoMember(1)]
        public string Filename { get; set; }

        public static MetaData CreateFromFilePath(string filename)
        {
            return new MetaData()
            {
                Filename = filename,
            };
        }
    }
}