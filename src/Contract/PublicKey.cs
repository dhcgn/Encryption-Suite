using ProtoBuf;

namespace EncryptionSuite.Contract
{
    [ProtoContract]
    public class PublicKey : ProtoBase<PublicKey>
    {
        [ProtoMember(1, IsRequired = true)]
        public byte[] Qx { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public byte[] Qy { get; set; }
    }
}