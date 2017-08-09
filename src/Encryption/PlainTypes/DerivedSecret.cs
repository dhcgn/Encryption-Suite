using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    public class DerivedSecret
    {
        [ProtoMember(1, IsRequired = true)]
        public byte[] PublicKeyHash { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public byte[] PublicKeyHashSalt { get; set; }

        [ProtoMember(3, IsRequired = true)]
        public byte[] EncryptedSharedSecret { get; set; }
    }
}