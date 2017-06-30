using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    public class DerivedSecret
    {
        [ProtoMember(1)]
        public byte[] PublicKeyHash { get; set; }

        [ProtoMember(2)]
        public byte[] PublicKeyHashSalt { get; set; }

        [ProtoMember(3)]
        public byte[] EncryptedSharedSecret { get; set; }
    }
}