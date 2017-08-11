using EncryptionSuite.Contract;
using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    internal class MetaInformation : ProtoBase<MetaInformation>
    {
        [ProtoMember(1, IsRequired = false)]
        public PasswordDerivationSettings PasswordDerivationSettings { get; set; }

        [ProtoMember(2, IsRequired = false)]
        public byte[] SecretInformationEncrypted { get; set; }

        [ProtoMember(3, IsRequired = false)]
        public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
    }
}