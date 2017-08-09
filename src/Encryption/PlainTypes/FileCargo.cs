using EncryptionSuite.Contract;
using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    internal class FileCargo : ProtoBase<FileCargo>
    {
        [ProtoMember(1, IsRequired = false)]
        public PasswordDerivationSettings DerivationSettings { get; set; }

        [ProtoMember(2, IsRequired = false)]
        public byte[] SecretInformationData { get; set; }

        [ProtoMember(3, IsRequired = false)]
        public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
    }
}