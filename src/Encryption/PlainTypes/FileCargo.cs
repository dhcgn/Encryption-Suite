using EncryptionSuite.Contract;
using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    internal class FileCargo : ProtoBase<FileCargo>
    {
        [ProtoMember(1)]
        public PasswordDerivationSettings DerivationSettings { get; set; }

        [ProtoMember(2)]
        public byte[] SecretInformationData { get; set; }

        [ProtoMember(3)]
        public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
    }
}