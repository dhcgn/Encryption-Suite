using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    internal class PasswordDerivationSettings
    {
        public static PasswordDerivationSettings Create()
        {
            return new PasswordDerivationSettings
            {
#if DEBUG
                Iterations = 100,
#else
                Iterations = 100_000,
#endif
                Salt = Random.CreateData(128 / 8),
            };
        }

        [ProtoMember(1)]
        public byte[] Salt { get; internal set; }

        [ProtoMember(2)]
        public int Iterations { get; internal set; }
    }
}