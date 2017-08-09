using System.Collections.Generic;
using System.IO;
using EncryptionSuite.Contract;
using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    public class EllipticCurveEncryptionInformation : ProtoBase<EllipticCurveEncryptionInformation>
    {
        [ProtoMember(1, IsRequired = true)]
        public List<DerivedSecret> DerivedSecrets { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public EcKeyPair EphemeralKey { get; set; }

        public static EllipticCurveEncryptionInformation Create(IEnumerable<EcKeyPair> publicKeys, byte[] secretKey)
        {
            var ephemeralKey = EllipticCurveCryptographer.CreateKeyPair(true);

            var result = new EllipticCurveEncryptionInformation
            {
                EphemeralKey = ephemeralKey.ExportPublicKey(),
            };

            result.DerivedSecrets = new List<DerivedSecret>();
            foreach (var publicKey in publicKeys)
            {
                var deriveSecret = EllipticCurveCryptographer.DeriveSecret(ephemeralKey, publicKey);

                var input = new MemoryStream(secretKey);
                var output = new MemoryStream();
                SymmetricEncryption.Encrypt(input, output, deriveSecret);

                var saltedHash = publicKey.GetPublicKeySaltedHash();

                var derivedSecret = new DerivedSecret
                {
                    PublicKeyHash = saltedHash.hash,
                    PublicKeyHashSalt = saltedHash.salt,
                    EncryptedSharedSecret = output.ToArray()
                };
                result.DerivedSecrets.Add(derivedSecret);
            }
            return result;
        }
    }
}