using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using EncryptionSuite.Contract;

namespace EncryptionSuite.Encryption.Hybrid
{
    public class HybridEncryption
    {
        public class EncryptionParameter
        {
            public IEnumerable<EcKeyPair> PublicKeys { get; set; }

            public Func<bool> IsCanceled { get; set; } = () => false;
            public Action<double> Progress { get; set; }
            public string Filename { get; set; }
        }

        public class DecryptionParameter
        {
            public string Password { get; set; }
            public EcKeyPair PrivateKey { get; set; }

            public Func<bool> IsCanceled { get; set; } = () => false;
            public Action<double> Progress { get; set; }
        }

        public static void Encrypt(Stream input, Stream output, EncryptionParameter parameter)
        {
            var secretKey = Random.CreateData(SymmetricEncryption.AesKeyLength + SymmetricEncryption.HmacKeyLength);

            var hybridFileInfo = EllipticCurveEncryptionInformation.Create(parameter.PublicKeys, secretKey);

            var internalParameter = new EncryptInternalParameter
            {
                Filename = parameter.Filename,
                PasswordDerivationSettings = null,
                EllipticCurveEncryptionInformation = hybridFileInfo,
                Progress = parameter.Progress,
                IsCanceled = parameter.IsCanceled
            };

            SymmetricEncryption.EncryptInternal(input, output, secretKey, internalParameter);
        }

        public static DecryptInfo Decrypt(Stream input, Stream output, DecryptionParameter parameter)
        {
            byte[] DeriveSecretFromHsm(EllipticCurveEncryptionInformation information)
            {
                var keys = Encryption.NitroKey.EllipticCurveCryptographer.GetEcKeyPairInfos();
                var ecIdentifier = keys.FirstOrDefault(info => information.DerivedSecrets.Any(secret => info.PublicKey.CheckPublicKeyHash(secret.PublicKeyHash, secret.PublicKeyHashSalt)))?.EcIdentifier;
                if (ecIdentifier == null)
                    throw new Exception("Couldn't find any key on any token");

                return GetSecretKey(ecIdentifier, information, parameter.Password);
            }

            var internalParameter = new DecryptInternalParameter
            {
                EllipticCurveDeriveKeyAction = information => parameter.PrivateKey == null ? DeriveSecretFromHsm(information) : GetSecretKey(parameter.PrivateKey, information),
                Progress = parameter.Progress,
                IsCanceled = parameter.IsCanceled
            };

            return SymmetricEncryption.DecryptInternal(input, output, null, null, internalParameter);
        }

        private static byte[] GetSecretKey(EcIdentifier ecIdentifier, EllipticCurveEncryptionInformation hybridFileInfo, string password)
        {
            var publicKey = Encryption.NitroKey.EllipticCurveCryptographer.GetPublicKey(ecIdentifier, password);
            var derivedSecret = hybridFileInfo.DerivedSecrets.FirstOrDefault(secret => publicKey.CheckPublicKeyHash(secret.PublicKeyHash, secret.PublicKeyHashSalt));
            var ds = Encryption.NitroKey.EllipticCurveCryptographer.DeriveSecret(ecIdentifier, hybridFileInfo.EphemeralKey, password);

            var derivedSecretInputStream = new MemoryStream(derivedSecret.EncryptedSharedSecret);
            var derivedSecretOutputStream = new MemoryStream();

            SymmetricEncryption.Decrypt(derivedSecretInputStream, derivedSecretOutputStream, ds);

            var secretKey = derivedSecretOutputStream.ToArray();
            return secretKey;
        }

        private static byte[] GetSecretKey(EcKeyPair privateKey, EllipticCurveEncryptionInformation hybridFileInfo)
        {
            var derivedSecret = hybridFileInfo.DerivedSecrets.FirstOrDefault(secret => privateKey.CheckPublicKeyHash(secret.PublicKeyHash, secret.PublicKeyHashSalt));

            var ds = EllipticCurveCryptographer.DeriveSecret(privateKey, hybridFileInfo.EphemeralKey);

            var derivedSecretInputStream = new MemoryStream(derivedSecret.EncryptedSharedSecret);
            var derivedSecretOutputStream = new MemoryStream();

            SymmetricEncryption.Decrypt(derivedSecretInputStream, derivedSecretOutputStream, ds);

            var secretKey = derivedSecretOutputStream.ToArray();
            return secretKey;
        }
    }
}