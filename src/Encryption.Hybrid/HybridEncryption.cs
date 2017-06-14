using System;
using System.IO;
using System.Linq;
using EncryptionSuite.Contract;

namespace EncryptionSuite.Encryption.Hybrid
{
    public class HybridEncryption
    {
        public static void Encrypt(Stream input, Stream output, params EcKeyPair[] publicKeys)
        {
            Encrypt(input, output, null, null, publicKeys);
        }

        public static void Encrypt(Stream input, Stream output, Action<double> progress, Func<bool> isCanceled, params EcKeyPair[] publicKeys)
        {
            var secretKey = Random.CreateData(SymmetricEncryption.AesKeyLength + SymmetricEncryption.HmacKeyLength);

            var hybridFileInfo = SymmetricEncryption.EllipticCurveEncryptionInformation.Create(publicKeys, secretKey);

            var parameter = new SymmetricEncryption.EncryptInternalParameter
            {
                Filename = null,
                PasswordDerivationSettings = null,
                EllipticCurveEncryptionInformation = hybridFileInfo,
                Progress = progress,
                IsCanceled = isCanceled
            };

            SymmetricEncryption.EncryptInternal(input, output, secretKey, parameter);
        }

        public static void Decrypt(Stream input, Stream output, EcKeyPair privateKey, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            var parameter = new SymmetricEncryption.DecryptInternalParameter
            {
                EllipticCurveDeriveKeyAction = information => GetSecretKey(privateKey, information),
                Progress = progress,
                IsCanceled = isCanceled
            };

            SymmetricEncryption.DecryptInternal(input, output, null, null, parameter);
        }

        public static void Decrypt(Stream input, Stream output, string password, Action<double> progress = null, Func<bool> isCanceled = null)
        {
            var keys = Encryption.NitroKey.EllipticCurveCryptographer.GetEcKeyPairInfos();

            var parameter = new SymmetricEncryption.DecryptInternalParameter
            {
                EllipticCurveDeriveKeyAction = information =>
                {
                    var ecIdentifier = keys.FirstOrDefault(info => information.DerivedSecrets.Any(secret => info.PublicKey.ToAns1().SequenceEqual(secret.PublicKey.ToAns1())))?.EcIdentifier;
                    if (ecIdentifier == null)
                        throw new Exception("Couldn't find any key on any token");

                    return GetSecretKey(ecIdentifier, information, password);
                },
                Progress = progress,
                IsCanceled = isCanceled
            };

            SymmetricEncryption.DecryptInternal(input, output, null, null, parameter);
        }

        private static byte[] GetSecretKey(EcIdentifier ecIdentifier, SymmetricEncryption.EllipticCurveEncryptionInformation hybridFileInfo, string password)
        {
            var publicKey = Encryption.NitroKey.EllipticCurveCryptographer.GetPublicKey(ecIdentifier, password);
            var derivedSecret = hybridFileInfo.DerivedSecrets.FirstOrDefault(secret => secret.PublicKey.ToAns1().SequenceEqual(publicKey.ToAns1()));
            var ds = Encryption.NitroKey.EllipticCurveCryptographer.DeriveSecret(ecIdentifier, hybridFileInfo.EphemeralKey, password);

            var derivedSecretInputStream = new MemoryStream(derivedSecret.EncryptedSharedSecret);
            var derivedSecretOutputStream = new MemoryStream();

            SymmetricEncryption.Decrypt(derivedSecretInputStream, derivedSecretOutputStream, ds);

            var secretKey = derivedSecretOutputStream.ToArray();
            return secretKey;
        }

        private static byte[] GetSecretKey(EcKeyPair privateKey, SymmetricEncryption.EllipticCurveEncryptionInformation hybridFileInfo)
        {
            var derivedSecret = hybridFileInfo.DerivedSecrets.FirstOrDefault(secret => secret.PublicKey.ToAns1().SequenceEqual(privateKey.ToAns1()));

            var ds = EllipticCurveCryptographer.DeriveSecret(privateKey, hybridFileInfo.EphemeralKey);

            var derivedSecretInputStream = new MemoryStream(derivedSecret.EncryptedSharedSecret);
            var derivedSecretOutputStream = new MemoryStream();

            SymmetricEncryption.Decrypt(derivedSecretInputStream, derivedSecretOutputStream, ds);

            var secretKey = derivedSecretOutputStream.ToArray();
            return secretKey;
        }
    }
}