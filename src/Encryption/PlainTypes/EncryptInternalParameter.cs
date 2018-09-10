using System;
using System.Runtime.CompilerServices;

[assembly:InternalsVisibleTo("EncryptionSuite.Encryption.Hybrid")]

namespace EncryptionSuite.Encryption
{
    internal class EncryptInternalParameter
    {
        public PasswordDerivationSettings PasswordDerivationSettings { get; set; }
        public string Filename { get; set; }
        public EllipticCurveEncryptionInformation EllipticCurveEncryptionInformation { get; set; }
        public Action<double> Progress { get; set; }
        public Func<bool> IsCanceled { get; set; }
    }
}