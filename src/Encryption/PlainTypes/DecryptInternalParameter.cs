using System;

namespace EncryptionSuite.Encryption
{
    internal class DecryptInternalParameter
    {
        public Func<EllipticCurveEncryptionInformation, byte[]> EllipticCurveDeriveKeyAction { get; set; }
        public Action<double> Progress { get; set; }
        public Func<bool> IsCanceled { get; set; }
    }
}