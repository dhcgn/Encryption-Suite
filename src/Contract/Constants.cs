using System.Collections.Generic;

namespace EncryptionSuite.Contract
{
    public static class Constants
    {
        public static byte[] MagicNumberSymmetric = {0x1c, 0x48, 0xe5, 0x3c, 0xDE, 0xED, 0xBE, 0xEF,};
        public static byte[] MagicNumberHybrid = {0x1c, 0x48, 0xe5, 0x3c, 0xBA, 0xDD, 0xCA, 0xFE,};

        public static HashSet<byte[]> MagicNumbers = new HashSet<byte[]> {MagicNumberHybrid, MagicNumberSymmetric};
    }
}