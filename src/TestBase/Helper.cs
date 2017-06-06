using System;
using System.Linq;

namespace EncryptionSuite.TestHelper
{
    public class Helper
    {
        public string ToHexString(byte[] data)
        {
            return BitConverter.ToString(data).ToLower().Replace("-", null);
        }

        public byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}
