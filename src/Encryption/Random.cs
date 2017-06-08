using System.Security.Cryptography;

namespace EncryptionSuite.Encryption
{
    public class Random
    {
        public static byte[] CreateSalt(int bit = 512/8)
        {
            return CreateData(bit);
        }

        public static byte[] CreateData(int bytes)
        {
            var salt = new byte[bytes];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(salt);
            }
            return salt;
        }
    }
}