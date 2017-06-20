using System.Security.Cryptography;

namespace EncryptionSuite.Encryption
{
    public class Hasher
    {
        public static byte[] CreateAesKeyFromPassword(string password, byte[] salt, int iterations)
        {
            byte[] keyAes;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                keyAes = deriveBytes.GetBytes(512 / 8);
            }
            return keyAes;
        }
    }
}
