using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionSuite.Encryption
{
    public class Hasher
    {
        public static byte[] CreateAesKeyFromPassword(string password, byte[] salt, int iterations)
        {
            Console.Out.WriteLine("password:   " + password);
            Console.Out.WriteLine("salt:       " + Convert.ToBase64String(salt));
            Console.Out.WriteLine("iterations: " + iterations);

            byte[] keyAes;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                keyAes = deriveBytes.GetBytes(512 / 8);
            }
            return keyAes;
        }
    }
}
