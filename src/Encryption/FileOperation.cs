using System.IO;
using System.Linq;

namespace EncryptionSuite.Encryption
{
    public class FileOperation
    {
        public static bool HasFileSignature(string path)
        {
            if (path == null || !File.Exists(path)) return false;

            var maxLength = Contract.Constants.MagicNumbers.Max(bytes => bytes.Length);

            byte[] buffer = new byte[maxLength];
            try
            {
                using (var fs = File.OpenRead(path))
                {
                    fs.Read(buffer, 0, buffer.Length);
                    fs.Close();
                }
            }
            catch
            {
                return false;
            }

            return Contract.Constants.MagicNumbers.Any(bytes => buffer.Take(bytes.Length).SequenceEqual(bytes));
        }
    }
}