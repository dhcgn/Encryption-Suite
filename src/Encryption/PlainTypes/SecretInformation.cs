using System.IO;
using EncryptionSuite.Contract;
using ProtoBuf;

namespace EncryptionSuite.Encryption
{
    [ProtoContract]
    internal class SecretInformation : ProtoBase<SecretInformation>
    {
        [ProtoMember(1, IsRequired = false)]
        public string Filename { get; set; }

        internal byte[] ToEncyptedData(byte[] secret)
        {
            var secretInformationPlainData = this.ToProtoBufData();
            var encrypted = new MemoryStream();
            var input = new MemoryStream();

            new MemoryStream(secretInformationPlainData).CopyTo(input);
            input.Seek(0, SeekOrigin.Begin);
            SymmetricEncryption.EncryptInternal(input, encrypted, secret);

            return encrypted.ToArray();
        }
    }
}