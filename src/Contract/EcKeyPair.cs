using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using ProtoBuf;

namespace EncryptionSuite.Contract
{
    [ProtoContract]
    public partial class EcKeyPair : ProtoBase<EcKeyPair>
    {
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        [ProtoMember(1)]
        public byte[] PrivateKey { get; set; }

        [ProtoMember(2)]
        public PublicKey PublicKey { get; set; }

        public int Version { get; set; }
    }

    /// <summary>
    /// Assembly contract shouldn't know all this crypto stuff
    /// </summary>
    public partial class EcKeyPair
    {
        public EcKeyPair ExportPublicKey()
        {
            return new EcKeyPair
            {
                PublicKey = new PublicKey
                {
                    Qx = this.PublicKey.Qx,
                    Qy = this.PublicKey.Qy,
                }
            };
        }

        /// <summary>
        /// Todo Because earsdropper should get the public key hash only, and receiver only need an inditcator that he could decrypt trhis message.
        /// </summary>
        /// <returns></returns>
        public (byte[] hash, byte[] salt) GetPublicKeySaltedHash()
        {
            var salt = new byte[256 / 8];
            RandomNumberGenerator.Create().GetBytes(salt);

            var hash = SHA256.Create().ComputeHash(this.ToAns1().Concat(salt).ToArray());

            return ValueTuple.Create(hash, salt);
        }

        public bool CheckPublicKeyHash(byte[] hash, byte[] salt)
        {
            var hashCompare = SHA256.Create().ComputeHash(this.ToAns1().Concat(salt).ToArray());
            return hash.SequenceEqual(hashCompare);
        }

        public static EcKeyPair CreateFromECParameters(ECParameters exportParameters)
        {
            return new EcKeyPair
            {
                PublicKey = new PublicKey()
                {
                    Qx = exportParameters.Q.X,
                    Qy = exportParameters.Q.Y,
                },
                PrivateKey = exportParameters.D
            };
        }

        public ECParameters CreateECParameters()
        {
            var ecParameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = this.PublicKey.Qx,
                    Y = this.PublicKey.Qy
                },
                D = this.PrivateKey,
                Curve = ECCurve.NamedCurves.brainpoolP320r1
            };
            ecParameters.Validate();

            return ecParameters;
        }


        public static EcKeyPair CreateFromAnsi(byte[] ecPoint)
        {
            // 045104
            if (ecPoint == null || ecPoint.Length != 83 || !ecPoint.Take(3).SequenceEqual(ans1Header))
                throw new ArgumentException("Must be 83 Bytes long and starts with 0x04.", nameof(ecPoint));

            return new EcKeyPair
            {
                PublicKey = new PublicKey()
                {
                    Qx = ecPoint.Skip(3).Take(40).ToArray(),
                    Qy = ecPoint.Skip(3).Skip(40).Take(40).ToArray(),
                },
              
                PrivateKey= null,
            };
        }

        private static byte[] ans1Header = new[] { (byte)0x04, (byte)0x51, (byte)0x04 };

        public byte[] ToAns1()
        {
            var uncompressedIndicator = (byte)0x04;
            var expetedLength = (byte)0x51;

            return new[] {uncompressedIndicator, expetedLength}.Concat(this.ToDre()).ToArray();
        }

        /// <summary>
        /// Spec: "The uncompressed form is indicated by 0x04"
        /// </summary>
        /// <returns></returns>
        /// <remarks>
        /// https://tools.ietf.org/html/rfc5480 -> Subject Public Key
        /// </remarks>
        public byte[] ToDre()
        {
            var uncompressedIndicator = (byte)0x04;
            return new[] { uncompressedIndicator }.Concat(this.PublicKey.Qx).Concat(this.PublicKey.Qy).ToArray();
        }

        [JsonIgnore]
        public string ToJson => JsonConvert.SerializeObject(this);

        public bool InculdePrivateKey => this.PrivateKey != null;

        public string ToArmor()
        {
            var base64 = Convert.ToBase64String(this.ToProtoBufData());
            var typeName = this.InculdePrivateKey ? "PRIVATE" : "PUBLIC";
            var start = $"-----BEGIN {typeName} KEY BLOCK-----";
            var end = $"-----END {typeName} BLOCK-----";

            var content = Regex.Replace(base64, $".{{{start.Length}}}", "$0\n");

            return start + "\r\n" + content + "\r\n" + end;
        }

        public static EcKeyPair FromJson(string json)
        {
            var keyPair = JsonConvert.DeserializeObject<EcKeyPair>(json);
            return keyPair;
        }
    }
}