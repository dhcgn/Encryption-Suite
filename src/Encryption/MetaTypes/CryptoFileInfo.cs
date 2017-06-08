﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using EncryptionSuite.Contract;
using ProtoBuf;

namespace EncryptionSuite.Encryption.MetaTypes
{
    [ProtoContract]
    public class CryptoFileInfo : ProtoBase<CryptoFileInfo>
    {
        [ProtoIgnore]
        public static readonly IReadOnlyList<byte> MagicNumber = new[] {(byte) 159, (byte) 96, (byte) 234, (byte) 202, (byte) 146, (byte) 105, (byte) 123};

        [ProtoMember(1)]
        public byte[] Iv { get; set; }

        [ProtoMember(2)]
        public byte[] Salt { get; set; }

        [ProtoMember(3)]
        public int Iterations { get; set; }

        [ProtoMember(4)]
        public byte[] Hmac { get; set; }

        [ProtoMember(5)]
        public byte[] EncryptedMetaData { get; set; }

        [ProtoMember(Int16.MaxValue)]
        public int Version { get; set; }

        internal static void WriteToDisk(CryptoFileInfo cryptoFileInfo, Stream output, Stream rawFile)
        {
            var cryptoFileInfoDate = cryptoFileInfo.ToProtoBufData();

            new MemoryStream(CryptoFileInfo.MagicNumber.ToArray()).CopyTo(output);
            new MemoryStream(BitConverter.GetBytes(cryptoFileInfoDate.Length)).CopyTo(output);
            new MemoryStream(cryptoFileInfoDate).CopyTo(output);
            rawFile.CopyTo(output);
        }

        internal static CryptoFileInfo LoadFromDisk(Stream input, FileStream raw)
        {
            byte[] magicData = new byte[CryptoFileInfo.MagicNumber.Count];
            input.Read(magicData, 0, magicData.Length);

            if (!magicData.SequenceEqual(CryptoFileInfo.MagicNumber))
                throw new Exception("File header does not match");

            byte[] intData = new byte[4];
            input.Read(intData, 0, intData.Length);
            int intValue = BitConverter.ToInt32(intData, 0);

            var protoDate = new byte[intValue];
            input.Read(protoDate, 0, intValue);

            input.CopyTo(raw);

            return CryptoFileInfo.FromProtoBufData(protoDate);
        }
    }
}