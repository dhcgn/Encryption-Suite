using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using EncryptionSuite.Contract;

namespace EncryptionSuite.Encryption
{
    internal class RawFileAccessor
    {
        internal enum Field
        {
            FileSignature = 0,
            Version = 1,
            Hmac = 2,
            InitializationVector = 3,
            MetaLength = 4,
        }

        internal static Dictionary<Field, (int begin, int length)> Positions = new Dictionary<Field, (int begin, int length)>()
        {
            {Field.FileSignature, (0, 8)},
            {Field.Version, (8, 16 / 8)},
            {Field.Hmac, (10, 512 / 8)},
            {Field.InitializationVector,(74, 128 / 8)},
            {Field.MetaLength, (90, 32 / 8)},
        };


        internal static void Write(Stream output, byte[] data, Field field)
        {
            var valueTuple = Positions[field];
            WriteInternal(output, data, valueTuple);
        }

        private static void WriteInternal(Stream output, byte[] data, ValueTuple<int, int> valueTuple)
        {
            if (data.Length != valueTuple.Item2)
                throw new Exception($"File length {valueTuple.Item2} expeted but was {data.Length}.");

            output.Seek(valueTuple.Item1, SeekOrigin.Begin);
            output.Write(data, 0, valueTuple.Item2);
        }

        internal static byte[] Read(Stream input, Field field)
        {
            var valueTuple = Positions[field];
            return ReadInternal(input, valueTuple);
        }

        private static byte[] ReadInternal(Stream input, ValueTuple<int, int> valueTuple)
        {
            input.Seek(valueTuple.Item1, SeekOrigin.Begin);
            byte[] data = new byte[valueTuple.Item2];
            input.Read(data, 0, valueTuple.Item2);
            return data;
        }

        internal static void SeekToMainData(Stream input)
        {
            var positonMetaData = Positions.Sum(pair => pair.Value.length);
            var metaDataLength = Read(input, Field.MetaLength);
            var length = BitConverter.ToInt32(metaDataLength, 0);

            input.Seek(length + positonMetaData, SeekOrigin.Begin);
        }

        internal static void Init(Stream output)
        {
            output.Seek(Positions[Field.FileSignature].begin, SeekOrigin.Begin);
            new MemoryStream(Constants.MagicNumberSymmetric.ToArray()).CopyTo(output);
        }

        internal static bool Verify(Stream input)
        {
            input.Seek(0, SeekOrigin.Begin);

            byte[] magicData = new byte[Constants.MagicNumberSymmetric.Length];
            input.Read(magicData, 0, magicData.Length);

            return Constants.MagicNumberSymmetric.SequenceEqual(magicData);
        }

        public static MetaInformation ReadMeta(Stream input)
        {
            var metaDataLength = Read(input, Field.MetaLength);
            var length = BitConverter.ToInt32(metaDataLength, 0);
            var positonMetaData = Positions.Sum(pair => pair.Value.length);

            var data = ReadInternal(input, (positonMetaData, length));

            return MetaInformation.FromProtoBufData(data);
        }

        public static void WriteMeta(Stream output, MetaInformation metaInformation)
        {
            var metaData = metaInformation.ToProtoBufData();
            var metaDataLength = BitConverter.GetBytes(metaData.Length);
            Write(output, metaDataLength, Field.MetaLength);

            var positonMetaData = Positions.Sum(pair => pair.Value.length);

            WriteInternal(output, metaData, (positonMetaData, metaData.Length));
        }
    }
}