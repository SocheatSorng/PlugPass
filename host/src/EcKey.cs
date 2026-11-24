using System;
using System.Security.Cryptography;

namespace PlugPass
{
    // ECDSA P-256 keys (WebAuthn ES256, COSE alg -7) via Windows CNG. A key is kept as its
    // 104-byte BCRYPT_ECCPRIVATE_BLOB: 8-byte header (magic, key size), X, Y, d.
    internal static class EcKey
    {
        internal const int BlobLength = 104;
        internal const int CoseAlgEs256 = -7;
        private const int Header = 8;
        private const int Size = 32;
        private const uint PrivateMagicP256 = 0x32534345; // "ECS2"

        // SubjectPublicKeyInfo prefix for an uncompressed P-256 point (id-ecPublicKey, prime256v1).
        private static readonly byte[] SpkiPrefix =
        {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        };

        internal static byte[] Generate()
        {
            CngKeyCreationParameters p = new CngKeyCreationParameters();
            p.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
            using (CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, p))
            {
                byte[] blob = key.Export(CngKeyBlobFormat.EccPrivateBlob);
                CheckBlob(blob);
                return blob;
            }
        }

        internal static void CheckBlob(byte[] blob)
        {
            if (blob == null || blob.Length != BlobLength || BitConverter.ToUInt32(blob, 0) != PrivateMagicP256
                || BitConverter.ToUInt32(blob, 4) != Size)
            {
                throw new CryptographicException("Not a P-256 private key.");
            }
        }

        // DER-encoded ECDSA-SHA256 signature over data (the format WebAuthn uses).
        internal static byte[] Sign(byte[] blob, byte[] data)
        {
            CheckBlob(blob);
            using (CngKey key = CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob))
            using (ECDsaCng ec = new ECDsaCng(key))
            {
                ec.HashAlgorithm = CngAlgorithm.Sha256;
                return RawToDer(ec.SignData(data));
            }
        }

        internal static byte[] X(byte[] blob)
        {
            return Slice(blob, Header, Size);
        }

        internal static byte[] Y(byte[] blob)
        {
            return Slice(blob, Header + Size, Size);
        }

        // COSE_Key map {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}, canonical order.
        internal static byte[] CoseKey(byte[] blob)
        {
            return new CborWriter().Map(5)
                .Int(1).Int(2)
                .Int(3).Int(CoseAlgEs256)
                .Int(-1).Int(1)
                .Int(-2).Bytes(X(blob))
                .Int(-3).Bytes(Y(blob))
                .ToArray();
        }

        internal static byte[] Spki(byte[] blob)
        {
            return Bytes.Concat(SpkiPrefix, X(blob), Y(blob));
        }

        // CNG returns r||s (32 bytes each); WebAuthn wants SEQUENCE { INTEGER r, INTEGER s }.
        internal static byte[] RawToDer(byte[] raw)
        {
            byte[] r = DerInteger(Slice(raw, 0, raw.Length / 2));
            byte[] s = DerInteger(Slice(raw, raw.Length / 2, raw.Length / 2));
            return Bytes.Concat(new byte[] { 0x30, (byte)(r.Length + s.Length) }, r, s);
        }

        private static byte[] DerInteger(byte[] v)
        {
            int i = 0;
            while (i < v.Length - 1 && v[i] == 0)
            {
                i++;
            }
            byte[] trimmed = Slice(v, i, v.Length - i);
            bool pad = (trimmed[0] & 0x80) != 0;
            byte[] body = pad ? Bytes.Concat(new byte[] { 0 }, trimmed) : trimmed;
            return Bytes.Concat(new byte[] { 0x02, (byte)body.Length }, body);
        }

        private static byte[] Slice(byte[] a, int offset, int count)
        {
            byte[] r = new byte[count];
            Buffer.BlockCopy(a, offset, r, 0, count);
            return r;
        }
    }
}
