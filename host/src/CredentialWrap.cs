using System;
using System.Security.Cryptography;

namespace PlugPass
{
    // A credential ID carries its own private key, encrypted and authenticated with keys derived
    // from the master secret, so nothing per site needs to be stored.
    //
    // Credential ID, version 1:
    //   0x01 | IV (16) | AES-256-CBC(encKey, payload) | HMAC-SHA256(macKey, 0x01 | IV | ciphertext) (32)
    // payload: RP ID hash (32) | P-256 private key blob (104) | user handle length (1) | user handle (0-64)
    // encKey = HMAC-SHA256(master, "PlugPass credential enc v1"), macKey likewise with "mac".
    internal static class CredentialWrap
    {
        internal const byte Version = 1;
        internal const int MaxUserHandle = 64;
        private const int IvLength = 16;
        private const int MacLength = 32;
        private const int HashLength = 32;

        internal sealed class Contents
        {
            internal byte[] RpIdHash;
            internal byte[] KeyBlob;
            internal byte[] UserHandle;
        }

        internal static byte[] Wrap(byte[] master, byte[] rpIdHash, byte[] keyBlob, byte[] userHandle)
        {
            if (rpIdHash.Length != HashLength || userHandle.Length > MaxUserHandle)
            {
                throw new ArgumentException("Bad credential contents.");
            }
            EcKey.CheckBlob(keyBlob);
            byte[] payload = Bytes.Concat(rpIdHash, keyBlob, new byte[] { (byte)userHandle.Length }, userHandle);
            byte[] iv = new byte[IvLength];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            byte[] ct;
            using (Aes aes = NewAes(master, iv))
            using (ICryptoTransform enc = aes.CreateEncryptor())
            {
                ct = enc.TransformFinalBlock(payload, 0, payload.Length);
            }
            Array.Clear(payload, 0, payload.Length);
            byte[] head = Bytes.Concat(new byte[] { Version }, iv, ct);
            return Bytes.Concat(head, Mac(master, head));
        }

        // Null when the ID wasn't made by this master secret (another key, tampered, or garbage).
        internal static Contents Unwrap(byte[] master, byte[] id)
        {
            int minLength = 1 + IvLength + 16 + MacLength;
            if (id == null || id.Length < minLength || id[0] != Version || (id.Length - 1 - IvLength - MacLength) % 16 != 0)
            {
                return null;
            }
            byte[] head = new byte[id.Length - MacLength];
            Buffer.BlockCopy(id, 0, head, 0, head.Length);
            byte[] mac = new byte[MacLength];
            Buffer.BlockCopy(id, head.Length, mac, 0, MacLength);
            if (!Bytes.FixedTimeEquals(mac, Mac(master, head)))
            {
                return null;
            }
            byte[] iv = new byte[IvLength];
            Buffer.BlockCopy(head, 1, iv, 0, IvLength);
            byte[] payload;
            using (Aes aes = NewAes(master, iv))
            using (ICryptoTransform dec = aes.CreateDecryptor())
            {
                payload = dec.TransformFinalBlock(head, 1 + IvLength, head.Length - 1 - IvLength);
            }
            int fixedLength = HashLength + EcKey.BlobLength + 1;
            if (payload.Length < fixedLength || payload.Length != fixedLength + payload[fixedLength - 1])
            {
                return null;
            }
            Contents c = new Contents();
            c.RpIdHash = Take(payload, 0, HashLength);
            c.KeyBlob = Take(payload, HashLength, EcKey.BlobLength);
            c.UserHandle = Take(payload, fixedLength, payload[fixedLength - 1]);
            Array.Clear(payload, 0, payload.Length);
            return c;
        }

        private static Aes NewAes(byte[] master, byte[] iv)
        {
            Aes aes = new AesCryptoServiceProvider();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = Derive(master, "PlugPass credential enc v1");
            aes.IV = iv;
            return aes;
        }

        private static byte[] Mac(byte[] master, byte[] data)
        {
            using (HMACSHA256 h = new HMACSHA256(Derive(master, "PlugPass credential mac v1")))
            {
                return h.ComputeHash(data);
            }
        }

        private static byte[] Derive(byte[] master, string label)
        {
            using (HMACSHA256 h = new HMACSHA256(master))
            {
                return h.ComputeHash(Bytes.Utf8(label));
            }
        }

        private static byte[] Take(byte[] a, int offset, int count)
        {
            byte[] r = new byte[count];
            Buffer.BlockCopy(a, offset, r, 0, count);
            return r;
        }
    }
}
