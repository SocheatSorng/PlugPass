using System;
using System.Security.Cryptography;

namespace PlugPass
{
    // A credential ID carries its own private key, encrypted and authenticated with keys derived from
    // the drive's master secret, so a site's key can always be rebuilt from the drive.
    //
    // Credential ID, version 2:
    //   0x02 | drive key ID (16) | IV (16) | AES-256-CBC(encKey, payload) | HMAC-SHA256(macKey, everything before) (32)
    // payload: RP ID hash (32) | P-256 private key blob (104) | user handle length (1) | user handle (0-64)
    // encKey = HMAC-SHA256(master, "PlugPass credential enc v2"), macKey likewise with "mac".
    // The key ID is public: it tells which drive made the credential without asking for the PIN.
    // (Version 1 was the phase 1 test format, with no drive; it is no longer accepted.)
    internal static class CredentialWrap
    {
        internal const byte Version = 2;
        internal const int MaxUserHandle = 64;
        private const int KeyIdLength = KeyFile.KeyIdLength;
        private const int IvLength = 16;
        private const int MacLength = 32;
        private const int HashLength = 32;
        private const int Prefix = 1 + KeyIdLength + IvLength;

        internal sealed class Contents
        {
            internal byte[] RpIdHash;
            internal byte[] KeyBlob;
            internal byte[] UserHandle;
        }

        internal static byte[] Wrap(byte[] master, byte[] keyId, byte[] rpIdHash, byte[] keyBlob, byte[] userHandle)
        {
            if (keyId.Length != KeyIdLength || rpIdHash.Length != HashLength || userHandle.Length > MaxUserHandle)
            {
                throw new ArgumentException("Bad credential contents.");
            }
            EcKey.CheckBlob(keyBlob);
            byte[] payload = Bytes.Concat(rpIdHash, keyBlob, new byte[] { (byte)userHandle.Length }, userHandle);
            byte[] iv = KeyFile.Random(IvLength);
            byte[] ct;
            using (Aes aes = NewAes(master, iv))
            using (ICryptoTransform enc = aes.CreateEncryptor())
            {
                ct = enc.TransformFinalBlock(payload, 0, payload.Length);
            }
            Array.Clear(payload, 0, payload.Length);
            byte[] head = Bytes.Concat(new byte[] { Version }, keyId, iv, ct);
            return Bytes.Concat(head, Mac(master, head));
        }

        // The drive key ID inside a credential ID, or null if it isn't a PlugPass v2 ID.
        internal static byte[] KeyIdOf(byte[] id)
        {
            if (!WellFormed(id))
            {
                return null;
            }
            return Take(id, 1, KeyIdLength);
        }

        // Null when the ID wasn't made by this master secret (another drive, tampered, or garbage).
        internal static Contents Unwrap(byte[] master, byte[] id)
        {
            if (!WellFormed(id))
            {
                return null;
            }
            byte[] head = Take(id, 0, id.Length - MacLength);
            if (!Bytes.FixedTimeEquals(Take(id, head.Length, MacLength), Mac(master, head)))
            {
                return null;
            }
            byte[] payload;
            using (Aes aes = NewAes(master, Take(head, 1 + KeyIdLength, IvLength)))
            using (ICryptoTransform dec = aes.CreateDecryptor())
            {
                payload = dec.TransformFinalBlock(head, Prefix, head.Length - Prefix);
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

        private static bool WellFormed(byte[] id)
        {
            return id != null && id.Length >= Prefix + 16 + MacLength && id[0] == Version
                && (id.Length - Prefix - MacLength) % 16 == 0;
        }

        private static Aes NewAes(byte[] master, byte[] iv)
        {
            Aes aes = new AesCryptoServiceProvider();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = Derive(master, "PlugPass credential enc v2");
            aes.IV = iv;
            return aes;
        }

        private static byte[] Mac(byte[] master, byte[] data)
        {
            using (HMACSHA256 h = new HMACSHA256(Derive(master, "PlugPass credential mac v2")))
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
