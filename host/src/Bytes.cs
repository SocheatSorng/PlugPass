using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PlugPass
{
    // Small byte helpers: base64url (no padding), SHA-256, concatenation, constant-time compare.
    internal static class Bytes
    {
        internal static string ToB64Url(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        // Returns null for anything that isn't valid base64url.
        internal static byte[] FromB64Url(string s)
        {
            if (s == null)
            {
                return null;
            }
            foreach (char c in s)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
                if (!ok)
                {
                    return null;
                }
            }
            if (s.Length % 4 == 1)
            {
                return null;
            }
            string b64 = s.Replace('-', '+').Replace('_', '/');
            b64 += new string('=', (4 - b64.Length % 4) % 4);
            try
            {
                return Convert.FromBase64String(b64);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        internal static byte[] Sha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        internal static byte[] Utf8(string s)
        {
            return new UTF8Encoding(false).GetBytes(s);
        }

        internal static byte[] Concat(params byte[][] parts)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                foreach (byte[] p in parts)
                {
                    ms.Write(p, 0, p.Length);
                }
                return ms.ToArray();
            }
        }

        internal static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
