using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PlugPass
{
    // PBKDF2-HMAC-SHA256 via Windows CNG (native, several times faster than .NET Framework's managed
    // Rfc2898DeriveBytes), falling back to Rfc2898DeriveBytes. Both give the same output (RFC 8018).
    internal static class Pbkdf2
    {
        private const int BcryptAlgHandleHmacFlag = 0x00000008;

        internal static byte[] DeriveSha256(byte[] password, byte[] salt, int iterations, int length)
        {
            try
            {
                return DeriveNative(password, salt, iterations, length);
            }
            catch (Exception ex)
            {
                if (ex is OutOfMemoryException)
                {
                    throw;
                }
                return DeriveManaged(password, salt, iterations, length);
            }
        }

        internal static byte[] DeriveManaged(byte[] password, byte[] salt, int iterations, int length)
        {
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(length);
            }
        }

        internal static byte[] DeriveNative(byte[] password, byte[] salt, int iterations, int length)
        {
            IntPtr alg;
            int status = BCryptOpenAlgorithmProvider(out alg, "SHA256", null, BcryptAlgHandleHmacFlag);
            if (status != 0)
            {
                throw new CryptographicException("BCryptOpenAlgorithmProvider failed: 0x" + status.ToString("X8"));
            }
            try
            {
                byte[] key = new byte[length];
                status = BCryptDeriveKeyPBKDF2(alg, password, password.Length, salt, salt.Length, (ulong)iterations, key, key.Length, 0);
                if (status != 0)
                {
                    throw new CryptographicException("BCryptDeriveKeyPBKDF2 failed: 0x" + status.ToString("X8"));
                }
                return key;
            }
            finally
            {
                BCryptCloseAlgorithmProvider(alg, 0);
            }
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr handle, string algId, string implementation, int flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDeriveKeyPBKDF2(IntPtr prf, byte[] password, int cbPassword, byte[] salt, int cbSalt,
            ulong iterations, byte[] derivedKey, int cbDerivedKey, int flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr handle, int flags);
    }
}
