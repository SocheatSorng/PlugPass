using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace PlugPass
{
    // Windows sign-in with the drive (phase 4). Two halves, each useless alone:
    //
    // On the drive, <drive>\PlugPass\windows.key (64 bytes, no PIN by design):
    //   "PPWINKEY" (8) | version = 1 (1) | reserved = 0 (7) | enrolment ID (16) | K (32)
    //
    // On the PC, registry value <enrolment ID hex> (REG_BINARY) in the sign-in key, holding
    // DPAPI(LocalMachine, entropy "PlugPass windows v1") of:
    //   "PPWINBLB" (8) | version = 1 (1) | reserved = 0 (7) | enrolment ID (16) | IV (16)
    //   | AES-256-CBC(encKey, plaintext) | HMAC-SHA256(macKey, everything before) (32)
    //   plaintext: user name length in UTF-16 units (2, LE) | user name (UTF-16LE) | password length (2) | password (UTF-16LE)
    //   encKey = HMAC-SHA256(K, "PlugPass windows enc v1"), macKey = HMAC-SHA256(K, "PlugPass windows mac v1").
    // The sign-in tile writes "<id>.rejected" (REG_DWORD 1) there when Windows rejects the password
    // (changed password): no sign-in screen retries it until the drive is enrolled again.
    //
    // Sign-in key: HKLM\SOFTWARE\PlugPass\SignIn (64-bit view), owner Administrators, access SYSTEM +
    // Administrators only. In the registry, not %ProgramData%: standard users can't create keys under
    // HKLM\SOFTWARE (so they can't plant or own it) and there are no junctions to follow.
    // The C++ tile (credprov/) reads exactly this format: keep them in step.
    internal static class WindowsKey
    {
        internal const string DriveFileName = "windows.key";
        internal const byte FormatVersion = 1;
        internal const string SignInKey = @"SOFTWARE\PlugPass\SignIn";
        private const int DriveFileLength = 64;
        private static readonly byte[] DriveMagic = Encoding.ASCII.GetBytes("PPWINKEY");
        private static readonly byte[] BlobMagic = Encoding.ASCII.GetBytes("PPWINBLB");
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("PlugPass windows v1");

        internal static string DrivePath(string root)
        {
            return Path.Combine(Path.Combine(root, KeyFile.FolderName), DriveFileName);
        }

        internal static bool IsEnrolled(string root)
        {
            return File.Exists(DrivePath(root));
        }

        // True when the sign-in tile recorded that Windows rejected this drive's stored password.
        internal static bool IsRejected(string root)
        {
            byte[] d = ReadDriveFile(root);
            if (d == null)
            {
                return false;
            }
            using (RegistryKey k = OpenStore(false))
            {
                return k != null && k.GetValue(Program.Hex(Slice(d, 16, 16)) + ".rejected") != null;
            }
        }

        // Lost drive: deletes this PC's half of every enrolment, so no drive can sign in any more.
        internal static void RemoveAll()
        {
            using (RegistryKey k = OpenStore(true))
            {
                foreach (string name in k.GetValueNames())
                {
                    k.DeleteValue(name, false);
                }
            }
        }

        // Whether any drive still signs in on this PC (the sign-in tile is only needed then).
        internal static bool AnyEnrolments()
        {
            using (RegistryKey k = OpenStore(false))
            {
                if (k == null)
                {
                    return false;
                }
                foreach (string name in k.GetValueNames())
                {
                    if (name.Length == 32)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        // Stores the password for `user` so this drive can sign them in. Replaces this drive's earlier
        // enrolment. Requires admin rights (writes HKLM), except in the test build.
        internal static void Enrol(string root, string user, string password)
        {
            if (string.IsNullOrEmpty(user) || user.Length > 256 || password == null || password.Length > 256)
            {
                throw new ArgumentException("Invalid user name or password.");
            }
            RequireLinkFreeDrive(root);
            string folder = Path.Combine(root, KeyFile.FolderName);
            Directory.CreateDirectory(folder);
            byte[] old = ReadDriveFile(root);
            byte[] enrolId = KeyFile.Random(16);
            byte[] k = KeyFile.Random(32);

            byte[] userBytes = Encoding.Unicode.GetBytes(user);
            byte[] passBytes = Encoding.Unicode.GetBytes(password);
            byte[] plain = Bytes.Concat(Len16(user.Length), userBytes, Len16(password.Length), passBytes);
            byte[] iv = KeyFile.Random(16);
            byte[] ct;
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = Derive(k, "PlugPass windows enc v1");
                aes.IV = iv;
                using (ICryptoTransform enc = aes.CreateEncryptor())
                {
                    ct = enc.TransformFinalBlock(plain, 0, plain.Length);
                }
            }
            Array.Clear(plain, 0, plain.Length);
            Array.Clear(passBytes, 0, passBytes.Length);
            byte[] head = Bytes.Concat(BlobMagic, new byte[] { FormatVersion, 0, 0, 0, 0, 0, 0, 0 }, enrolId, iv, ct);
            byte[] blob;
            using (HMACSHA256 h = new HMACSHA256(Derive(k, "PlugPass windows mac v1")))
            {
                blob = Bytes.Concat(head, h.ComputeHash(head));
            }

            using (RegistryKey store = OpenStore(true))
            {
                store.SetValue(Program.Hex(enrolId), ProtectedData.Protect(blob, Entropy, DataProtectionScope.LocalMachine),
                    RegistryValueKind.Binary);
            }
            byte[] driveFile = Bytes.Concat(DriveMagic, new byte[] { FormatVersion, 0, 0, 0, 0, 0, 0, 0 }, enrolId, k);
            WriteAtomic(DrivePath(root), driveFile);
            Array.Clear(driveFile, 0, driveFile.Length);
            Array.Clear(k, 0, k.Length);
            if (old != null)
            {
                DeleteEnrolment(Slice(old, 16, 16)); // the drive's previous enrolment is no longer usable
            }
        }

        // Removes this drive's Windows sign-in: the PC half first, then the drive file.
        internal static void Remove(string root)
        {
            byte[] current = ReadDriveFile(root);
            if (current != null)
            {
                DeleteEnrolment(Slice(current, 16, 16));
            }
            string path = DrivePath(root);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

#if TESTHOOKS
        // Test build only: decrypts like the sign-in tile does and returns the user name (never the
        // password), or null when the two halves don't match.
        internal static string CheckUser(string root, out string password)
        {
            password = null;
            byte[] d = ReadDriveFile(root);
            if (d == null)
            {
                return null;
            }
            byte[] wrapped;
            using (RegistryKey store = OpenStore(false))
            {
                wrapped = store == null ? null : store.GetValue(Program.Hex(Slice(d, 16, 16))) as byte[];
            }
            if (wrapped == null)
            {
                return null;
            }
            byte[] blob = ProtectedData.Unprotect(wrapped, Entropy, DataProtectionScope.LocalMachine);
            byte[] k = Slice(d, 32, 32);
            int macAt = blob.Length - 32;
            using (HMACSHA256 h = new HMACSHA256(Derive(k, "PlugPass windows mac v1")))
            {
                if (!Bytes.FixedTimeEquals(Slice(blob, macAt, 32), h.ComputeHash(Slice(blob, 0, macAt))))
                {
                    return null;
                }
            }
            byte[] plain;
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = Derive(k, "PlugPass windows enc v1");
                aes.IV = Slice(blob, 32, 16);
                using (ICryptoTransform dec = aes.CreateDecryptor())
                {
                    plain = dec.TransformFinalBlock(blob, 48, macAt - 48);
                }
            }
            int userLen = BitConverter.ToUInt16(plain, 0);
            string user = Encoding.Unicode.GetString(plain, 2, userLen * 2);
            int passLen = BitConverter.ToUInt16(plain, 2 + userLen * 2);
            password = Encoding.Unicode.GetString(plain, 4 + userLen * 2, passLen * 2);
            return user;
        }
#endif

        // The sign-in key. write: create it if needed and (re)apply owner + access rules.
        // Test build: with PLUGPASS_TEST_REGKEY set, a throwaway key under HKCU\Software\PlugPassTest.
        private static RegistryKey OpenStore(bool write)
        {
#if TESTHOOKS
            string test = Environment.GetEnvironmentVariable("PLUGPASS_TEST_REGKEY");
            if (!string.IsNullOrEmpty(test))
            {
                string path = @"Software\PlugPassTest\" + test + @"\SignIn";
                return write ? Registry.CurrentUser.CreateSubKey(path) : Registry.CurrentUser.OpenSubKey(path);
            }
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PLUGPASS_HOME")))
            {
                throw new InvalidOperationException("Test build: set PLUGPASS_TEST_REGKEY for Windows sign-in.");
            }
#endif
            RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            if (!write)
            {
                return hklm.OpenSubKey(SignInKey);
            }
            RegistrySecurity sec = new RegistrySecurity();
            sec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            sec.SetAccessRuleProtection(true, false);
            sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            RegistryKey key = hklm.CreateSubKey(SignInKey, RegistryKeyPermissionCheck.ReadWriteSubTree, sec);
            key.SetAccessControl(sec); // an existing key gets the same owner and rules
            return key;
        }

        private static void DeleteEnrolment(byte[] enrolId)
        {
            using (RegistryKey store = OpenStore(true))
            {
                store.DeleteValue(Program.Hex(enrolId), false);
                store.DeleteValue(Program.Hex(enrolId) + ".rejected", false);
            }
        }

        // Windows sign-in only uses FAT32/exFAT drives: they can't hold links, so nothing on the drive
        // can redirect reads (by the SYSTEM-run tile) or writes (by this elevated app) elsewhere.
        private static void RequireLinkFreeDrive(string root)
        {
#if TESTHOOKS
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PLUGPASS_HOME")))
            {
                return; // tests use a folder on NTFS as the drive
            }
#endif
            string format = new DriveInfo(root).DriveFormat;
            if (!format.StartsWith("FAT", StringComparison.OrdinalIgnoreCase) && !format.Equals("exFAT", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Windows sign-in needs a drive formatted as FAT32 or exFAT (this one is " + format + ").");
            }
        }

        // Null when the drive has no (valid) Windows sign-in file.
        private static byte[] ReadDriveFile(string root)
        {
            string path = DrivePath(root);
            if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return null;
            }
            byte[] d = File.ReadAllBytes(path);
            if (d.Length != DriveFileLength || d[8] != FormatVersion)
            {
                return null;
            }
            for (int i = 0; i < DriveMagic.Length; i++)
            {
                if (d[i] != DriveMagic[i])
                {
                    return null;
                }
            }
            return d;
        }

        private static void WriteAtomic(string path, byte[] data)
        {
            string temp = path + ".tmp";
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
            using (FileStream fs = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                fs.Write(data, 0, data.Length);
                fs.Flush(true);
            }
            if (!MoveFileEx(temp, path, 0x1 | 0x8))
            {
                int err = Marshal.GetLastWin32Error();
                File.Delete(temp);
                throw new IOException("Couldn't save " + Path.GetFileName(path) + ".", new Win32Exception(err));
            }
        }

        // Checks a Windows password for a local account (used before enrolling).
        internal static bool PasswordIsCorrect(string user, string password)
        {
            IntPtr token;
            if (!LogonUser(user, ".", password, 2 /* interactive */, 0, out token))
            {
                return false;
            }
            CloseHandle(token);
            return true;
        }

        internal static bool IsElevated()
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static byte[] Derive(byte[] k, string label)
        {
            using (HMACSHA256 h = new HMACSHA256(k))
            {
                return h.ComputeHash(Encoding.UTF8.GetBytes(label));
            }
        }

        private static byte[] Len16(int n)
        {
            return new byte[] { (byte)n, (byte)(n >> 8) };
        }

        private static byte[] Slice(byte[] a, int offset, int count)
        {
            byte[] r = new byte[count];
            Buffer.BlockCopy(a, offset, r, 0, count);
            return r;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string existing, string replacement, int flags);
    }
}
