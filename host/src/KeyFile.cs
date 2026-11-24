using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace PlugPass
{
    internal enum UnlockResult
    {
        Ok,
        WrongPin,
        Wiped,      // too many wrong PINs: the key on this drive was erased
        OtherPc,    // the drive was set up on another PC (or this PC lost its half of the key)
        Damaged,
    }

    internal sealed class Passkey
    {
        internal string RpId;
        internal string CredId;      // base64url
        internal string UserHandle;  // base64url
        internal string UserName;
        internal string DisplayName;
        internal string Created;     // ISO 8601 UTC
    }

    // What the PIN unlocks: the master secret (wraps every site key), the signature counter and the
    // passkeys stored on the drive (discoverable credentials).
    internal sealed class KeyPayload
    {
        internal byte[] Master;
        internal uint Counter;
        internal List<Passkey> Passkeys = new List<Passkey>();
    }

    // The PlugPass key on a USB drive: <drive>\PlugPass\plugpass.ppkey.
    //
    // Format version 1 (all integers little-endian):
    //   0  "PLUGPASS" (8)        8  version = 1 (1)       9  wrong-PIN count (1)    10 reserved = 0 (2)
    //   12 PBKDF2 iterations (4) 16 key ID (16)          32 PIN salt (16)          48 IV (16)
    //   64 AES-256-CBC ciphertext of the JSON payload ... then HMAC-SHA256 (32) over the header (with
    //      the wrong-PIN count read as 0, so it can change without the PIN) and the ciphertext.
    //
    // Keys: pinKey = PBKDF2-SHA256(PIN, salt, iterations); k = HMAC-SHA256(pcSecret, pinKey);
    // encKey / macKey = HMAC-SHA256(k, label). pcSecret is 32 random bytes kept on this PC only
    // (DPAPI, current user), so the drive alone can't be unlocked or brute-forced elsewhere.
    internal sealed class KeyFile
    {
        internal const string FolderName = "PlugPass";
        internal const string FileName = "plugpass.ppkey";
        internal const byte FormatVersion = 1;
        internal const int MaxWrongPins = 8;
        internal const int MinPinLength = 6;
        internal const int MaxPinLength = 64;
        internal const int Iterations = 600000;
        internal const int KeyIdLength = 16;
        private const int HeaderLength = 64;
        private const int MacLength = 32;
        private const int WrongPinOffset = 9;
        private const int MaxFileBytes = 1024 * 1024;
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("PLUGPASS");

        private readonly string _root;
        private byte[] _header;
        private byte[] _body; // ciphertext + MAC
        private byte[] _encKey;
        private byte[] _macKey;

        private KeyFile(string root)
        {
            _root = root;
        }

        internal byte[] KeyId
        {
            get { return Slice(_header, 16, KeyIdLength); }
        }

        internal int WrongPins
        {
            get { return _header[WrongPinOffset]; }
        }

        internal int TriesLeft
        {
            get { return MaxWrongPins - WrongPins; }
        }

        // Set after a successful Unlock (or Create).
        internal KeyPayload Payload { get; private set; }

        internal static string PathFor(string root)
        {
            return Path.Combine(Path.Combine(root, FolderName), FileName);
        }

        internal static bool Exists(string root)
        {
            return File.Exists(PathFor(root));
        }

        // Null when the PIN is acceptable; otherwise what's wrong with it, in plain words.
        internal static string CheckPin(string pin)
        {
            if (pin == null || pin.Length < MinPinLength)
            {
                return "The PIN must have at least " + MinPinLength + " characters.";
            }
            if (pin.Length > MaxPinLength)
            {
                return "The PIN can have at most " + MaxPinLength + " characters.";
            }
            foreach (char c in pin)
            {
                if (char.IsControl(c))
                {
                    return "The PIN can't contain control characters.";
                }
            }
            return null;
        }

        // Makes a new key on the drive. Refuses to overwrite an existing one.
        internal static KeyFile Create(string root, string pin)
        {
            string problem = CheckPin(pin);
            if (problem != null)
            {
                throw new ArgumentException(problem);
            }
            if (Exists(root))
            {
                throw new IOException("This drive already has a PlugPass key.");
            }
            KeyFile kf = new KeyFile(root);
            kf._header = new byte[HeaderLength];
            Buffer.BlockCopy(Magic, 0, kf._header, 0, Magic.Length);
            kf._header[8] = FormatVersion;
            Buffer.BlockCopy(BitConverter.GetBytes(Iterations), 0, kf._header, 12, 4);
            Buffer.BlockCopy(Random(KeyIdLength), 0, kf._header, 16, KeyIdLength);
            PcSecrets.Save(kf.KeyId, Random(32));
            KeyPayload p = new KeyPayload();
            p.Master = Random(32);
            kf.Payload = p;
            kf.SetPin(pin);
            Directory.CreateDirectory(Path.Combine(root, FolderName));
            kf.Save();
            return kf;
        }

        // Reads the header only (no PIN needed). Null when there's no key or it isn't readable.
        internal static KeyFile Open(string root)
        {
            string path = PathFor(root);
            try
            {
                FileInfo fi = new FileInfo(path);
                if (!fi.Exists || fi.Length > MaxFileBytes || (fi.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return null;
                }
                byte[] all = File.ReadAllBytes(path);
                if (all.Length < HeaderLength + 16 + MacLength || !StartsWithMagic(all) || all[8] != FormatVersion
                    || BitConverter.ToInt32(all, 12) < Iterations || (all.Length - HeaderLength - MacLength) % 16 != 0)
                {
                    return null;
                }
                KeyFile kf = new KeyFile(root);
                kf._header = Slice(all, 0, HeaderLength);
                kf._body = Slice(all, HeaderLength, all.Length - HeaderLength);
                return kf;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }

        internal UnlockResult Unlock(string pin)
        {
            byte[] pcSecret = PcSecrets.Load(KeyId);
            if (pcSecret == null)
            {
                return UnlockResult.OtherPc;
            }
            if (WrongPins >= MaxWrongPins)
            {
                Wipe();
                return UnlockResult.Wiped;
            }
            DeriveKeys(pin ?? "", pcSecret);
            byte[] ct = Slice(_body, 0, _body.Length - MacLength);
            byte[] mac = Slice(_body, _body.Length - MacLength, MacLength);
            if (!Bytes.FixedTimeEquals(mac, ComputeMac(ct)))
            {
                _header[WrongPinOffset] = (byte)(WrongPins + 1);
                if (WrongPins >= MaxWrongPins)
                {
                    Wipe();
                    return UnlockResult.Wiped;
                }
                WriteFile();
                return UnlockResult.WrongPin;
            }
            KeyPayload p = Decrypt(ct);
            if (p == null)
            {
                return UnlockResult.Damaged;
            }
            Payload = p;
            if (WrongPins != 0)
            {
                _header[WrongPinOffset] = 0;
                WriteFile();
            }
            return UnlockResult.Ok;
        }

        // Re-encrypts under a new PIN (new salt). Requires a successful Unlock first.
        internal void ChangePin(string newPin)
        {
            string problem = CheckPin(newPin);
            if (problem != null)
            {
                throw new ArgumentException(problem);
            }
            RequireUnlocked();
            SetPin(newPin);
            Save();
        }

        // Encrypts the payload and writes the file. Requires a successful Unlock (or Create).
        internal void Save()
        {
            RequireUnlocked();
            byte[] iv = Random(16);
            Buffer.BlockCopy(iv, 0, _header, 48, 16);
            byte[] plain = Bytes.Utf8(Json.Write(ToJson(Payload)));
            byte[] ct;
            using (Aes aes = NewAes(iv))
            using (ICryptoTransform enc = aes.CreateEncryptor())
            {
                ct = enc.TransformFinalBlock(plain, 0, plain.Length);
            }
            Array.Clear(plain, 0, plain.Length);
            _body = Bytes.Concat(ct, ComputeMac(ct));
            WriteFile();
        }

        // Crypto-erase: without this PC's secret the drive file can never be opened again; then the
        // file itself is removed. Only these two exact paths are deleted.
        private void Wipe()
        {
            PcSecrets.Delete(KeyId);
            string path = PathFor(_root);
            try
            {
                if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0)
                {
                    File.WriteAllBytes(path, new byte[new FileInfo(path).Length]);
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
                // The PC secret is already gone, so the file is unreadable anyway.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private void SetPin(string pin)
        {
            Buffer.BlockCopy(Random(16), 0, _header, 32, 16);
            byte[] pcSecret = PcSecrets.Load(KeyId);
            if (pcSecret == null)
            {
                throw new InvalidOperationException("This PC's half of the key is missing.");
            }
            DeriveKeys(pin, pcSecret);
        }

        private void DeriveKeys(string pin, byte[] pcSecret)
        {
            byte[] pinBytes = Bytes.Utf8(pin.Normalize(NormalizationForm.FormC));
            byte[] pinKey = Pbkdf2.DeriveSha256(pinBytes, Slice(_header, 32, 16), BitConverter.ToInt32(_header, 12), 32);
            Array.Clear(pinBytes, 0, pinBytes.Length);
            using (HMACSHA256 h = new HMACSHA256(pcSecret))
            {
                byte[] k = h.ComputeHash(pinKey);
                using (HMACSHA256 hk = new HMACSHA256(k))
                {
                    _encKey = hk.ComputeHash(Bytes.Utf8("PlugPass key file enc v1"));
                    _macKey = hk.ComputeHash(Bytes.Utf8("PlugPass key file mac v1"));
                }
                Array.Clear(k, 0, k.Length);
            }
            Array.Clear(pinKey, 0, pinKey.Length);
            Array.Clear(pcSecret, 0, pcSecret.Length);
        }

        private byte[] ComputeMac(byte[] ct)
        {
            byte[] header = (byte[])_header.Clone();
            header[WrongPinOffset] = 0;
            using (HMACSHA256 h = new HMACSHA256(_macKey))
            {
                return h.ComputeHash(Bytes.Concat(header, ct));
            }
        }

        private KeyPayload Decrypt(byte[] ct)
        {
            try
            {
                byte[] plain;
                using (Aes aes = NewAes(Slice(_header, 48, 16)))
                using (ICryptoTransform dec = aes.CreateDecryptor())
                {
                    plain = dec.TransformFinalBlock(ct, 0, ct.Length);
                }
                Dictionary<string, object> d = Json.Parse(new UTF8Encoding(false, true).GetString(plain));
                Array.Clear(plain, 0, plain.Length);
                return d == null ? null : FromJson(d);
            }
            catch (CryptographicException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        private Aes NewAes(byte[] iv)
        {
            Aes aes = new AesCryptoServiceProvider();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _encKey;
            aes.IV = iv;
            return aes;
        }

        // Writes to a temp file next to the key, flushes it to the drive, then swaps it in, so a drive
        // pulled out mid-write keeps the previous complete file.
        private void WriteFile()
        {
            string path = PathFor(_root);
            string temp = path + ".tmp";
            byte[] all = Bytes.Concat(_header, _body);
            using (FileStream fs = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                fs.Write(all, 0, all.Length);
                fs.Flush(true);
            }
            if (!MoveFileEx(temp, path, MoveFileReplaceExisting | MoveFileWriteThrough))
            {
                int err = Marshal.GetLastWin32Error();
                try
                {
                    File.Delete(temp);
                }
                catch (IOException)
                {
                }
                throw new IOException("Couldn't save the PlugPass key.", new Win32Exception(err));
            }
        }

        private void RequireUnlocked()
        {
            if (Payload == null)
            {
                throw new InvalidOperationException("The key is locked.");
            }
        }

        private static Dictionary<string, object> ToJson(KeyPayload p)
        {
            List<object> list = new List<object>();
            foreach (Passkey k in p.Passkeys)
            {
                Dictionary<string, object> e = new Dictionary<string, object>();
                e["rpId"] = k.RpId;
                e["credId"] = k.CredId;
                e["userHandle"] = k.UserHandle;
                e["userName"] = k.UserName;
                e["displayName"] = k.DisplayName;
                e["created"] = k.Created;
                list.Add(e);
            }
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["master"] = Bytes.ToB64Url(p.Master);
            d["counter"] = (long)p.Counter;
            d["passkeys"] = list;
            return d;
        }

        private static KeyPayload FromJson(Dictionary<string, object> d)
        {
            KeyPayload p = new KeyPayload();
            p.Master = Bytes.FromB64Url(Json.Str(d, "master"));
            object counter;
            if (p.Master == null || p.Master.Length != 32 || !d.TryGetValue("counter", out counter))
            {
                return null;
            }
            p.Counter = (uint)Convert.ToInt64(counter);
            object[] list = Json.Arr(d, "passkeys") ?? new object[0];
            foreach (object o in list)
            {
                Dictionary<string, object> e = o as Dictionary<string, object>;
                if (e == null)
                {
                    continue;
                }
                Passkey k = new Passkey();
                k.RpId = Json.Str(e, "rpId");
                k.CredId = Json.Str(e, "credId");
                k.UserHandle = Json.Str(e, "userHandle");
                k.UserName = Json.Str(e, "userName") ?? "";
                k.DisplayName = Json.Str(e, "displayName") ?? "";
                k.Created = Json.Str(e, "created") ?? "";
                if (k.RpId != null && k.CredId != null && k.UserHandle != null)
                {
                    p.Passkeys.Add(k);
                }
            }
            return p;
        }

        private static bool StartsWithMagic(byte[] all)
        {
            for (int i = 0; i < Magic.Length; i++)
            {
                if (all[i] != Magic[i])
                {
                    return false;
                }
            }
            return true;
        }

        internal static byte[] Random(int n)
        {
            byte[] b = new byte[n];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(b);
            }
            return b;
        }

        private static byte[] Slice(byte[] a, int offset, int count)
        {
            byte[] r = new byte[count];
            Buffer.BlockCopy(a, offset, r, 0, count);
            return r;
        }

        private const int MoveFileReplaceExisting = 0x1;
        private const int MoveFileWriteThrough = 0x8;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string existing, string replacement, int flags);
    }

    // This PC's half of each drive key: <DataDir>\keys\<key ID>.pcsecret, DPAPI (current user).
    internal static class PcSecrets
    {
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("PlugPass PC secret v1");

        private static string PathFor(byte[] keyId)
        {
            return Path.Combine(Path.Combine(AppPaths.DataDir, "keys"), BitConverter.ToString(keyId).Replace("-", "").ToLowerInvariant() + ".pcsecret");
        }

        internal static void Save(byte[] keyId, byte[] secret)
        {
            string path = PathFor(keyId);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string temp = path + ".tmp";
            File.WriteAllBytes(temp, ProtectedData.Protect(secret, Entropy, DataProtectionScope.CurrentUser));
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            File.Move(temp, path);
            Array.Clear(secret, 0, secret.Length);
        }

        // Null when this PC doesn't have it (drive set up elsewhere) or it can't be decrypted.
        internal static byte[] Load(byte[] keyId)
        {
            string path = PathFor(keyId);
            try
            {
                return File.Exists(path)
                    ? ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.CurrentUser)
                    : null;
            }
            catch (CryptographicException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }

        internal static void Delete(byte[] keyId)
        {
            string path = PathFor(keyId);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
