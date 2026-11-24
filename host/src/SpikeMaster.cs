using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PlugPass
{
    // PHASE 1 ONLY: the master secret lives in <DataDir>\spike-master.bin, DPAPI-protected for the
    // current Windows user, with no drive and no PIN. Phase 2 replaces this with a PIN-protected key
    // file on the USB drive. Never ship this.
    internal static class SpikeMaster
    {
        private const string FileName = "spike-master.bin";
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("PlugPass spike master v1");

        // The master secret, or null if none exists yet and create is false.
        internal static byte[] Load(bool create)
        {
            string path = Path.Combine(AppPaths.DataDir, FileName);
            if (File.Exists(path))
            {
                return ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.CurrentUser);
            }
            if (!create)
            {
                return null;
            }
            byte[] master = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(master);
            }
            Directory.CreateDirectory(AppPaths.DataDir);
            string temp = path + ".tmp";
            File.WriteAllBytes(temp, ProtectedData.Protect(master, Entropy, DataProtectionScope.CurrentUser));
            File.Move(temp, path);
            return master;
        }
    }
}
