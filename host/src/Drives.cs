using System;
using System.Collections.Generic;
using System.IO;

namespace PlugPass
{
    // Finds the PlugPass USB drive: the first removable drive with PlugPass\plugpass.ppkey.
    // Test build only: --key-dir <folder> stands in for a drive, --no-drive-scan ignores real drives.
    internal static class Drives
    {
        internal static List<string> RemovableRoots()
        {
            List<string> roots = new List<string>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType == DriveType.Removable && d.IsReady)
                    {
                        roots.Add(d.RootDirectory.FullName);
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
            return roots;
        }

        internal static bool IsRemovableRoot(string path)
        {
            string full;
            try
            {
                full = Path.GetFullPath(path).TrimEnd('\\') + "\\";
            }
            catch (ArgumentException)
            {
                return false;
            }
            foreach (string root in RemovableRoots())
            {
                if (string.Equals(root, full, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        // The drive root holding a PlugPass key, or null.
        internal static string FindKeyRoot(string[] args)
        {
#if TESTHOOKS
            string keyDir = Option(args, "--key-dir");
            if (keyDir != null)
            {
                return KeyFile.Exists(keyDir) ? keyDir : null;
            }
            if (Array.IndexOf(args, "--no-drive-scan") >= 0)
            {
                return null;
            }
#endif
            // Prefer a drive whose key this PC knows, so a second (or planted) drive can't take its place.
            string fallback = null;
            foreach (string root in RemovableRoots())
            {
                KeyFile kf = KeyFile.Open(root);
                if (kf == null)
                {
                    continue;
                }
                byte[] secret = PcSecrets.Load(kf.KeyId);
                if (secret != null)
                {
                    Array.Clear(secret, 0, secret.Length);
                    return root;
                }
                if (fallback == null)
                {
                    fallback = root;
                }
            }
            return fallback;
        }

        // A drive root given on the command line: the real build accepts only removable drives.
        internal static bool IsAllowedTarget(string path)
        {
#if TESTHOOKS
            return Directory.Exists(path);
#else
            return IsRemovableRoot(path);
#endif
        }

        internal static string Option(string[] args, string name)
        {
            int i = Array.IndexOf(args, name);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
    }
}
