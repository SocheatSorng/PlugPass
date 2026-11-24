using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.Win32;

namespace PlugPass
{
    // Per-user install, no administrator rights:
    //   %LOCALAPPDATA%\Programs\PlugPass\PlugPass.exe, extension\, com.plugpass.host.json
    //   HKCU native messaging registration for Chrome, Edge and Brave
    //   HKCU uninstall entry (Settings > Apps) and a Start menu shortcut
    // Uninstalling never touches %LOCALAPPDATA%\PlugPass (this PC's halves of drive keys), so a
    // reinstall keeps every drive working.
    // Test build only: with PLUGPASS_HOME set, everything goes under it and "registry" writes go to
    // PLUGPASS_HOME\registry.json, so tests never change the real registry or Start menu.
    internal static class Installer
    {
        internal const string HostName = "com.plugpass.host";
        internal const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\PlugPass";
        internal static readonly string[] BrowserKeys =
        {
            @"Software\Google\Chrome\NativeMessagingHosts\" + HostName,
            @"Software\Microsoft\Edge\NativeMessagingHosts\" + HostName,
            @"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\" + HostName,
        };

        internal static string InstallDir
        {
            get
            {
#if TESTHOOKS
                string home = Environment.GetEnvironmentVariable("PLUGPASS_HOME");
                if (!string.IsNullOrEmpty(home))
                {
                    return Path.Combine(Path.Combine(home, "Programs"), "PlugPass");
                }
#endif
                return Path.Combine(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"), "PlugPass");
            }
        }

        internal static string InstalledExe
        {
            get { return Path.Combine(InstallDir, "PlugPass.exe"); }
        }

        internal static string ExtensionDir
        {
            get { return Path.Combine(InstallDir, "extension"); }
        }

        internal static string ShortcutPath
        {
            get
            {
                string dir = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
#if TESTHOOKS
                string home = Environment.GetEnvironmentVariable("PLUGPASS_HOME");
                if (!string.IsNullOrEmpty(home))
                {
                    dir = Path.Combine(home, "StartMenu");
                }
#endif
                return Path.Combine(dir, "PlugPass.lnk");
            }
        }

        internal static bool IsInstalled
        {
            get { return File.Exists(InstalledExe); }
        }

        internal static string CurrentExe
        {
            get { return Assembly.GetExecutingAssembly().Location; }
        }

        internal static bool RunningInstalledCopy
        {
            get { return SamePath(CurrentExe, InstalledExe); }
        }

        // Installs (or updates) from the folder the running exe is in, which must also hold extension\.
        internal static void Install()
        {
            IRegistryStore reg = RegistryStore.Open(); // first: the test build refuses before touching anything
            string source = CurrentExe;
            string sourceExtension = FindExtension(Path.GetDirectoryName(source));
            if (sourceExtension == null)
            {
                throw new IOException("The extension folder wasn't found next to PlugPass.exe.");
            }
            Directory.CreateDirectory(InstallDir);
            RefuseLink(InstallDir);

            if (!SamePath(source, InstalledExe))
            {
                MoveAsideIfInUse(InstalledExe);
                File.Copy(source, InstalledExe, true);
            }
            if (!SamePath(sourceExtension, ExtensionDir))
            {
                DeleteTree(ExtensionDir);
                CopyTree(sourceExtension, ExtensionDir);
            }

            string manifestPath = Path.Combine(InstallDir, HostName + ".json");
            Dictionary<string, object> manifest = new Dictionary<string, object>();
            manifest["name"] = HostName;
            manifest["description"] = "PlugPass helper app";
            manifest["path"] = InstalledExe;
            manifest["type"] = "stdio";
            manifest["allowed_origins"] = new[] { Program.ExtensionOrigin };
            File.WriteAllText(manifestPath, Json.Write(manifest), new System.Text.UTF8Encoding(false));

            foreach (string key in BrowserKeys)
            {
                reg.SetDefault(key, manifestPath);
            }
            Dictionary<string, object> entry = new Dictionary<string, object>();
            entry["DisplayName"] = "PlugPass";
            entry["DisplayVersion"] = Program.Version;
            entry["Publisher"] = "PlugPass";
            entry["DisplayIcon"] = InstalledExe;
            entry["InstallLocation"] = InstallDir;
            entry["UninstallString"] = "\"" + InstalledExe + "\" uninstall";
            entry["QuietUninstallString"] = "\"" + InstalledExe + "\" uninstall --quiet";
            entry["NoModify"] = 1;
            entry["NoRepair"] = 1;
            reg.SetValues(UninstallKey, entry);

            CreateShortcut(ShortcutPath, InstalledExe);
        }

        // Removes what Install added. Returns true when the running exe is the installed copy and will
        // be deleted a few seconds after this process exits.
        internal static bool Uninstall()
        {
            IRegistryStore reg = RegistryStore.Open();
            foreach (string key in BrowserKeys)
            {
                reg.DeleteKey(key);
            }
            reg.DeleteKey(UninstallKey);
            if (File.Exists(ShortcutPath))
            {
                File.Delete(ShortcutPath);
            }
            if (!Directory.Exists(InstallDir))
            {
                return false;
            }
            RefuseLink(InstallDir);
            DeleteTree(ExtensionDir);
            DeleteIfExists(Path.Combine(InstallDir, HostName + ".json"));
            foreach (string old in Directory.GetFiles(InstallDir, "PlugPass.old-*.exe"))
            {
                TryDelete(old);
            }
            if (RunningInstalledCopy)
            {
                ScheduleSelfDelete(InstalledExe, InstallDir);
                return true;
            }
            DeleteIfExists(InstalledExe);
            if (Directory.GetFileSystemEntries(InstallDir).Length == 0)
            {
                Directory.Delete(InstallDir);
            }
            return false;
        }

        private static string FindExtension(string exeDir)
        {
            string here = Path.Combine(exeDir, "extension");
            if (File.Exists(Path.Combine(here, "manifest.json")))
            {
                return here;
            }
            string parent = Path.Combine(Path.GetDirectoryName(exeDir) ?? exeDir, "extension"); // bin\test -> bin\extension
            return File.Exists(Path.Combine(parent, "manifest.json")) ? parent : null;
        }

        // A running helper (started by the browser) keeps its exe locked; Windows allows renaming it,
        // so move it aside and let the next install or uninstall clean it up.
        private static void MoveAsideIfInUse(string exe)
        {
            foreach (string old in Directory.GetFiles(Path.GetDirectoryName(exe), "PlugPass.old-*.exe"))
            {
                TryDelete(old);
            }
            if (!File.Exists(exe))
            {
                return;
            }
            try
            {
                using (new FileStream(exe, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                }
            }
            catch (IOException)
            {
                File.Move(exe, Path.Combine(Path.GetDirectoryName(exe), "PlugPass.old-" + DateTime.Now.ToString("yyyyMMddHHmmss") + ".exe"));
            }
        }

        private static void CopyTree(string from, string to)
        {
            Directory.CreateDirectory(to);
            foreach (string f in Directory.GetFiles(from))
            {
                File.Copy(f, Path.Combine(to, Path.GetFileName(f)), true);
            }
            foreach (string d in Directory.GetDirectories(from))
            {
                if (!IsLink(d))
                {
                    CopyTree(d, Path.Combine(to, Path.GetFileName(d)));
                }
            }
        }

        // Deletes a folder PlugPass created; a link inside is removed itself, never followed.
        private static void DeleteTree(string dir)
        {
            if (!Directory.Exists(dir))
            {
                return;
            }
            if (IsLink(dir))
            {
                Directory.Delete(dir, false);
                return;
            }
            foreach (string f in Directory.GetFiles(dir))
            {
                File.SetAttributes(f, FileAttributes.Normal);
                File.Delete(f);
            }
            foreach (string d in Directory.GetDirectories(dir))
            {
                DeleteTree(d);
            }
            Directory.Delete(dir, false);
        }

        private static void RefuseLink(string dir)
        {
            if (IsLink(dir))
            {
                throw new IOException("The PlugPass program folder is a link; refusing to change it.");
            }
        }

        private static bool IsLink(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }

        private static void DeleteIfExists(string file)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }

        private static void TryDelete(string file)
        {
            try
            {
                File.Delete(file);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static void ScheduleSelfDelete(string exe, string dir)
        {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe",
                "/c ping -n 4 127.0.0.1 >nul & del /f /q \"" + exe + "\" & rmdir \"" + dir + "\"");
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            Process.Start(psi);
        }

        private static void CreateShortcut(string lnk, string target)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(lnk));
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(shellType);
            object link = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnk });
            Type t = link.GetType();
            t.InvokeMember("TargetPath", BindingFlags.SetProperty, null, link, new object[] { target });
            t.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, link, new object[] { Path.GetDirectoryName(target) });
            t.InvokeMember("Description", BindingFlags.SetProperty, null, link, new object[] { "Set up a USB drive as your PlugPass key" });
            t.InvokeMember("Save", BindingFlags.InvokeMethod, null, link, null);
        }

        internal static bool SamePath(string a, string b)
        {
            return string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }
    }

    internal interface IRegistryStore
    {
        void SetDefault(string subKey, string value);

        void SetValues(string subKey, Dictionary<string, object> values);

        void DeleteKey(string subKey);
    }

    internal static class RegistryStore
    {
        internal static IRegistryStore Open()
        {
#if TESTHOOKS
            string home = Environment.GetEnvironmentVariable("PLUGPASS_HOME");
            if (!string.IsNullOrEmpty(home))
            {
                return new FileRegistry(Path.Combine(home, "registry.json"));
            }
            throw new InvalidOperationException("The test build only installs with PLUGPASS_HOME set.");
#else
            return new CurrentUserRegistry();
#endif
        }
    }

    internal sealed class CurrentUserRegistry : IRegistryStore
    {
        public void SetDefault(string subKey, string value)
        {
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey(subKey))
            {
                k.SetValue("", value, RegistryValueKind.String);
            }
        }

        public void SetValues(string subKey, Dictionary<string, object> values)
        {
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey(subKey))
            {
                foreach (KeyValuePair<string, object> v in values)
                {
                    k.SetValue(v.Key, v.Value, v.Value is int ? RegistryValueKind.DWord : RegistryValueKind.String);
                }
            }
        }

        public void DeleteKey(string subKey)
        {
            Registry.CurrentUser.DeleteSubKeyTree(subKey, false);
        }
    }

#if TESTHOOKS
    // Test build: a JSON file stands in for HKCU. { "<subkey>": { "<value name>": value } }
    internal sealed class FileRegistry : IRegistryStore
    {
        private readonly string _path;

        internal FileRegistry(string path)
        {
            _path = path;
        }

        public void SetDefault(string subKey, string value)
        {
            Dictionary<string, object> values = new Dictionary<string, object>();
            values[""] = value;
            SetValues(subKey, values);
        }

        public void SetValues(string subKey, Dictionary<string, object> values)
        {
            Dictionary<string, object> all = Load();
            Dictionary<string, object> key = all.ContainsKey(subKey) ? (Dictionary<string, object>)all[subKey] : new Dictionary<string, object>();
            foreach (KeyValuePair<string, object> v in values)
            {
                key[v.Key] = v.Value;
            }
            all[subKey] = key;
            File.WriteAllText(_path, Json.Write(all));
        }

        public void DeleteKey(string subKey)
        {
            Dictionary<string, object> all = Load();
            all.Remove(subKey);
            File.WriteAllText(_path, Json.Write(all));
        }

        private Dictionary<string, object> Load()
        {
            return File.Exists(_path) ? (Json.Parse(File.ReadAllText(_path)) ?? new Dictionary<string, object>()) : new Dictionary<string, object>();
        }
    }
#endif
}
