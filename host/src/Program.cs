using System;
using System.IO;

namespace PlugPass
{
    // PlugPass helper app.
    //   PlugPass [setup]                      setup window: make a USB drive your PlugPass key
    //   PlugPass version                      print the version
    //   PlugPass create-key <drive>           make a PlugPass key on a USB drive; stdin: PIN, PIN again
    //   PlugPass change-pin <drive>           stdin: current PIN, new PIN, new PIN again
    //   PlugPass key-info <drive>             key ID and PIN tries left (no PIN needed)
    //   PlugPass chrome-extension://<id>/ ... started by Chrome/Edge/Brave as the native messaging host
    // Test build only: unlock-check <dir>; --key-dir/--no-drive-scan; --auto-approve | --auto-fallback |
    // --auto-deny and PLUGPASS_TEST_PIN answer the PIN window without showing it.
    //
    // Exit codes: 0 ok, 2 usage, 3 wrong PIN, 4 key erased (too many wrong PINs), 5 set up on another PC,
    // 6 no key / unreadable / can't write, 7 refused (PIN rules, key already there, not a removable drive),
    // 8 locked (the drive says it already used up its tries; nothing is erased on its word).
    internal static class Program
    {
        internal const string Version = "0.3.0";
        internal const string ExtensionOrigin = "chrome-extension://amppkfbnjicgeeakigkmafdllhknaigl/";

        // Runs a key command while holding the key-file lock; a drive that can't be written is an error.
        private static int Locked(Func<int> command)
        {
            using (KeyLock held = KeyLock.Acquire(60 * 1000))
            {
                if (held == null)
                {
                    return Fail(6, "Another PlugPass window is still open.");
                }
                try
                {
                    return command();
                }
                catch (IOException ex)
                {
                    return Fail(6, "Couldn't write to the drive: " + ex.Message);
                }
                catch (UnauthorizedAccessException ex)
                {
                    return Fail(6, "Couldn't write to the drive: " + ex.Message);
                }
            }
        }

        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 0 || (args.Length == 1 && args[0] == "setup"))
            {
                return SetupForm.Run();
            }
            if (args.Length == 1 && (args[0] == "version" || args[0] == "--version"))
            {
                Console.WriteLine("PlugPass " + Version);
                return 0;
            }
            if (args.Length >= 1 && args[0].StartsWith("chrome-extension://", StringComparison.Ordinal))
            {
                // Browsers already enforce allowed_origins; this also stops other programs posing as one.
                if (args[0] != ExtensionOrigin)
                {
                    return Fail(2, "Unknown extension.");
                }
                return NativeHost.Run(ChoosePrompt(args), args);
            }
            if (args.Length == 2 && args[0] == "create-key")
            {
                return Locked(delegate { return CreateKey(args[1]); });
            }
            if (args.Length == 2 && args[0] == "change-pin")
            {
                return Locked(delegate { return ChangePin(args[1]); });
            }
            if (args.Length == 2 && args[0] == "key-info")
            {
                return KeyInfo(args[1]);
            }
            bool quiet = Array.IndexOf(args, "--quiet") >= 0;
            if (args.Length >= 1 && args.Length <= 2 && args[0] == "install" && (args.Length == 1 || quiet))
            {
                return InstallCommand(quiet);
            }
            if (args.Length >= 1 && args.Length <= 2 && args[0] == "uninstall" && (args.Length == 1 || quiet))
            {
                return UninstallCommand(quiet);
            }
#if TESTHOOKS
            if (args.Length == 2 && args[0] == "unlock-check")
            {
                return Locked(delegate { return UnlockCheck(args[1]); });
            }
#endif
            Console.Error.WriteLine("Usage: PlugPass [setup] | version | install [--quiet] | uninstall [--quiet] | "
                + "create-key <drive> | change-pin <drive> | key-info <drive>");
            return 2;
        }

        private static int CreateKey(string root)
        {
            if (!Drives.IsAllowedTarget(root))
            {
                return Fail(7, "Not a removable drive: " + root);
            }
            string pin = Console.In.ReadLine();
            string again = Console.In.ReadLine();
            string problem = KeyFile.CheckPin(pin);
            if (problem != null)
            {
                return Fail(7, problem);
            }
            if (pin != again)
            {
                return Fail(7, "The two PINs don't match.");
            }
            if (KeyFile.Exists(root))
            {
                return Fail(7, "This drive already has a PlugPass key.");
            }
            KeyFile kf = KeyFile.Create(root, pin);
            Console.WriteLine("Created PlugPass key " + Hex(kf.KeyId));
            return 0;
        }

        private static int ChangePin(string root)
        {
            KeyFile kf = KeyFile.Open(root);
            if (kf == null)
            {
                return Fail(6, "No readable PlugPass key on " + root);
            }
            string current = Console.In.ReadLine();
            string pin = Console.In.ReadLine();
            string again = Console.In.ReadLine();
            string problem = KeyFile.CheckPin(pin);
            if (problem != null)
            {
                return Fail(7, problem);
            }
            if (pin != again)
            {
                return Fail(7, "The two new PINs don't match.");
            }
            int code = UnlockCode(kf.Unlock(current), kf);
            if (code != 0)
            {
                return code;
            }
            kf.ChangePin(pin);
            Console.WriteLine("PIN changed.");
            return 0;
        }

        private static int InstallCommand(bool quiet)
        {
            try
            {
                Installer.Install();
            }
            catch (IOException ex)
            {
                return Fail(6, "Install failed: " + ex.Message);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Fail(6, "Install failed: " + ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return Fail(6, "Install failed: " + ex.Message);
            }
            Console.WriteLine("Installed " + Installer.InstalledExe);
            Console.WriteLine("Extension folder: " + Installer.ExtensionDir);
            if (!quiet)
            {
                System.Windows.Forms.MessageBox.Show(SetupForm.ExtensionSteps(), "PlugPass installed");
            }
            return 0;
        }

        // Settings > Apps runs this. Drive keys and this PC's halves of them are kept, so a reinstall
        // keeps every drive working.
        private static int UninstallCommand(bool quiet)
        {
            if (!quiet && System.Windows.Forms.MessageBox.Show(
                    "Remove PlugPass from this PC?\n\nYour USB drive and its keys are kept, so after a reinstall it works again. "
                    + "Also remove the PlugPass extension from your browser.",
                    "PlugPass", System.Windows.Forms.MessageBoxButtons.OKCancel) != System.Windows.Forms.DialogResult.OK)
            {
                return 0;
            }
            bool pending;
            try
            {
                pending = Installer.Uninstall();
            }
            catch (IOException ex)
            {
                return Fail(6, "Uninstall failed: " + ex.Message);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Fail(6, "Uninstall failed: " + ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return Fail(6, "Uninstall failed: " + ex.Message);
            }
            Console.WriteLine(pending ? "Uninstalled; PlugPass.exe is removed in a few seconds." : "Uninstalled.");
            if (!quiet)
            {
                System.Windows.Forms.MessageBox.Show("PlugPass was removed. Remove the PlugPass extension from your browser too.", "PlugPass");
            }
            return 0;
        }

        private static int KeyInfo(string root)
        {
            KeyFile kf = KeyFile.Open(root);
            if (kf == null)
            {
                return Fail(6, "No readable PlugPass key on " + root);
            }
            Console.WriteLine("key " + Hex(kf.KeyId) + " tries-left " + kf.TriesLeft
                + (PcSecrets.Load(kf.KeyId) == null ? " other-pc" : " this-pc"));
            return 0;
        }

#if TESTHOOKS
        private static int UnlockCheck(string root)
        {
            KeyFile kf = KeyFile.Open(root);
            if (kf == null)
            {
                return Fail(6, "No readable PlugPass key on " + root);
            }
            int code = UnlockCode(kf.Unlock(Console.In.ReadLine()), kf);
            if (code == 0)
            {
                Console.WriteLine("ok passkeys " + kf.Payload.Passkeys.Count + " counter " + kf.Payload.Counter);
            }
            return code;
        }
#endif

        private static int UnlockCode(UnlockResult r, KeyFile kf)
        {
            switch (r)
            {
                case UnlockResult.Ok:
                    return 0;
                case UnlockResult.WrongPin:
                    return Fail(3, "Wrong PIN. " + kf.TriesLeft + " tries left.");
                case UnlockResult.Wiped:
                    return Fail(4, "Too many wrong PINs: the PlugPass key on this drive was erased.");
                case UnlockResult.Locked:
                    return Fail(8, "This PlugPass drive is locked after too many wrong PINs.");
                case UnlockResult.OtherPc:
                    return Fail(5, "This drive was set up on another PC.");
                default:
                    return Fail(6, "The PlugPass key on this drive is damaged.");
            }
        }

        private static int Fail(int code, string message)
        {
            Console.Error.WriteLine(message);
            return code;
        }

        internal static string Hex(byte[] b)
        {
            return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
        }

        private static IPinPrompt ChoosePrompt(string[] args)
        {
#if TESTHOOKS
            foreach (string a in args)
            {
                if (a == "--auto-approve")
                {
                    return new ScriptedPrompt(Decision.Allow, args);
                }
                if (a == "--auto-fallback")
                {
                    return new ScriptedPrompt(Decision.Fallback, args);
                }
                if (a == "--auto-deny")
                {
                    return new ScriptedPrompt(Decision.Cancel, args);
                }
            }
#endif
            return new DialogPrompt();
        }
    }
}
