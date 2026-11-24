using System;
using System.IO;

namespace PlugPass
{
    // PlugPass helper app.
    //   PlugPass version                      print the version
    //   PlugPass create-key <drive>           make a PlugPass key on a USB drive; stdin: PIN, PIN again
    //   PlugPass change-pin <drive>           stdin: current PIN, new PIN, new PIN again
    //   PlugPass key-info <drive>             key ID and PIN tries left (no PIN needed)
    //   PlugPass chrome-extension://<id>/ ... started by Chrome/Edge/Brave as the native messaging host
    // Test build only: unlock-check <dir>; --key-dir/--no-drive-scan; --auto-approve | --auto-fallback |
    // --auto-deny and PLUGPASS_TEST_PIN answer the PIN window without showing it.
    //
    // Exit codes: 0 ok, 2 usage, 3 wrong PIN, 4 key erased (too many wrong PINs), 5 set up on another PC,
    // 6 no key / unreadable, 7 refused (PIN rules, key already there, not a removable drive).
    internal static class Program
    {
        internal const string Version = "0.2.0";

        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 1 && (args[0] == "version" || args[0] == "--version"))
            {
                Console.WriteLine("PlugPass " + Version);
                return 0;
            }
            if (args.Length >= 1 && args[0].StartsWith("chrome-extension://", StringComparison.Ordinal))
            {
                return NativeHost.Run(ChoosePrompt(args), args);
            }
            if (args.Length == 2 && args[0] == "create-key")
            {
                return CreateKey(args[1]);
            }
            if (args.Length == 2 && args[0] == "change-pin")
            {
                return ChangePin(args[1]);
            }
            if (args.Length == 2 && args[0] == "key-info")
            {
                return KeyInfo(args[1]);
            }
#if TESTHOOKS
            if (args.Length == 2 && args[0] == "unlock-check")
            {
                return UnlockCheck(args[1]);
            }
#endif
            Console.Error.WriteLine("Usage: PlugPass version | create-key <drive> | change-pin <drive> | key-info <drive>");
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
