using System;

namespace PlugPass
{
    // PlugPass helper app.
    //   PlugPass version                      print the version
    //   PlugPass chrome-extension://<id>/ ... started by Chrome/Edge as the native messaging host
    // Test build only: --auto-approve | --auto-fallback | --auto-deny answer the consent step without a window.
    internal static class Program
    {
        internal const string Version = "0.1.0";

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
                return NativeHost.Run(ChooseConsent(args));
            }
            Console.Error.WriteLine("Usage: PlugPass version");
            return 2;
        }

        private static IConsent ChooseConsent(string[] args)
        {
#if TESTHOOKS
            foreach (string a in args)
            {
                if (a == "--auto-approve")
                {
                    return new ScriptedConsent(Decision.Allow);
                }
                if (a == "--auto-fallback")
                {
                    return new ScriptedConsent(Decision.Fallback);
                }
                if (a == "--auto-deny")
                {
                    return new ScriptedConsent(Decision.Cancel);
                }
            }
#endif
            return new DialogConsent();
        }
    }
}
