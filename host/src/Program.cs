using System;

namespace PlugPass
{
    // PlugPass helper app. Later: Chrome/Edge native messaging host (security key for Google),
    // drive setup, and the PIN prompt. See docs/spec.md.
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
            Console.Error.WriteLine("Usage: PlugPass version");
            return 2;
        }
    }
}
