using System;
using System.IO;

namespace PlugPass
{
    internal static class AppPaths
    {
        // %LOCALAPPDATA%\PlugPass. The test build also honours PLUGPASS_HOME so tests never touch real data.
        internal static string DataDir
        {
            get
            {
#if TESTHOOKS
                string home = Environment.GetEnvironmentVariable("PLUGPASS_HOME");
                if (!string.IsNullOrEmpty(home))
                {
                    return home;
                }
#endif
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PlugPass");
            }
        }
    }
}
