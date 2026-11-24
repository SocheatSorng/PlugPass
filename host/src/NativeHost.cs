using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PlugPass
{
    // Chrome/Edge native messaging: each message is a 32-bit little-endian length followed by UTF-8
    // JSON, on stdin and stdout. Chrome starts this exe with the calling extension's origin as the
    // first argument; the host manifest's allowed_origins limits which extension may start it.
    internal static class NativeHost
    {
        internal const int MaxRequestBytes = 64 * 1024;

        internal static int Run(IPinPrompt prompt, string[] args)
        {
            Stream input = Console.OpenStandardInput();
            Stream output = Console.OpenStandardOutput();
            while (true)
            {
                byte[] lengthBytes = ReadExact(input, 4);
                if (lengthBytes == null)
                {
                    return 0; // browser closed the pipe
                }
                int length = BitConverter.ToInt32(lengthBytes, 0);
                if (length <= 0 || length > MaxRequestBytes)
                {
                    Send(output, Authenticator.Error("NotSupportedError", "Request too large.", true));
                    return 1;
                }
                byte[] body = ReadExact(input, length);
                if (body == null)
                {
                    return 1;
                }
                Send(output, HandleOne(body, prompt, args));
            }
        }

        private static Dictionary<string, object> HandleOne(byte[] body, IPinPrompt prompt, string[] args)
        {
            Dictionary<string, object> req;
            try
            {
                req = Json.Parse(new UTF8Encoding(false, true).GetString(body));
            }
            catch (Exception)
            {
                req = null;
            }
            if (req == null)
            {
                return Authenticator.Error("NotSupportedError", "Unreadable request.", true);
            }
            try
            {
                return Authenticator.Handle(req, prompt, delegate { return Drives.FindKeyRoot(args); });
            }
            catch (Exception ex)
            {
                // Type name only: messages could in theory carry data we don't want in the page.
                return Authenticator.Error("UnknownError", "PlugPass failed (" + ex.GetType().Name + ").", true);
            }
        }

        private static void Send(Stream output, Dictionary<string, object> reply)
        {
            byte[] json = new UTF8Encoding(false).GetBytes(Json.Write(reply));
            output.Write(BitConverter.GetBytes(json.Length), 0, 4);
            output.Write(json, 0, json.Length);
            output.Flush();
        }

        private static byte[] ReadExact(Stream s, int count)
        {
            byte[] buf = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = s.Read(buf, read, count - read);
                if (n <= 0)
                {
                    return null;
                }
                read += n;
            }
            return buf;
        }
    }
}
