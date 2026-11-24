using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

namespace PlugPass
{
    // JSON via the .NET Framework's JavaScriptSerializer: objects become Dictionary<string, object>,
    // arrays object[]. These helpers return null/false for anything of the wrong shape.
    internal static class Json
    {
        internal static Dictionary<string, object> Parse(string json)
        {
            return new JavaScriptSerializer().DeserializeObject(json) as Dictionary<string, object>;
        }

        internal static string Write(object value)
        {
            return new JavaScriptSerializer().Serialize(value);
        }

        internal static Dictionary<string, object> Map(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) ? v as Dictionary<string, object> : null;
        }

        internal static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) ? v as string : null;
        }

        internal static object[] Arr(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) ? v as object[] : null;
        }

        internal static bool Bool(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v is bool && (bool)v;
        }

        internal static string Escape(string s)
        {
            StringBuilder sb = new StringBuilder(s.Length + 8);
            foreach (char c in s)
            {
                if (c == '"' || c == '\\')
                {
                    sb.Append('\\').Append(c);
                }
                else if (c < 0x20)
                {
                    sb.Append("\\u").Append(((int)c).ToString("x4"));
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
    }
}
