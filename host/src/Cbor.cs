using System;
using System.IO;
using System.Text;

namespace PlugPass
{
    // Minimal CBOR encoder (RFC 8949) for WebAuthn: unsigned/negative integers, byte strings, text
    // strings and map headers. Callers write map keys in CTAP2 canonical order themselves.
    internal sealed class CborWriter
    {
        private readonly MemoryStream _ms = new MemoryStream();

        internal CborWriter Map(int count)
        {
            Head(5, (ulong)count);
            return this;
        }

        internal CborWriter Int(long value)
        {
            if (value >= 0)
            {
                Head(0, (ulong)value);
            }
            else
            {
                Head(1, (ulong)(-1 - value));
            }
            return this;
        }

        internal CborWriter Bytes(byte[] data)
        {
            Head(2, (ulong)data.Length);
            _ms.Write(data, 0, data.Length);
            return this;
        }

        internal CborWriter Text(string s)
        {
            byte[] data = new UTF8Encoding(false).GetBytes(s);
            Head(3, (ulong)data.Length);
            _ms.Write(data, 0, data.Length);
            return this;
        }

        internal byte[] ToArray()
        {
            return _ms.ToArray();
        }

        private void Head(int major, ulong value)
        {
            int mt = major << 5;
            if (value < 24)
            {
                _ms.WriteByte((byte)(mt | (int)value));
            }
            else if (value <= byte.MaxValue)
            {
                _ms.WriteByte((byte)(mt | 24));
                _ms.WriteByte((byte)value);
            }
            else if (value <= ushort.MaxValue)
            {
                _ms.WriteByte((byte)(mt | 25));
                _ms.WriteByte((byte)(value >> 8));
                _ms.WriteByte((byte)value);
            }
            else if (value <= uint.MaxValue)
            {
                _ms.WriteByte((byte)(mt | 26));
                for (int shift = 24; shift >= 0; shift -= 8)
                {
                    _ms.WriteByte((byte)(value >> shift));
                }
            }
            else
            {
                throw new ArgumentOutOfRangeException("value");
            }
        }
    }
}
