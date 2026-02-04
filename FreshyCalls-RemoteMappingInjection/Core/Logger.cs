/**
 * Logger.cs - Conditional logging based on DEBUG compilation symbol
 */

using System;

namespace SharpFreshGate.Core
{
    public static class Logger
    {
        /// <summary>
        /// Logs an informational message (only in DEBUG builds)
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        public static void Info(string message)
        {
            Console.WriteLine($"[*] {message}");
        }

        /// <summary>
        /// Logs a success message (only in DEBUG builds)
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        public static void Success(string message)
        {
            Console.WriteLine($"[+] {message}");
        }

        /// <summary>
        /// Logs a warning message (only in DEBUG builds)
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        public static void Warning(string message)
        {
            Console.WriteLine($"[!] {message}");
        }

        /// <summary>
        /// Logs an error message (only in DEBUG builds)
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        public static void Error(string message)
        {
            Console.WriteLine($"[-] {message}");
        }

        /// <summary>
        /// Logs a debug message with hex address (only in DEBUG builds)
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        public static void DebugAddress(string label, IntPtr address)
        {
            Console.WriteLine($"[*] {label}: 0x{address.ToString("X")}");
        }

        /// <summary>
        /// Logs bytes as hex string (only in DEBUG builds)
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        public static void DebugBytes(string label, byte[] bytes)
        {
            string byteString = BitConverter.ToString(bytes).Replace("-", " ");
            Console.WriteLine($"[*] {label}: {byteString}");
        }
    }
}
