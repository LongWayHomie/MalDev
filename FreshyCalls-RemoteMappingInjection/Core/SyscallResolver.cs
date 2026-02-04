/**
 * SyscallResolver.cs - Syscall number resolution from fresh ntdll
 * 
 * Parses clean ntdll.dll loaded by FreshNtdll to extract syscall numbers (SSNs)
 * and find clean syscall;ret gadgets for indirect syscall execution.
 */

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpFreshGate.Core
{
    /// <summary>
    /// Represents a resolved syscall with its SSN and clean trampoline address
    /// </summary>
    public class SyscallEntry
    {
        public string FunctionName { get; set; }
        public ushort SSN { get; set; }
        public IntPtr SyscallAddress { get; set; }  // Address of syscall;ret in clean ntdll
        
        public override string ToString()
        {
            return $"{FunctionName}: SSN=0x{SSN:X4}, Addr=0x{SyscallAddress.ToString("X")}";
        }
    }

    /// <summary>
    /// Syscall resolver - extracts SSNs from fresh ntdll
    /// </summary>
    public static class SyscallResolver
    {
        private static Dictionary<string, SyscallEntry> _syscallTable = new Dictionary<string, SyscallEntry>();
        private static IntPtr _cleanNtdllBase = IntPtr.Zero;
        private static bool _initialized = false;

        // Common syscalls
        public static SyscallEntry NtAllocateVirtualMemory { get; private set; }
        public static SyscallEntry NtProtectVirtualMemory { get; private set; }
        public static SyscallEntry NtCreateThreadEx { get; private set; }
        public static SyscallEntry NtWriteVirtualMemory { get; private set; }
        public static SyscallEntry NtFreeVirtualMemory { get; private set; }
        public static SyscallEntry NtWaitForSingleObject { get; private set; }
        public static SyscallEntry NtClose { get; private set; }
        public static SyscallEntry NtOpenProcess { get; private set; }
        public static SyscallEntry NtCreateSection { get; private set; }
        public static SyscallEntry NtMapViewOfSection { get; private set; }
        public static SyscallEntry NtUnmapViewOfSection { get; private set; }


        /// <summary>
        /// Initialize syscall resolver - parse fresh ntdll and resolve syscalls
        /// </summary>
        public static bool Initialize()
        {
            if (_initialized)
                return true;

            Logger.Info("Initializing syscall resolver with FreshyCalls...");

            // Get clean ntdll from KnownDlls
            _cleanNtdllBase = FreshNtdll.GetCleanNtdllBase();
            if (_cleanNtdllBase == IntPtr.Zero)
            {
                Logger.Error("Failed to load fresh ntdll");
                return false;
            }

            Logger.DebugAddress("Fresh ntdll base", _cleanNtdllBase);

            try
            {
                // Parse exports and resolve SSNs from CLEAN ntdll
                if (!ParseNtdllExports())
                {
                    Logger.Error("Failed to parse ntdll exports");
                    return false;
                }

                // Resolve common syscalls
                NtAllocateVirtualMemory = GetSyscall("NtAllocateVirtualMemory");
                NtProtectVirtualMemory = GetSyscall("NtProtectVirtualMemory");
                NtCreateThreadEx = GetSyscall("NtCreateThreadEx");
                NtWriteVirtualMemory = GetSyscall("NtWriteVirtualMemory");
                NtFreeVirtualMemory = GetSyscall("NtFreeVirtualMemory");
                NtWaitForSingleObject = GetSyscall("NtWaitForSingleObject");
                NtClose = GetSyscall("NtClose");
                NtOpenProcess = GetSyscall("NtOpenProcess");
                NtCreateSection = GetSyscall("NtCreateSection");
                NtMapViewOfSection = GetSyscall("NtMapViewOfSection");
                NtUnmapViewOfSection = GetSyscall("NtUnmapViewOfSection");

                _initialized = true;
                Logger.Success($"Syscall resolver initialized. Resolved {_syscallTable.Count} syscalls from fresh ntdll.");
                
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Syscall resolver initialization failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get a resolved syscall by name
        /// </summary>
        public static SyscallEntry GetSyscall(string name)
        {
            if (_syscallTable.TryGetValue(name, out var entry))
                return entry;
            return null;
        }

        /// <summary>
        /// Parse ntdll.dll export table and resolve SSNs for Nt* functions
        /// </summary>
        private static bool ParseNtdllExports()
        {
            try
            {
                // Read DOS header from CLEAN ntdll
                var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(_cleanNtdllBase);
                if (dosHeader.e_magic != NativeConstants.IMAGE_DOS_SIGNATURE)
                {
                    Logger.Error($"Invalid DOS signature: 0x{dosHeader.e_magic:X4}");
                    return false;
                }

                // Read NT headers from CLEAN ntdll
                IntPtr ntHeadersPtr = IntPtr.Add(_cleanNtdllBase, dosHeader.e_lfanew);
                uint ntSignature = (uint)Marshal.ReadInt32(ntHeadersPtr);
                if (ntSignature != NativeConstants.IMAGE_NT_SIGNATURE)
                {
                    Logger.Error($"Invalid NT signature: 0x{ntSignature:X8}");
                    return false;
                }

                // Skip PE signature (4 bytes) and read FILE_HEADER
                IntPtr fileHeaderPtr = IntPtr.Add(ntHeadersPtr, sizeof(uint));
                var fileHeader = Marshal.PtrToStructure<IMAGE_FILE_HEADER>(fileHeaderPtr);

                // Skip FILE_HEADER and read OPTIONAL_HEADER (x64 PE32+ only)
                IntPtr optionalHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<IMAGE_FILE_HEADER>());
                ushort optionalMagic = (ushort)Marshal.ReadInt16(optionalHeaderPtr);
                
                if (optionalMagic != NativeConstants.IMAGE_OPTIONAL_HEADER_MAGIC_PE32PLUS) // 0x020B
                {
                    Logger.Error($"Not a PE32+ (x64) image. Magic: 0x{optionalMagic:X4}");
                    return false;
                }

                Logger.Info("Detected PE32+ (64-bit) ntdll");

                // DataDirectory is at offset 112 in IMAGE_OPTIONAL_HEADER64
                IntPtr exportDataDirPtr = IntPtr.Add(optionalHeaderPtr, 112);
                uint exportRva = (uint)Marshal.ReadInt32(exportDataDirPtr);
                uint exportSize = (uint)Marshal.ReadInt32(IntPtr.Add(exportDataDirPtr, 4));

                if (exportRva == 0)
                {
                    Logger.Error("No export directory found");
                    return false;
                }

                Logger.Info($"Export directory RVA: 0x{exportRva:X8}, Size: {exportSize}");

                // Read the export directory from CLEAN ntdll
                IntPtr exportDirPtr = IntPtr.Add(_cleanNtdllBase, (int)exportRva);
                var exportDir = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

                Logger.Info($"Export directory: {exportDir.NumberOfNames} named exports");

                // Get export arrays (all RVAs are relative to CLEAN ntdll base)
                IntPtr namesPtr = IntPtr.Add(_cleanNtdllBase, (int)exportDir.AddressOfNames);
                IntPtr ordinalsPtr = IntPtr.Add(_cleanNtdllBase, (int)exportDir.AddressOfNameOrdinals);
                IntPtr functionsPtr = IntPtr.Add(_cleanNtdllBase, (int)exportDir.AddressOfFunctions);

                // Collect all Nt* functions
                var ntFunctions = new List<(string name, IntPtr address)>();

                for (uint i = 0; i < exportDir.NumberOfNames; i++)
                {
                    uint nameRva = (uint)Marshal.ReadInt32(IntPtr.Add(namesPtr, (int)(i * 4)));
                    IntPtr namePtr = IntPtr.Add(_cleanNtdllBase, (int)nameRva);
                    string funcName = Marshal.PtrToStringAnsi(namePtr);

                    // Only process Nt* functions (not Zw*, Rtl*, etc.)
                    if (funcName.StartsWith("Nt") && !funcName.StartsWith("Ntdll"))
                    {
                        ushort ordinal = (ushort)Marshal.ReadInt16(IntPtr.Add(ordinalsPtr, (int)(i * 2)));
                        uint funcRva = (uint)Marshal.ReadInt32(IntPtr.Add(functionsPtr, ordinal * 4));
                        IntPtr funcAddress = IntPtr.Add(_cleanNtdllBase, (int)funcRva);

                        ntFunctions.Add((funcName, funcAddress));
                    }
                }

                Logger.Info($"Found {ntFunctions.Count} Nt* functions in fresh ntdll");

                // Find a clean syscall;ret gadget
                IntPtr syscallGadget = FindSyscallGadget(ntFunctions);
                if (syscallGadget == IntPtr.Zero)
                {
                    Logger.Warning("Could not find syscall;ret gadget");
                }

                // Resolve SSN for each function
                foreach (var (name, address) in ntFunctions)
                {
                    var entry = ResolveSyscallEntry(name, address, syscallGadget);
                    if (entry != null)
                    {
                        _syscallTable[name] = entry;
                    }
                }

                return _syscallTable.Count > 0;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error parsing exports: {ex.Message}\nStack: {ex.StackTrace}");
                return false;
            }
        }

        /// <summary>
        /// Resolve SSN from a Nt* function in fresh ntdll
        /// Since ntdll is clean (no hooks), we can directly read the SSN
        /// </summary>
        private static SyscallEntry ResolveSyscallEntry(string name, IntPtr funcAddress, IntPtr defaultGadget)
        {
            try
            {
                // Read function prologue
                byte[] prologue = new byte[24];
                Marshal.Copy(funcAddress, prologue, 0, prologue.Length);

                // Standard syscall stub pattern (no hooks in fresh ntdll):
                // 4C 8B D1           mov r10, rcx
                // B8 XX XX 00 00     mov eax, SSN
                // 0F 05              syscall
                // C3                 ret

                if (prologue[0] == 0x4C && prologue[1] == 0x8B && prologue[2] == 0xD1 &&
                    prologue[3] == 0xB8)
                {
                    ushort ssn = BitConverter.ToUInt16(prologue, 4);
                    
                    // Find syscall instruction in this function
                    IntPtr syscallAddr = defaultGadget;
                    for (int i = 0; i < 20; i++)
                    {
                        if (prologue[i] == 0x0F && prologue[i + 1] == 0x05)
                        {
                            syscallAddr = IntPtr.Add(funcAddress, i);
                            break;
                        }
                    }

                    return new SyscallEntry
                    {
                        FunctionName = name,
                        SSN = ssn,
                        SyscallAddress = syscallAddr
                    };
                }

                // If the pattern doesn't match, this might not be a standard syscall
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Find a clean syscall;ret gadget in fresh ntdll
        /// </summary>
        private static IntPtr FindSyscallGadget(List<(string name, IntPtr address)> functions)
        {
            foreach (var (name, address) in functions)
            {
                try
                {
                    byte[] bytes = new byte[24];
                    Marshal.Copy(address, bytes, 0, 24);

                    // Check for standard syscall stub
                    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1)
                    {
                        // Find syscall;ret sequence (0x0F 0x05 0xC3)
                        for (int i = 0; i < 20; i++)
                        {
                            if (bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3)
                            {
                                IntPtr gadget = IntPtr.Add(address, i);
                                Logger.Success($"Found syscall;ret gadget at 0x{gadget.ToString("X")} (from {name})");
                                return gadget;
                            }
                        }
                    }
                }
                catch { }
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Print all resolved syscalls (debug)
        /// </summary>
        public static void DumpSyscallTable()
        {
            Logger.Info("=== Resolved Syscalls from Fresh NTDLL ===");
            foreach (var entry in _syscallTable.Values)
            {
                Logger.Info(entry.ToString());
            }
        }
    }
}
