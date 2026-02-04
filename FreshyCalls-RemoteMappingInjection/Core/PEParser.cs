/**
 * PEParser.cs - PE format parsing for gadget and syscall discovery
 */

using System;
using System.Runtime.InteropServices;

namespace SharpFreshGate.Core
{
    public class PEParser
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        /// <summary>
        /// Finds a RET gadget (0xC3) in the executable sections of the specified module
        /// </summary>
        public static IntPtr FindRetGadget(string moduleName)
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
            {
                Logger.Error($"Failed to get handle for {moduleName}. Error: {Marshal.GetLastWin32Error()}");
                return IntPtr.Zero;
            }
            Logger.Info($"Got handle for {moduleName}: 0x{hModule.ToString("X")}");

            return FindGadgetInModule(hModule, new byte[] { 0xC3 });
        }

        /// <summary>
        /// Finds a syscall;ret gadget (0x0F 0x05 0xC3) in the executable sections of the specified module
        /// </summary>
        public static IntPtr FindSyscallRetGadget(string moduleName)
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
            {
                Logger.Error($"Failed to get handle for {moduleName}. Error: {Marshal.GetLastWin32Error()}");
                return IntPtr.Zero;
            }
            Logger.Info($"Got handle for {moduleName}: 0x{hModule.ToString("X")}");

            // syscall (0x0F 0x05) + ret (0xC3)
            return FindGadgetInModule(hModule, new byte[] { 0x0F, 0x05, 0xC3 });
        }

        /// <summary>
        /// Generic gadget finder - searches for byte pattern in executable sections
        /// </summary>
        private static IntPtr FindGadgetInModule(IntPtr hModule, byte[] pattern)
        {
            try
            {
                // Read DOS Header
                IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(hModule);
                if (dosHeader.e_magic != NativeConstants.IMAGE_DOS_SIGNATURE)
                {
                    Logger.Error("Invalid DOS signature.");
                    return IntPtr.Zero;
                }

                // Calculate NT Headers address
                IntPtr ntHeadersPtr = IntPtr.Add(hModule, dosHeader.e_lfanew);
                uint ntSignature = (uint)Marshal.ReadInt32(ntHeadersPtr);
                if (ntSignature != NativeConstants.IMAGE_NT_SIGNATURE)
                {
                    Logger.Error("Invalid NT signature.");
                    return IntPtr.Zero;
                }

                // Read NT Headers
                IMAGE_NT_HEADERS64 ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeadersPtr);

                // Validate Optional Header Magic for PE32+
                if (ntHeaders.OptionalHeader.Magic != NativeConstants.IMAGE_OPTIONAL_HEADER_MAGIC_PE32PLUS)
                {
                    Logger.Error($"Incorrect Optional Header Magic: 0x{ntHeaders.OptionalHeader.Magic:X}. Expected 0x20b.");
                    return IntPtr.Zero;
                }

                // Calculate address of the first section header
                int sizeOfOptionalHeader = ntHeaders.FileHeader.SizeOfOptionalHeader;
                IntPtr firstSectionHeaderPtr = IntPtr.Add(ntHeadersPtr,
                    sizeof(uint) +
                    Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) +
                    sizeOfOptionalHeader);

                Logger.Info($"Found {ntHeaders.FileHeader.NumberOfSections} sections. Scanning executable ones...");

                // Iterate through section headers
                for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
                {
                    IntPtr currentSectionHeaderPtr = IntPtr.Add(firstSectionHeaderPtr, i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
                    IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(currentSectionHeaderPtr);

                    // Check if the section is executable
                    if ((sectionHeader.Characteristics & NativeConstants.IMAGE_SCN_MEM_EXECUTE) != 0)
                    {
                        string sectionName = new string(sectionHeader.Name).TrimEnd('\0', ' ');
                        Logger.Info($"Scanning executable section '{sectionName}' (RVA: 0x{sectionHeader.VirtualAddress:X}, Size: {sectionHeader.VirtualSize} bytes)...");

                        IntPtr sectionStartAddress = IntPtr.Add(hModule, (int)sectionHeader.VirtualAddress);
                        IntPtr sectionEndAddress = IntPtr.Add(sectionStartAddress, (int)sectionHeader.VirtualSize - pattern.Length);

                        // Scan the section for the pattern
                        for (IntPtr currentAddr = sectionStartAddress;
                             currentAddr.ToInt64() < sectionEndAddress.ToInt64();
                             currentAddr = IntPtr.Add(currentAddr, 1))
                        {
                            try
                            {
                                bool found = true;
                                for (int j = 0; j < pattern.Length; j++)
                                {
                                    byte currentByte = Marshal.ReadByte(IntPtr.Add(currentAddr, j));
                                    if (currentByte != pattern[j])
                                    {
                                        found = false;
                                        break;
                                    }
                                }

                                if (found)
                                {
                                    string patternHex = BitConverter.ToString(pattern).Replace("-", " ");
                                    Logger.Success($"Found pattern [{patternHex}] at 0x{currentAddr.ToString("X")} in section '{sectionName}'.");
                                    return currentAddr;
                                }
                            }
                            catch (AccessViolationException)
                            {
                                Logger.Warning($"Access violation at 0x{currentAddr.ToString("X")}. Skipping rest of section.");
                                break;
                            }
                            catch
                            {
                                break;
                            }
                        }
                    }
                }

                Logger.Error("No matching gadget found in any executable section.");
                return IntPtr.Zero;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error during PE parsing: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Gets the export directory of a module (useful for syscall number resolution)
        /// </summary>
        public static IntPtr GetExportDirectory(string moduleName, out IMAGE_EXPORT_DIRECTORY exportDir)
        {
            exportDir = default;
            
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
                return IntPtr.Zero;

            try
            {
                IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(hModule);
                if (dosHeader.e_magic != NativeConstants.IMAGE_DOS_SIGNATURE)
                    return IntPtr.Zero;

                IntPtr ntHeadersPtr = IntPtr.Add(hModule, dosHeader.e_lfanew);
                IMAGE_NT_HEADERS64 ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeadersPtr);

                // Get export directory RVA (first data directory entry)
                IntPtr dataDirectoryPtr = IntPtr.Add(ntHeadersPtr, 
                    sizeof(uint) + Marshal.SizeOf<IMAGE_FILE_HEADER>() + 112); // 112 = offset to DataDirectory in OptionalHeader64
                
                uint exportRva = (uint)Marshal.ReadInt32(dataDirectoryPtr);
                if (exportRva == 0)
                    return IntPtr.Zero;

                IntPtr exportDirPtr = IntPtr.Add(hModule, (int)exportRva);
                exportDir = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDirPtr);
                
                return exportDirPtr;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }
    }
}
