# FreshyCalls Remote Mapping Injection

A proof-of-concept demonstrating advanced EDR evasion using the **FreshyCalls** technique for indirect syscall execution with remote process injection. Most of modules comes from my SharpFreshyCalls proof of concept.

## Overview

This PoC performs shellcode injection into a remote process (notepad.exe) using section mapping and remote thread creation, while bypassing user-mode hooks through indirect syscalls resolved from a clean `ntdll.dll`.

## Technique: FreshyCalls

**FreshyCalls** is an EDR evasion technique that:

1. **Loads a clean `ntdll.dll`** from the `\KnownDlls\` section object (unhooked by EDR)
2. **Parses PE exports** to extract syscall numbers (SSNs) from the clean ntdll
3. **Finds a `syscall;ret` gadget** in the clean ntdll for indirect execution
4. **Executes syscalls indirectly** by jumping to the gadget with the correct SSN

This bypasses user-mode hooks placed by EDRs on the normal `ntdll.dll` loaded in the process.

## Injection Flow

```
1. Load clean ntdll from \KnownDlls\
2. Parse exports → Resolve syscalls (NtCreateSection, NtMapViewOfSection, etc.)
3. Create memory section with PAGE_EXECUTE_READWRITE
4. Map section into target process (notepad.exe)
5. Write shellcode (msfvenom calc.exe payload)
6. Create remote thread → Execute shellcode
7. Result: Calculator spawns as child of notepad.exe
```

## Requirements

- **Platform**: Windows x64 only
- **Target**: .NET Framework 4.8

## Usage

```bash
# Start target process
notepad.exe

# Run injector
.\FreshyCalls-RemoteMappingInjection.exe
```

**Expected Result**: Calculator (CalculatorApp.exe) spawns from notepad.exe process.

## Core Architecture

### **Core/** Directory Files

#### **FreshNtdll.cs**
- Loads a clean, unhooked `ntdll.dll` from `\KnownDlls\`
- Uses `NtOpenSection` and `NtMapViewOfSection` to map the system's clean ntdll into memory
- Returns base address of the clean ntdll for export parsing
- **Key Function**: `GetCleanNtdllBase()`

#### **SyscallResolver.cs**
- Parses the PE export directory of the clean ntdll
- Extracts function names, syscall numbers (SSNs), and addresses
- Finds a `syscall;ret` gadget for indirect execution
- Maintains a table of resolved syscall entries
- **Key Functions**: `Initialize()`, `ParseNtdllExports()`, `GetSyscall()`

#### **IndirectSyscall.cs**
- Provides C# wrappers for native syscalls using indirect execution
- Allocates RWX memory for syscall stubs
- Implements syscall dispatcher that loads SSN and jumps to the `syscall;ret` gadget
- **Implemented Syscalls**:
  - `NtCreateSection` - Create memory section
  - `NtMapViewOfSection` - Map section into process
  - `NtWriteVirtualMemory` - Write to remote memory
  - `NtCreateThreadEx` - Create remote thread
  - And more (NtAllocateVirtualMemory, NtProtectVirtualMemory, etc.)

#### **NativeStructs.cs**
- Defines Windows native structures and constants
- Contains PE format structures (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, etc.)
- Defines NTSTATUS codes, memory protection constants, and access rights
- **Purpose**: Interop layer for native Windows APIs

#### **DynamicInvoke.cs**
- Dynamic function resolution using `GetProcAddress`
- Provides delegates and wrappers for kernel32.dll functions
- Used for fallback or non-syscall operations
- **Key Functions**: `GetLibraryAddress()`, `GetDelegate<T>()`

#### **PEParser.cs**
- Utility functions for parsing PE (Portable Executable) files
- Finds ROP gadgets and parses export directories
- **Key Functions**: `FindGadget()`, `GetExportDirectory()`

#### **Logger.cs**
- Simple logging utility for console output
- Color-coded messages (Info, Success, Error)
- **Key Functions**: `Info()`, `Success()`, `Error()`


## OPSEC Features

- ✅ **No user-mode hooks**: Syscalls bypass EDR hooks in ntdll
- ✅ **Clean SSNs**: Dynamically resolved from unhooked ntdll
- ✅ **Indirect execution**: Uses `syscall;ret` gadgets instead of direct syscalls
- ✅ **Section mapping**: Memory sections instead of VirtualAllocEx
- ✅ **No suspicious APIs**: Avoids CreateRemoteThread, uses NtCreateThreadEx

## Detection Considerations

While this technique evades user-mode hooks, it may still be detected by:

- **Kernel-mode monitoring**: ETW, kernel callbacks, minifilter drivers
- **Behavioral analysis**: Process injection, section mapping patterns
- **Memory scanning**: Shellcode signatures in memory

## Educational Purpose

**This is a proof-of-concept for educational and research purposes only.** Use responsibly and only in authorized environments.

## References

- [FreshyCalls Technique](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/)
- [Syscalls for EDR Evasion](https://github.com/jthuraisamy/SysWhispers2)
- [PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
