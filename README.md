# MalDev — Collection of Shellcode Loaders

> ⚠️ **Disclaimer:** This repository is intended **strictly for educational purposes and security research**. All techniques presented here are to be used **only on systems you own or have explicit written authorization to test**. The author takes no responsibility for any misuse of this material. Use at your own risk.

---

## Overview

A personal collection of shellcode loaders built as a learning project alongside [MalDevAcademy](https://maldevacademy.com/) coursework. Each project implements a specific combination of injection technique, encryption, and evasion measures.

**Testing environment:** All loaders were tested against Windows Defender on Windows 10/11 using Metasploit Framework shellcode. Results may vary across different AV/EDR configurations.

**Language breakdown:** Most loaders are written in **C**, with one exception in **C#** (NtAPIXOR). Several projects use **MASM** for syscall stubs.

> 📁 **Note on missing `.sln` files:** Solution files are intentionally omitted from most projects. The source code is provided for study and reference — you are expected to read and understand it, not compile it blindly. If you need to build a project, set up your own VS solution.

---

## Learning Progression

The loaders are ordered roughly by increasing complexity. Starting from basic CRT/remote injection, progressing through APC techniques, encryption, sandbox evasion, and finally syscall-based approaches that avoid userland hooks entirely.

---

## Loader Reference Table

| No. | Loader Name | Lang | Encryption | Staged | Evasion Measures | Description |
|:--:|:---|:---:|:---:|:---:|:---|:---|
| 1 | ProcInjShellcodeInternetAPI | C | None | ✅ | • Remote injection<br>• CRT | Remote process injection via CRT with staged payload downloaded from a remote server |
| 2 | ProcInjShellcodeNtQuerySystemInfo | C | None | ✅ | • IPv6 obfuscation<br>• Direct syscall usage<br>• Process enumeration | Remote process injection via CRT with IPv6-obfuscated payload; uses `NtQuerySystemInformation` syscall for process enumeration |
| 3 | ThreadHijackIPv6Obf | C | None | ❌ | • Thread hijacking<br>• IPv6 obfuscation | Remote process thread hijacking with IPv6-obfuscated payload |
| 4 | RC4APCInjection | C | RC4 | ❌ | • APC injection<br>• Alertable thread | APC injection via alertable sacrificial thread with RC4-encrypted shellcode |
| 5 | EarlyBirdAPCInjection | C | None | ✅ | • Early Bird technique<br>• Debugged-state spawn | Early Bird APC injection spawning a target process in debugged state; payload fetched from staging server |
| 6 | RC4EarlyBirdAPCInjectionStaged | C | RC4 | ✅ | • Early Bird technique<br>• Debugged-state spawn | Early Bird APC injection with RC4-encrypted staged shellcode fetched from a web server |
| 7 | AESCRTSleep | C | AES | ❌ | • CRT injection<br>• Random sleep timing<br>• Remote injection | CRT injection with AES-encrypted payload; sleeps a random interval before execution to evade sandbox timeouts |
| 8 | XORCRTInj | C | XOR | ❌ | • CRT injection | CRT injection with XOR-encrypted payload; includes a separate encryption utility |
| 9 | NtAPIXOR | C# | XOR | ❌ | • Native API usage<br>• Remote injection | Remote process injection using Native API calls (C#) with XOR-encrypted payload |
| 10 | XORProcessHypnosis | C | XOR | ❌ | • Process Hypnosis<br>• Application Setup Strings<br>• Remote injection<br>• API emulation<br>• Debugger check<br>• Sleep check | Process Hypnosis technique with XOR-encrypted payload and sandbox evasion checks |
| 11 | ProcessHypnosisStaged | C | None | ✅ | • Process Hypnosis | Process Hypnosis technique with staged payload — minimal evasion, baseline implementation |
| 12 | XORProcessHypnosisStaged | C | XOR | ✅ | • Process Hypnosis<br>• Staged key<br>• Application Setup Strings<br>• Remote injection<br>• API emulation<br>• Sleep check<br>• Debugger check | Process Hypnosis with XOR-encrypted staged payload and separately staged encryption key |
| 13 | EarlyBirdAPCInjectionStagedSpoofControl | C | RC4 | ✅ | • Early Bird technique<br>• PPID spoofing<br>• API emulation<br>• Execution control<br>• Payload execution check<br>• Remote injection<br>• Sleep check | Early Bird APC injection with RC4-encrypted staged payload, PPID spoofing, and execution flow control |
| 14 | ProcessHypnosisStagedObfuscated | C | None | ✅ | • Process Hypnosis<br>• API hashing<br>• Custom GetModuleHandle/GetProcAddress<br>• Runtime API resolution<br>• Execution control<br>• API emulation<br>• Debugger check<br>• Sleep check | Process Hypnosis with staged payload, API hashing, and custom GMH/GPA implementations to evade static analysis |
| 15 | EarlyBirdAPCEvasion | C | None | ✅ | • Early Bird technique<br>• API hashing<br>• API emulation<br>• PPID spoofing<br>• Custom GMH/GPA<br>• Runtime API resolution<br>• Execution control<br>• API Hammering<br>• Debugger check<br>• Sleep check | Early Bird APC with comprehensive evasion stack: API hashing, hammering, PPID spoofing, runtime resolution, execution control |
| 16 | EarlyBirdAPCInjectionSyscalls | C + ASM | None | ✅ | • Early Bird technique<br>• Direct syscalls (SysWhispers3)<br>• Custom GMH/GPA<br>• Runtime API resolution<br>• API hashing<br>• Execution control<br>• API emulation<br>• Debugger check<br>• Sleep check | Early Bird APC injection using direct syscalls via SysWhispers3, bypassing userland hooks |
| 17 | HGRemoteMappingInjection | C | None | ❌ | • HellsGate technique<br>• Remote mapping injection | Remote mapping injection using HellsGate for dynamic syscall number resolution |
| 18 | DLL-ProcessHypnosisEv | C | XOR | ❌ | • Process Hypnosis<br>• DLL export<br>• Application Setup Strings<br>• Sleep check<br>• API emulation<br>• Execution control | Process Hypnosis technique delivered as a DLL with XOR-encrypted shellcode and evasion |
| 19 | SysWhispRemoteMappingInjection | C + ASM | None | ❌ | • SysWhispers3<br>• Remote mapping injection<br>• API unhooking<br>• Custom GMH/GPA<br>• API hashing<br>• Runtime API resolution<br>• Execution control<br>• API Hammering<br>• API emulation<br>• Debugger check<br>• Sleep check | Remote mapping injection using SysWhispers3 syscalls with a full evasion stack including API unhooking |
| 20 | APCInjection-IndirectSyscalls | C + ASM | XOR | ❌ | • APC injection<br>• HellsHall technique<br>• Indirect syscalls<br>• Custom GMH/GPA<br>• API hashing<br>• Runtime API resolution<br>• Execution control<br>• API Hammering<br>• API emulation<br>• Debugger check<br>• Sleep check | APC injection with indirect syscalls via HellsHall; most advanced evasion stack in the repo |
| 21 | FreshyCalls-RemoteMappingInjection | C | None | ❌ | • FreshyCalls technique<br>• Remote mapping injection | Remote mapping injection using FreshyCalls for syscall-based userland hook bypass |

---

## Key Techniques Glossary

| Term | Description |
|:---|:---|
| **CRT Injection** | CreateRemoteThread-based shellcode injection into a remote process |
| **APC Injection** | Queuing shellcode execution via Asynchronous Procedure Calls |
| **Early Bird APC** | APC injection into a newly spawned suspended process before its entry point runs |
| **Process Hypnosis** | Replacing the image of a suspended process before it executes |
| **Remote Mapping Injection** | Mapping a shellcode section into a remote process without using `WriteProcessMemory` |
| **PPID Spoofing** | Spawning a process with a forged parent PID to blend into process trees |
| **API Hashing** | Resolving API addresses at runtime using hashed function names to avoid import table artifacts |
| **API Hammering** | Calling benign APIs in a loop to inflate execution time and evade sandbox timeouts |
| **HellsGate / HellsHall** | Techniques for resolving SSNs (syscall numbers) dynamically from ntdll to enable direct/indirect syscalls |
| **SysWhispers3** | A tool to generate direct/indirect syscall stubs, avoiding userland hooks in ntdll |
| **FreshyCalls** | Technique for sorting syscall stubs to determine SSNs without reading hooked ntdll |

---

## References & Credits

Projects and resources that informed this work:

- [MalDevAcademy](https://maldevacademy.com/) — primary learning resource
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3) — direct/indirect syscall generation
- [HellsGate](https://github.com/am0nsec/HellsGate) — dynamic SSN resolution
- [HellsHall](https://github.com/Maldev-Academy/HellHall) — indirect syscall variant
- [FreshyCalls](https://github.com/crummie5/FreshyCalls) — syscall stub sorting technique
- [Process Hypnosis](https://github.com/captain-woof/process-hypnosis) — technique reference