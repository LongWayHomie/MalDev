# MalDev
This is basically a collection of loaders I have been doing as a side project to implement most of the things I'm learning while doing MalDevAcademy stuff. Most of these loaders work "out of the box", but testing included only using them with Metasploit Framework. 
Since I'm not a master of C or C# at all, I guess you may come across some absurd and confusing code. I was just trying to make things work so... (✌ﾟ∀ﾟ)☞
This repo is for educational purposes only. Use at your own risk.

1. **ProcInjShellcodeInternetAPI** - remote process injection via CRT with staged payload (downloaded from server).
2. **ProcInjShellcodeNtQuerySystemInfo** - remote process injection via CRT with IPv6-obfuscated payload and NtQuerySystemInformation syscall to enumerate processes.
3. **ThreadHijackIPv6Obf** - remote process thread hijacking with IPv6-obfuscated payload.
4. **RC4APCInjection** - APC injection via alertable sacificial thread with RC4 encrypted shellcode
5. **EarlyBirdAPCInjection** - Early Bird APC Injection using debugged state with staged shellcode
6. **RC4EarlyBirdAPCInjectionStaged** - Early Bird APC Injection using debugged state with staged RC4 encrypted shellcode from webserver
7. **AESCRTSleep** - CRT injection with AES encrypted payload, sleeping for random seconds before injection
8. **XORCRTInj** - CRT injection with XORed payload with encryption program
9. **NtAPIXOR** - Using Native API for process injection (C#)
10. **XORProcessHypnosis** - using Process Hypnosis technique with XORed payload
11. **ProcessHypnosisStaged** - using Process Hypnosis technique with staged payload
12. **XORProcessHypnosisStaged** - using Process Hypnosis technique with XORed staged payload and key
13. **EarlyBirdAPCInjectionStagedSpoofControl** - using Early Bird technique with staged, encoded payload, execution control and PPID spoofing
14. **ProcessHypnosisStagedObfuscated** - Process Hypnosis with staged payload, basic evasion, execution control, API hashing, custom GMH/GPA func.
15. **EarlyBirdAPCEvasion** - using Early Bird technique with staged payload, API hashing, API emulation, PPID spoofing etc.
16. **EarlyBirdAPCInjectionSyscalls** - using Early Bird technique with staged payload and syscalls
17. **HGRemoteMappingInjection** - remote mapping injection using HellsGate technique

