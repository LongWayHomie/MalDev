﻿# MalDev

1. **ProcInjShellcodeInternetAPI** - remote process injection via CRT with staged payload (downloaded from server).
2. **ProcInjShellcodeNtQuerySystemInfo** - remote process injection via CRT with IPv6-obfuscated payload and NtQuerySystemInformation syscall to enumerate processes.
3. **ThreadHijackIPv6Obf** - remote process thread hijacking with IPv6-obfuscated payload.
4. **RC4APCInjection** - APC injection via alertable sacificial thread with RC4 encrypted shellcode
5. **EarlyBirdAPCInjection** - Early Bird APC Injection using debugged state with RC4 encrypted shellcode
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

