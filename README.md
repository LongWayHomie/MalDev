﻿# MalDev

1. **ProcInjShellcodeInternetAPI** - remote process injection via CRT with staged payload (downloaded from server).
2. **ProcInjShellcodeNtQuerySystemInfo** - remote process injection via CRT with IPv6-obfuscated payload and NtQuerySystemInformation syscall to enumerate processes.
3. **ThreadHijackIPv6Obf** - remote process thread hijacking with IPv6-obfuscated payload.
4. **RC4APCInjection** - APC injection via alertable sacificial thread with RC4 encrypted shellcode
5. **EarlyBirdAPCInjection** - Early Bird APC Injection using debugged state with RC4 encrypted shellcode
6. **EarlyBirdAPCInjectionStaged** - Early Bird APC Injection using debugged state with staged RC4 encrypted shellcode from webserver