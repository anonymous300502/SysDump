# 🕳️ SyscallDumper

![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

> 🔧 A Python-based tool to extract native Windows syscalls (`Nt*`, `Zw*`) from `ntdll.dll`, detect inline hooks, and generate clean `syscalls.asm` NASM stubs. Ideal for red teamers, malware analysts, exploit devs, and anyone working with syscall-level evasion.

---

## ✨ Features

- ✅ Extracts `Nt*` and `Zw*` syscall numbers from the current Windows build
- 🧠 Compares in-memory syscall stubs vs. on-disk exports
- 🛡️ Detects inline hooking or patching (e.g. EDR tampering)
- 🧬 Generates `.asm` syscall wrappers in **SysWhispers**-style (retpoline-free)
- 🔢 Interactive numbered menu for selecting functions
- 💻 Clean NASM syntax for raw syscall usage
- 📦 Outputs stubs to `syscalls.asm`

---

>## 🖥️ Sample Output in terminal:

>Num Function Syscall# Hooked

>1 NtAllocateVirtualMemory 0x018 NO<br>
>2 NtOpenProcess 0x026 YES<br>
>3 NtCreateThreadEx 0x0B0 NO<br>

>Enter comma-separated numbers to generate asm (e.g. 1,3): 1,3<br>

>[+] Written 2 syscall stubs to syscalls.asm






> 💡 After execution, you'll get a `syscalls.asm` file with the selected syscall stubs.

---

## 📁 Output Sample (`syscalls.asm`)

```nasm
; NtAllocateVirtualMemory
global NtAllocateVirtualMemory
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x018
    syscall
    ret

; NtCreateThreadEx
global NtCreateThreadEx
NtCreateThreadEx:
    mov r10, rcx
    mov eax, 0x0B0
    syscall
    ret
```





⚙️ Requirements

    ✅ Python 3.6+

    ✅ Windows x64

    ✅ Admin NOT required (uses ctypes.string_at instead of ReadProcessMemory)

📦 Install Dependencies

```pip install pefile```

🚀 How to Use

```python syscall_dumper.py```

    View a list of system call functions with their syscall numbers and hook status

    Enter the numbers of the desired functions (e.g. 2,5,8)

    A clean syscalls.asm file will be generated with selected syscall wrappers


🔧 Assembly Format

    Output is written in NASM syntax

    Compatible with:

        nasm + link.exe / ld

        Raw shellcode loaders

        Manual mappers

        SysWhispers-style syscall execution
