import ctypes
import pefile
import os
import struct

EXPORT_ZW = True
def get_syscall_stub(func_addr):
    try:
        return ctypes.string_at(func_addr, 10)
    except (OSError, ValueError):
        return None
def get_ntdll_syscalls():
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    h_ntdll = kernel32.GetModuleHandleW("ntdll.dll")
    if not h_ntdll:
        raise Exception("Could not get ntdll.dll handle in memory.")
    ntdll_path = os.path.join(os.environ["SystemRoot"], "System32", "ntdll.dll")
    pe = pefile.PE(ntdll_path)
    syscall_dict = {}
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        name = exp.name.decode()
        if not (name.startswith("Nt") or (EXPORT_ZW and name.startswith("Zw"))):
            continue
        try:
            func_ptr = getattr(ntdll, name)
            func_addr = ctypes.cast(func_ptr, ctypes.c_void_p).value
            stub = get_syscall_stub(func_addr)
            file_rva = exp.address
            file_offset = pe.get_offset_from_rva(file_rva)
            file_stub = pe.__data__[file_offset:file_offset + 10]
            if stub and stub[:3] == b'\x4c\x8b\xd1' and stub[3] == 0xb8:
                syscall_num = int.from_bytes(stub[4:8], byteorder='little')
                hooked = stub != file_stub
                syscall_dict[name] = (syscall_num, hooked)
            else:
                syscall_dict[name] = (None, False)
        except Exception:
            syscall_dict[name] = (None, False)
    return syscall_dict
def generate_asm(name, num):
    # SysWhispers-like 64-bit syscall stub, NASM syntax
    stub = f"""
; {name}
global {name}
{name}:
    mov r10, rcx
    mov eax, 0x{num:03X}
    syscall
    ret
"""
    return stub.strip()
if __name__ == "__main__":
    syscalls = get_ntdll_syscalls()
    resolved = [(i+1, name, val[0], val[1]) for i, (name, val) in enumerate(
        sorted(syscalls.items(), key=lambda x: (x[1][0] if x[1][0] is not None else 9999))
    ) if val[0] is not None]
    print(f"{'Num':<5} {'Function':<35} {'Syscall#':<8} Hooked")
    print("-" * 55)
    for idx, name, num, hooked in resolved:
        print(f"{idx:<5} {name:<35} 0x{num:03X}    {'YES' if hooked else 'NO'}")
    print("\nEnter comma-separated numbers to generate asm (e.g. 1,3,5):")
    selection = input(">>> ").strip()
    selected_indices = set()
    for s in selection.split(","):
        s = s.strip()
        if s.isdigit():
            selected_indices.add(int(s))
    selected_syscalls = [item for item in resolved if item[0] in selected_indices]
    if not selected_syscalls:
        print("[-] No valid selections. Exiting.")
        exit(0)
    asm_file = "syscalls.asm"
    with open(asm_file, "w") as f:
        f.write("; Auto-generated syscall wrappers\n\n")
        for _, name, num, _ in selected_syscalls:
            f.write(generate_asm(name, num))
            f.write("\n\n")
    print(f"[+] Written {len(selected_syscalls)} syscall stubs to {asm_file}")
