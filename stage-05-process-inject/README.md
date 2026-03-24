# Stage 05: Early Bird APC Injection with Remote-Side Decryption

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first cross-process injection stage. Everything changes here:
- **APC injection** into a suspended `charmap.exe` — no CreateRemoteThread, bypasses Sysmon Event ID 8
- **Remote-side decryption** — the injector NEVER holds plaintext shellcode. A 41-byte decoder stub XOR-decrypts inside the target process
- **Triple-layer encryption** — position mask → RC4 "AES" → remote XOR. Three layers, three different decryption locations
- **Direct IAT imports** — no PEB walking. Injection APIs (CreateProcessW, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, ResumeThread) visible in the import table
- Uses `common` library (first stage with shared library dependency)

**This binary achieved 0/76 on VirusTotal** (March 2026).

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Early Bird APC injection (spawn suspended → inject → resume) | Sysmon Event ID 1+10 correlation for suspended process spawn |
| Remote-side decryption (plaintext never in injector) | Detecting RWX memory in legitimate processes (pe-sieve/Moneta) |
| Triple-layer encryption pipeline | YARA rule for APC injection API chain in IAT |
| Position-independent decoder stub (41 bytes, RIP-relative) | Sigma rule for CreateProcessW(SUSPENDED) + QueueUserAPC sequence |
| KUSER_SHARED_DATA anti-sandbox (no API call) | ETW-based detection of cross-process VirtualAllocEx + WriteProcessMemory |
| IAT trade-off: visible APIs vs invisible PEB patterns | Memory forensics: finding injected code in charmap.exe's address space |

---

## What's New vs Stages 01-04

| Concept | Stages 01-04 | Stage 05 |
|---------|-------------|----------|
| Execution context | Same process | **Cross-process** (charmap.exe) |
| Thread creation | CreateThread (same-process) | **QueueUserAPC** (APC injection, different process) |
| Shellcode in injector memory | Yes (plaintext exists briefly) | **No** — only XOR'd intermediate, never plaintext |
| Memory protection | RW → RX (W^X) | **RW → RWX** (stub must write AND execute) |
| API resolution | PEB walking (hidden IAT) | **Direct imports** (visible IAT) |
| Encryption layers | 1-2 (XOR or RC4) | **3** (position mask + AES/RC4 + remote XOR) |
| MITRE technique | T1620 (Reflective Code Loading) | **T1055.004** (APC Injection) — first real process injection |
| Sysmon Event 8 | N/A | **Does NOT fire** — APC injection bypasses CreateRemoteThread detection |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,132 lines** of guided analysis — injection chain walkthrough, decoder stub reversing, multi-layer crypto analysis, detection engineering |
| `svcctl.exe` | The compiled binary (~279 KB, Rust, PE64) — open in Ghidra/x64dbg and follow along |

---

## Quick Start

1. **Complete Stages 01-04 first** — this stage assumes familiarity with the loader pipeline and crypto concepts
2. **Download** `svcctl.exe` and `LEARNING_PATH.md`
3. **Read** Section 0 (Source Code Deep Dive) — the binary is only 76 lines
4. **Trace** the injection chain in Section 2 (API by API walkthrough)
5. **Reverse** the decoder stub in Section 4 (41 bytes of position-independent x64)
6. **Write** detection rules in Section 5 (YARA + Sigma for APC patterns)
7. **Observe** the injection live in x64dbg with Section 8 (Hands-On Lab)

---

## The Injection Flow

```
svcctl.exe                              charmap.exe (suspended)
┌─────────────────────┐                ┌──────────────────────────┐
│ demask(MASKED_SC)   │                │                          │
│ aes::decrypt()      │                │                          │
│ → intermediate      │                │                          │
│   (XOR'd, NOT sc)   │                │                          │
│                     │                │                          │
│ CreateProcessW(SUSP)│───creates─────►│ (main thread suspended)  │
│ VirtualAllocEx(RW)  │───allocates───►│ [empty RW region]        │
│ WriteProcessMemory  │───writes──────►│ [stub|key|intermediate]  │
│ VirtualProtectEx    │───protects────►│ [RWX]                    │
│ QueueUserAPC(stub)  │───queues──────►│ APC: run stub at resume  │
│ ResumeThread        │───resumes─────►│ stub XOR-decrypts        │
│                     │                │ stub JMPs to shellcode   │
│ [exit — job done]   │                │ MessageBox("GoodBoy")    │
└─────────────────────┘                └──────────────────────────┘
```

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (uses `common` library) |
| Injection Method | Early Bird APC (T1055.004) |
| Target Process | `C:\Windows\System32\charmap.exe` (CREATE_SUSPENDED) |
| API Resolution | Direct IAT imports (no PEB walking) |
| Encryption | 3 layers: position mask (index×0x37+0x5A) → RC4 "AES" (32-byte key) → remote XOR (16-byte key) |
| Decoder Stub | 41 bytes, position-independent x64, RIP-relative addressing |
| Payload | 302-byte MessageBox("GoodBoy") + ExitProcess |
| Combined Injection Size | 359 bytes (41 stub + 16 key + 302 intermediate) |
| Memory Protection | RW → RWX (stub must write AND execute in-place) |
| Anti-Sandbox | KUSER_SHARED_DATA uptime (>5 min, no API call) |
| Binary Size | ~279 KB |
| Binary Name | `svcctl.exe` (mimics Service Control utility) |
| VT Score | 0/76 achieved (March 2026) |

---

## Course Progression

This is **Stage 05** of 15:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05 (this)   Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

| Stage | Technique | What's New |
|-------|-----------|------------|
| 01 | Basic Loader | XOR decrypt, PEB-walk, VirtualAlloc→VirtualProtect→CreateThread |
| 02 | XOR Cryptanalysis | Known-plaintext attack, IC key-length detection, memory scrubbing |
| 03 | AES + Jigsaw | Entropy normalization, payload fragmentation, RC4 stream cipher |
| 04 | API Hashing | Hash algorithm deep dive, cross-DLL resolution, rainbow tables |
| **05** | **APC Injection** | **Cross-process execution, remote-side decryption, decoder stub, triple encryption** |
| 06 | Variant Analysis | Same technique, different keys — family clustering |
| 07 | Direct Syscalls | The name is a lie — and that's the lesson |
| 08 | Indirect Syscalls | Call stack forensics, gadget scanning |
| 09 | Anti-Debug | 7 techniques: PEB, NtQueryInfo, RDTSC, hardware breakpoints |
| 10 | Anti-Sandbox | Hardware fingerprinting, weighted scoring |
| 11 | Persistence | Registry Run key, scheduled tasks, COM hijacking |
| 12 | Module Stomping | Overwrite legitimate DLL .text section |
| 13 | Sleep Obfuscation | Encrypt payload during sleep |
| 14 | Combined Loader | 8-layer evasion stack |
| 15 | C2 Agent | Full command-and-control with encrypted HTTPS beaconing |

---

## Safety

> **EDUCATIONAL USE ONLY**

- This binary is a proof-of-concept for authorized security training, research, and CTF competitions
- **Payload**: Injects `MessageBox("GoodBoy")` into charmap.exe — harmless dialog, then exits
- The injector process exits immediately after injection — charmap.exe shows the dialog
- **WRITE** code on your host machine. **EXECUTE** only in isolated VMs
- **This binary creates a child process** (charmap.exe) — be aware of this in sandbox environments

**Do NOT submit this binary to VirusTotal** — doing so trains AV engines against it.

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) recommended |
| Ghidra 11.x | Static analysis / disassembly | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg + ScyllaHide | Dynamic analysis / debugging | [x64dbg.com](https://x64dbg.com/) |
| Python 3.10+ | Crypto analysis, detection scripts | [python.org](https://python.org/) |
| Process Monitor | Cross-process activity monitoring | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) |
| Process Hacker | Memory inspection of injected process | [GitHub](https://github.com/processhacker/processhacker) |

**Recommended VM Configuration**:
- 4+ CPU cores, 8+ GB RAM, 100+ GB disk
- Let the VM run for 5+ minutes before executing (KUSER_SHARED_DATA uptime gate)
- `charmap.exe` must exist at `C:\Windows\System32\charmap.exe` (present on all standard Windows installs)

---

## About the Goodboy Framework

A comprehensive malware development & analysis course with:
- **15 progressive stages** from basic loader to full C2 agent
- **Dual perspective** — every technique taught from both offense and defense
- **Empirical AV/ML evasion data** from testing against 76+ antivirus engines

All 15 binaries achieved 0/76 on VirusTotal.

---

## License

This material is provided for educational purposes in authorized security training, research, penetration testing, and CTF competitions. Not for unauthorized access or operational deployment against systems without explicit written permission.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
