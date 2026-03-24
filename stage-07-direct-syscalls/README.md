# Stage 07: Direct Syscalls — Bypassing Userland Hooks

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first stage to use the `syscall` instruction directly — bypassing kernel32, kernelbase, AND ntdll function hooks entirely. The binary:
- Resolves **System Service Numbers (SSNs)** by reading ntdll stub bytes at runtime
- Detects **EDR hooks** by validating the expected stub prologue (`4C 8B D1 B8`)
- Issues the `syscall` instruction from its own **.text section** via inline assembly
- Uses a **hybrid architecture**: direct syscalls for offensive APIs (alloc, protect, thread), kernel32 PEB walk for benign APIs (wait, close)
- Self-contained (no `common` library dependency)

**VT Score: 3/76** — ESET Agent.ION (sample-burned) + Google Detected + Ikarus Trojan.Win64.Crypt. The `syscall` instruction in .text is the detection signal — the fundamental trade-off of direct syscalls.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| SSN resolution from ntdll stub bytes (HellsGate technique) | YARA rule for `syscall` (0F 05) in non-ntdll .text sections |
| Hook detection via stub byte validation | Call stack analysis: return address in .text = direct syscall |
| Inline `syscall` assembly wrappers (6/5/11-arg Nt* functions) | ETW Threat Intelligence: kernel-level detection that sees ALL syscalls |
| Hybrid design: syscalls for offensive, kernel32 for benign | YARA rule for SSN reading pattern (stub byte checks in code) |
| The evasion trade-off: hook bypass vs new detection surface | Empirical VT data: same 3/76 score, completely different engines |

---

## What's New vs Stages 01-06

| Concept | Stages 01-06 | Stage 07 |
|---------|-------------|----------|
| API calls | Through kernel32/ntdll function pointers | **Direct `syscall` instruction — never calls ntdll** |
| SSN awareness | Stage 04 resolved ntdll exports but never read SSNs | **Reads SSN from stub bytes (`4C 8B D1 B8 XX XX`)** |
| Hook detection | None | **Validates stub prologue — returns None if hooked** |
| Hook bypass | No — all calls go through hookable ntdll | **Yes — `syscall` in .text skips ntdll entirely** |
| Call stack | Normal (ntdll return address) | **Anomalous (.text return address — detection signal)** |
| Detection engines | AVG/Avast (ML classifiers) | **Google/Ikarus (instruction pattern scanners)** |
| MITRE | T1620 (Stages 01-04), T1055.004 (05-06) | **T1562.001 (Impair Defenses: hook bypass)** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **767 lines** — SSN resolution, syscall wrappers, call stack forensics, ETW detection, evasion trade-off data, adversarial challenges |
| `direct-syscalls.exe` | The compiled binary (~279 KB, Rust, PE64) — contains actual `syscall` instructions in .text |

---

## Quick Start

1. **Complete Stages 04-06 first** — this stage assumes PEB walking, export tables, and Nt* API familiarity
2. **Download** `direct-syscalls.exe` and `LEARNING_PATH.md`
3. **Search** for `0F 05` in the .text section with Ghidra — you'll find 3 `syscall` instructions
4. **Trace** SSN resolution in Section 2 (reading ntdll stub bytes)
5. **Understand** the syscall wrappers in Section 3 (inline assembly for 6/5/11-arg functions)
6. **Write** detection rules in Section 5 (YARA + call stack analysis + ETW)

---

## The Hybrid Architecture

```
direct-syscalls.exe

  ntdll path (direct syscall):         kernel32 path (PEB walk):
  ┌──────────────────────────┐        ┌──────────────────────────┐
  │ find_module(ntdll)       │        │ resolve_api(kernel32,    │
  │ find_export(NtAllocVM)   │        │   WaitForSingleObject)   │
  │ read_ssn() → SSN         │        │ → function pointer       │
  │                          │        │                          │
  │ mov r10, rcx             │        │ wt(handle, INFINITE)     │
  │ mov eax, SSN             │        │ → kernel32 → ntdll       │
  │ syscall  ← IN .TEXT      │        │ → syscall (in ntdll)     │
  │                          │        │                          │
  │ Bypasses ALL hooks       │        │ Goes through hooks       │
  │ Anomalous call stack     │        │ Normal call stack        │
  └──────────────────────────┘        └──────────────────────────┘

  3 direct syscalls:                   2 kernel32 calls:
  • NtAllocateVirtualMemory (RW)       • WaitForSingleObject
  • NtProtectVirtualMemory (RX)        • CloseHandle
  • NtCreateThreadEx
```

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Syscall Method | Inline `syscall` instruction via `core::arch::asm!` |
| SSN Resolution | Runtime reading from ntdll stub bytes (HellsGate approach) |
| Hook Detection | Validates `4C 8B D1 B8` prologue — exits if hooked |
| Nt* APIs (direct syscall) | NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx |
| kernel32 APIs (PEB walk) | WaitForSingleObject, CloseHandle |
| Hash Algorithm | Additive hash (seed `0x1F2E3D4C`, mul `0x1003F`) — same as all stages |
| Shellcode | 302-byte MessageBox("GoodBoy") + ExitThread, XOR encrypted |
| Memory | W^X discipline (RW → RX via NtProtectVirtualMemory syscall) |
| Binary Size | ~279 KB |
| VT Score | 3/76 (ESET + Google + Ikarus) |

---

## The Evasion Trade-Off

| Approach | Score | Why |
|----------|-------|-----|
| 5 direct syscalls | 4/76 | Too many `0F 05` in .text |
| 5 syscalls + opt-level=2 | 5/76 | Google added |
| **3 syscalls + kernel32 wait/close** | **3/76** | **Optimal — fewer syscalls, benign call stack for wait/close** |
| 3x int 0x2E (legacy) | 6/76 | Legacy interrupt path is MORE suspicious |

Same total score as Stages 01-04 (3/76) but completely different engines: Google+Ikarus (instruction scanners) instead of AVG+Avast (ML classifiers).

---

## Course Progression

This is **Stage 07** of 15:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07 (this)   Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless dialog, then exits
- No network activity, no persistence, no system modifications
- **EXECUTE** only in isolated VMs

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) recommended |
| Ghidra 11.x | Find `0F 05` syscall instructions in .text | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg + ScyllaHide | Trace SSN resolution and syscall execution | [x64dbg.com](https://x64dbg.com/) |
| Python 3.10+ | SSN dumping scripts, detection tools | [python.org](https://python.org/) |

---

## About the Goodboy Framework

A comprehensive malware development & analysis course. All 15 binaries achieved 0/76 on VirusTotal.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
