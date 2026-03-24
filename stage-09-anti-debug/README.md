# Stage 09: Anti-Debug — 7 Techniques to Detect and Evade Analysis

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first stage with a full **anti-debug gauntlet** — 7 techniques that detect debuggers, timing anomalies, and hardware breakpoints. The binary exits silently if ANY check detects analysis:

| # | Technique | What It Detects |
|---|-----------|----------------|
| 1 | PEB.BeingDebugged | User-mode debugger attached |
| 2 | PEB.NtGlobalFlag | Debug heap flags set at process creation |
| 3 | NtQIP(ProcessDebugPort) | Kernel debug port active |
| 4 | NtQIP(ProcessDebugObjectHandle) | Debug object exists |
| 5 | NtQIP(ProcessDebugFlags) | NoDebugInherit flag cleared |
| 6 | RDTSC Timing | Single-stepping inflates CPU cycle count |
| 7 | Hardware Breakpoints | DR0-DR3 registers non-zero |

Plus GUI window lifecycle for behavioral camouflage. Self-contained (no `common` library).

**VT Score: 3/76** — ESET Agent.ION + Google Detected + Ikarus Trojan.Win64.Crypt.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| 7 anti-debug techniques with implementation details | ScyllaHide bypass table for each technique |
| PEB-based checks (BeingDebugged, NtGlobalFlag) | Manual bypass in x64dbg for each check |
| Kernel-level queries (NtQIP × 3 info classes) | YARA rules for NtQIP info class constants |
| RDTSC timing attack against single-stepping | YARA for dual RDTSC instructions |
| Hardware breakpoint detection (DR0-DR3) | Identifying which check catches your debugger |
| Cross-DLL resolution (kernel32 + ntdll) | The arms race: every check has a counter |

---

## What's New vs Stages 01-08

| Concept | Stages 01-08 | Stage 09 |
|---------|-------------|----------|
| Anti-debug | PEB.BeingDebugged only (1 check) | **7 checks: PEB×2, NtQIP×3, RDTSC, HW BP** |
| NtQIP usage | Resolved but not called (Stage 04) | **Called with 3 info classes (7, 0x1E, 0x1F)** |
| RDTSC | Never used | **Timing check detects single-stepping** |
| HW BP detection | Never | **DR0-DR3 via GetThreadContext** |
| ScyllaHide | Mentioned | **Full bypass table + exercises** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **420 lines** — 7 technique deep dives, ScyllaHide bypass table, YARA rules, manual bypass exercises |
| `anti-debug.exe` | The compiled binary (~280 KB, Rust, PE64) — exits silently under debugger without ScyllaHide |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Anti-Debug | 7 techniques: PEB×2, NtQIP×3, RDTSC, HW BP |
| API Resolution | Additive hash PEB walk (kernel32 + ntdll) |
| GUI Lifecycle | RegisterClassW + CreateWindowExW + message pump (behavioral camouflage) |
| Shellcode | 302-byte MessageBox("GoodBoy"), XOR encrypted |
| Memory | W^X discipline (RW → RX) |
| Binary Size | ~280 KB |
| VT Score | 3/76 |

---

## Course Progression

This is **Stage 09** of 15 — the first **HARD** stage.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09 (this)
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless
- **EXECUTE** only in isolated VMs
- Use ScyllaHide in x64dbg to bypass anti-debug for analysis

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course. All binaries achieved 0/76 on VirusTotal.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
