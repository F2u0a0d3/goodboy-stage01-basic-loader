# Stage 08: Indirect Syscalls — Gadget Scanning and Call Stack Evasion

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The evolution of Stage 07's direct syscalls. This binary eliminates **both** detection signals from direct syscalls:
- **Zero `syscall` instructions in .text** — the opcode only exists inside ntdll's gadget
- **Legitimate call stack** — return address points to ntdll, not the binary's .text section
- Scans ntdll's `.text` section for a `syscall;ret` (`0F 05 C3`) **gadget**
- Uses `CALL gadget` instead of inline `syscall` — execution flows through ntdll
- All 5 Nt* operations via indirect syscall (no kernel32 dependency for any offensive API)
- Self-contained (no `common` library)

**VT Score: 3/76** — ESET Agent.ION + AVG/Avast MalwareX-gen. Google and Ikarus (which caught Stage 07) are **gone** — the `0F 05`-in-.text detection no longer triggers.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Gadget scanning: finding `syscall;ret` inside ntdll | YARA for gadget scanner code patterns |
| CALL-based indirection (stack offset adjustment) | Gadget address validation: CALL to mid-function = suspicious |
| Zero `syscall` in .text — defeats Stage 07 YARA | ETW still sees everything (kernel-level, unavoidable) |
| All 5 syscalls via single ntdll gadget | Timing analysis: `call;ret` overhead is measurable |
| No kernel32 needed at all | Comparative: same 3/76 but different 3 engines than Stage 07 |

---

## What's New vs Stage 07

| Aspect | Stage 07 (Direct) | Stage 08 (Indirect) |
|--------|-------------------|---------------------|
| `syscall` in .text | 3 instances | **0 instances** |
| Call stack | .text return addr (anomalous) | **ntdll return addr (legitimate)** |
| Google/Ikarus detection | Yes (instruction scan) | **No — eliminated** |
| AVG/Avast detection | No | Yes (ML returned) |
| Gadget scanner | Not needed | **Scans ntdll for 0F 05 C3** |
| Stack arg offset | `[rsp+0x28]` | **`[rsp+0x20]`** (CALL pushes 8 bytes) |
| kernel32 dependency | Yes (wait/close) | **None — all via ntdll** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **527 lines** — gadget scanning, CALL offset adjustment, detection comparison, adversarial challenges |
| `indirect-syscalls.exe` | The compiled binary (~293 KB, Rust, PE64) — zero `0F 05` in .text |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Syscall Method | Indirect — `CALL` to ntdll `syscall;ret` gadget |
| Gadget | `0F 05 C3` found by scanning ntdll's .text section |
| SSN Resolution | Runtime reading from ntdll stubs (same as Stage 07) |
| Nt* APIs | NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject, NtClose |
| kernel32 dependency | None — all operations via ntdll indirect syscalls |
| Shellcode | 302-byte MessageBox("GoodBoy"), XOR encrypted |
| Memory | W^X (RW → RX via NtProtectVirtualMemory indirect syscall) |
| Binary Size | ~293 KB |
| VT Score | 3/76 (ESET + AVG + Avast) |

---

## Course Progression

This is **Stage 08** of 15. Stages 07-08 form a pair: direct → indirect syscalls.

| Stage | Technique | Detection Surface |
|-------|-----------|-------------------|
| 07 | Direct Syscalls | `0F 05` in .text + anomalous call stack |
| **08** | **Indirect Syscalls** | **Gadget scanner pattern + mid-function CALL target** |

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless dialog
- **EXECUTE** only in isolated VMs

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course. All binaries achieved 0/76 on VirusTotal.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
