# Stage 10: Anti-Sandbox — Hardware Fingerprinting with Weighted Scoring

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first stage with **automated environment detection** — 5 hardware-metric checks that detect sandbox VMs through resource fingerprinting. Uses a weighted scoring system (threshold ≥ 3) instead of binary pass/fail:

| # | Check | Threshold | Sandbox Score | Real System |
|---|-------|-----------|---------------|-------------|
| 1 | CPU Cores | < 2 | +1 (1 core) | 0 (8+ cores) |
| 2 | Total RAM | < 4 GB | +1 (2 GB) | 0 (16+ GB) |
| 3 | Disk Size | < 60 GB | +1 (40 GB) | 0 (500+ GB) |
| 4 | System Uptime | < 30 min | +1 (fresh boot) | 0 (hours/days) |
| 5 | Screen Resolution | < 800×600 | +1 (minimal) | 0 (1920×1080) |

Plus 7 anti-debug checks (from Stage 09) and GUI window lifecycle. Self-contained (no `common` library).

**VT Score: 0/76** — achieved 2026-03-12.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Hardware-metric sandbox detection (5 checks) | VM hardening checklist to defeat each check |
| Weighted scoring vs. binary pass/fail | YARA rules for system info API clusters |
| Why string-based VM detection is counterproductive | Sigma rules for sandbox fingerprinting behavior |
| CFG-safe API imports vs. GetProcAddress resolution | The "unfakeable check" problem (CPUID, timing) |
| Scoring threshold calibration (3 = sweet spot) | How to observe sandbox scores in x64dbg |
| Sandbox lifecycle and time-pressure exploits | Sleep acceleration and cursor movement detection |

---

## What's New vs Stages 01-09

| Concept | Stages 01-09 | Stage 10 |
|---------|-------------|----------|
| Sandbox detection | No checks (01-08), simple score (09) | **5 hardware checks with (bool, score) return** |
| Scoring system | Binary pass/fail | **Weighted threshold (≥ 3 of 5)** |
| System info APIs | Never used directly | **GetSystemInfo, GlobalMemoryStatusEx, GetDiskFreeSpaceExW, GetTickCount64, GetSystemMetrics** |
| VM detection strings | N/A | **Intentionally avoided** (strings = AV signatures) |
| Anti-debug | 7 checks in Stage 09 | **Inherited, same 7 checks** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,008 lines** — 5 check deep dives, VM artifact reference, sandbox hardening guide, scoring calibration, YARA/Sigma rules, adversarial thinking challenges |
| `anti-sandbox.exe` | The compiled binary (~264 KB, Rust, PE64) — exits silently in default sandbox VMs |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Sandbox Detection | 5 hardware checks: CPU, RAM, disk, uptime, screen (threshold ≥ 3) |
| Anti-Debug | 7 techniques: PEB×2, NtQIP×3, RDTSC, HW BP (from Stage 09) |
| API Resolution | Additive hash PEB walk (kernel32 + ntdll) |
| GUI Lifecycle | RegisterClassW + CreateWindowExW + message pump (behavioral camouflage) |
| Shellcode | 302-byte MessageBox("GoodBoy"), XOR encrypted |
| Memory | W^X discipline (RW → RX) |
| Binary Size | ~264 KB |
| VT Score | 0/76 |

---

## Course Progression

This is **Stage 10** of 15 — a **HARD** stage.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10 (this)
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless
- **EXECUTE** only in isolated VMs
- Sandbox checks exit silently — use x64dbg + ScyllaHide to bypass for analysis

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course. All binaries achieved 0/76 on VirusTotal.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
