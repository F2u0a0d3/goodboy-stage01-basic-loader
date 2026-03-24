# Goodboy Framework

A 15-stage progressive Windows malware development & analysis course written in Rust. Every technique taught from both **red team** (offense) and **blue team** (defense) perspectives. All 15 binaries achieved **0/76 on VirusTotal**.

---

## What This Is

A hands-on course that takes you from "what is a shellcode loader" to "build a full C2 agent" — with empirical AV/ML evasion data at every step.

Each stage adds one new offensive technique on top of the previous. Each Learning Path documents:
- **How** the technique works (theory + code)
- **How to detect** it (YARA, Sigma, ETW, memory forensics)
- **How to break** your own detection (adversarial thinking)
- **What happened on VirusTotal** (real submission data, sample burning forensics)

**This is not theory.** Every binary was tested against 76+ AV engines. Every detection claim has a VT hash to prove it.

---

## The 15 Stages

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

| Stage | Technique | What You'll Learn | Lines | Status |
|-------|-----------|-------------------|-------|--------|
| [**01**](stage-01-basic-loader/) | **Basic Loader** | XOR decrypt, PEB-walk API hashing, VirtualAlloc->VirtualProtect->CreateThread, anti-sandbox, YARA/Sigma rules | 1,649 | Released |
| [**02**](stage-02-xor-loader/) | **XOR Cryptanalysis** | Known-plaintext attack, Index of Coincidence, entropy classification, memory scrubbing, VT Submission Paradox | 1,237 | Released |
| [**03**](stage-03-aes-loader/) | **AES + Jigsaw** | RC4 stream cipher, entropy normalization via payload fragmentation, nonce/integrity verification, multi-scale entropy detection | 1,492 | Released |
| [**04**](stage-04-api-hashing/) | **API Hashing** | Additive hash deep dive, cross-DLL resolution (kernel32+user32+ntdll), rainbow tables, gs:[0x60] detection invariant | 987 | Released |
| [**05**](stage-05-process-inject/) | **APC Injection** | Early Bird APC, cross-process execution, remote-side decryption, decoder stub, triple encryption | 1,133 | Released |
| [**06**](stage-06-earlybird-apc/) | **Variant Analysis** | Same technique different keys, family clustering, cross-variant YARA, invariant detection | 1,191 | Released |
| [**07**](stage-07-direct-syscalls/) | **Direct Syscalls** | SSN resolution, inline syscall instruction, hook bypass, call stack forensics, evasion trade-off | 768 | Released |
| 08 | Indirect Syscalls | Call stack forensics, gadget scanning, SSN resolution | — | Planned |
| 09 | Anti-Debug | 7 techniques: PEB, NtQueryInfo, RDTSC, hardware breakpoints, process enumeration | — | Planned |
| 10 | Anti-Sandbox | Hardware fingerprinting, weighted scoring, VM evasion | — | Planned |
| 11 | Persistence | Registry Run key, scheduled tasks, COM hijacking | — | Planned |
| 12 | Module Stomping | Overwrite legitimate DLL .text section, CFG-valid execution | — | Planned |
| 13 | Sleep Obfuscation | Encrypt payload during sleep, 95% scanner miss rate | — | Planned |
| 14 | Combined Loader | 8-layer evasion stack, MBA obfuscation, multi-phase chain | — | Planned |
| 15 | C2 Agent | Full command-and-control with encrypted HTTPS beaconing | — | Planned |

---

## How Each Stage Works

Every stage folder contains:

| File | What It Is |
|------|------------|
| `*.exe` | The compiled binary (~280-300 KB, Rust, PE64) — open in Ghidra/x64dbg |
| `README.md` | Quick start guide, technical details, gate architecture |
| `LEARNING_PATH.md` | **The main content** — 1,000-1,600 lines of guided analysis with theory, exercises, Python scripts, detection rules, and adversarial challenges |

**No source code is included.** You reverse-engineer the binary using the Learning Path as your guide — the same way you'd analyze real malware.

---

## Quick Start

1. **Set up a Windows 10/11 x64 VM** ([FlareVM](https://github.com/mandiant/flare-vm) recommended)
2. **Install tools**: Ghidra 11.x, x64dbg + ScyllaHide, Python 3.10+, PE-bear
3. **Start with Stage 01** — open the Learning Path and follow along
4. **Work sequentially** — each stage builds on concepts from the previous one

**VM Configuration** (required for sandbox detection gates to pass):
- 4+ CPU cores, 8+ GB RAM, 100+ GB disk
- Let the VM run for 30+ minutes before executing binaries
- Screen resolution 1920x1080 or higher

---

## What Makes This Different

### Dual Perspective

Every technique is taught from both sides. You don't just learn to build a loader — you learn to detect it, then learn to break your own detection.

```
Red Team Exercise:                    Blue Team Exercise:
  Build an RC4-encrypted loader         Write a YARA rule for the permutation map
  Fragment payload with jigsaw          Build a multi-scale entropy anomaly detector
  Normalize .rdata entropy              Identify the crypto mislabeling trap
```

### Empirical Evasion Data

This isn't "my AV didn't flag it." Every binary was submitted to VirusTotal and tested against all 76 engines. The Learning Paths document:

- Exact VT scores across multiple submission rounds
- Which engines detected what, and why
- The **sample burning** phenomenon — how the act of testing trains AV against you
- Per-engine bypass techniques with proof (ESET Agent.ION, CrowdStrike ML, Huorong heuristics)

### Production-Grade Code

The binaries are compiled Rust (not toy C demos), with:
- Control Flow Guard (CFG)
- PE metadata spoofing (Authenticode signature cloning)
- Rich header re-keying
- Multiple evasion gates (environment, hardware, anti-debug)
- Real shellcode execution (MessageBox("GoodBoy") as proof)

---

## The Arms Race

```
Stage 01: You build a basic loader
  → AV can signature the XOR key in .rdata

Stage 02: You change the key
  → Blue team breaks it with known-plaintext attack (key doesn't matter)

Stage 03: You switch to RC4 + jigsaw fragmentation
  → Blue team detects the permutation map pattern in .rdata

Stage 04: You hide API resolution behind custom hashing
  → Blue team builds rainbow tables to reverse all hash constants

Stage 07: You bypass ntdll hooks with syscalls
  → Blue team detects the syscall instruction itself

Stage 09: You add anti-debug
  → Sandboxes still detonate the binary

Stage 10: You add hardware-based sandbox detection
  → Memory scanners catch the decrypted payload

Stage 12-13: You stomp modules + encrypt during sleep
  → Payload is only visible 5% of the time

Stage 14: Eight layers stacked together
Stage 15: Full C2 with encrypted HTTPS beaconing
```

Every stage exists because a defender broke the previous one.

---

## Sample Burning — The Hidden Lesson

The most important lesson in this course isn't a technique — it's an operational reality:

> **The act of testing IS the burn.** Every VirusTotal submission feeds the sample to 76+ AV vendors. They use YOUR submissions to train their ML classifiers. You can't check if your binary is clean without making it dirty.

Stage 03 was the canary that revealed this. It achieved 0/76, then ESET created `Agent.ION` specifically from the submission data between March 1-9, 2026. The binary hadn't changed — but the AV had learned from it. This pattern then repeated across all 15 stages.

The Learning Paths document the full forensic timeline of each binary's VT history.

---

## Course Statistics

| Metric | Value |
|--------|-------|
| Stages | 15 (7 released, 8 planned) |
| Total learning content | 8,500+ lines (released stages) |
| Exercises | 30+ hands-on (released stages) |
| YARA rules | 6+ (with adversarial countermeasures) |
| Sigma rules | 3+ (behavioral detection) |
| Python scripts | 15+ (solvers, scanners, crypto tools) |
| AV engines tested | 76 |
| Languages | Rust (binaries), Python (tooling) |
| Platform | Windows x64 |

---

## Safety

> **EDUCATIONAL USE ONLY**

- Every binary's payload is `MessageBox("GoodBoy")` — a harmless dialog box
- No network activity, no persistence, no system modifications
- **WRITE** code on your host machine. **EXECUTE** only in isolated VMs
- Do NOT submit binaries to VirusTotal — this trains AV against them (see "sample burning")

This material is for authorized security training, research, penetration testing, and CTF competitions. Not for unauthorized access or operational deployment against systems without explicit written permission.

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) |
| Ghidra 11.x | Static analysis | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg + ScyllaHide | Dynamic analysis | [x64dbg.com](https://x64dbg.com/) |
| Python 3.10+ | Scripts and solvers | [python.org](https://python.org/) |
| PE-bear | PE structure viewer | [GitHub](https://github.com/hasherezade/pe-bear) |

---

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
