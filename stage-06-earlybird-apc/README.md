# Stage 06: Variant Analysis — Same Technique, Different Keys

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

A **variant** of Stage 05 — same Early Bird APC injection, same decoder stub, same triple encryption. Different keys, different target (`notepad.exe` instead of `charmap.exe`), different VT detection profile.

The educational purpose: **variant analysis** — the skill of recognizing shared code patterns across different binaries in the same malware family. This is what separates junior analysts from senior threat intelligence professionals.

- Same `inject_with_decoder()` from common library
- Different AES_KEY (32 bytes), different INNER_KEY (16 bytes), different target process
- **1/76 VT** — only ESET Agent.ION detects this variant. CrowdStrike and Elastic (which flagged Stage 05 at 3/76) do NOT flag Stage 06

**This binary achieved 0/76 on VirusTotal** (March 11, 2026 — the first Goodboy binary confirmed clean).

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| How simple parameter changes produce different VT scores | Family clustering: identifying shared code across variants |
| Variant generation as an operational workflow | Writing YARA rules that catch ALL variants, not just one |
| Why ML classifiers match on aggregate features, not just APIs | BinDiff/Diaphora for structural comparison |
| Per-engagement key rotation | Threat intelligence: "same actor, different tools" attribution |

---

## What's New vs Stage 05

| Aspect | Stage 05 | Stage 06 |
|--------|----------|----------|
| Target | charmap.exe | **notepad.exe** |
| AES_KEY | `0xb7, 0x3a, 0x91...` | **`0xe4, 0x2b, 0x87...`** |
| INNER_KEY | `0xd1, 0x7b, 0xe3...` | **`0x8a, 0x3e, 0xf7...`** |
| Intermediate first byte | `0x38` | **`0x63`** |
| VT Score | 3/76 (ESET + CrowdStrike + Elastic) | **1/76 (ESET only)** |
| Binary size | ~279 KB | **~268 KB** |
| Injection technique | Early Bird APC | **Identical** |
| Decoder stub | 41-byte XOR | **Identical** |
| Position mask | index×0x37+0x5A | **Identical** |

Same technique. Different fingerprint. Different detection results.

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,191 lines** — variant analysis methodology, family clustering exercises, cross-variant YARA rules, BinDiff comparison, detection invariant identification |
| `earlybird-apc.exe` | The compiled binary (~268 KB, Rust, PE64) — compare side-by-side with Stage 05's `svcctl.exe` |

---

## Quick Start

1. **Complete Stage 05 first** — this stage assumes you understand APC injection
2. **Download** both `svcctl.exe` (Stage 05) and `earlybird-apc.exe` (Stage 06)
3. **Compare** the two binaries in Ghidra (Section 1: Side-by-Side Analysis)
4. **Identify** what's shared vs what's different (Section 2: Variant Diffing)
5. **Write** a YARA rule that catches BOTH variants (Section 3: Cross-Variant Detection)
6. **Cluster** the two binaries into one family using structural analysis (Section 4)

---

## The Variant Analysis Challenge

```
Given TWO binaries:
  svcctl.exe      (Stage 05, 279 KB, injects into charmap.exe)
  earlybird-apc.exe (Stage 06, 268 KB, injects into notepad.exe)

Answer:
  1. Are these the same malware family?
  2. What's shared? (technique, stub, common library code)
  3. What's different? (keys, target, size, VT score)
  4. Write ONE detection rule that catches BOTH
  5. Predict: if a third variant appears, what will change?
```

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (uses `common` library — same as Stage 05) |
| Injection Method | Early Bird APC (T1055.004) — identical to Stage 05 |
| Target Process | `C:\Windows\System32\notepad.exe` (CREATE_SUSPENDED) |
| Encryption | 3 layers: position mask → RC4 "AES" → remote XOR (same structure, different keys) |
| Decoder Stub | 41 bytes — identical to Stage 05 |
| Anti-Sandbox | KUSER_SHARED_DATA uptime (same as Stage 05) |
| Binary Size | ~268 KB |
| Binary Name | `earlybird-apc.exe` |
| VT Score | 0/76 achieved → 1/76 current (ESET Agent.ION only) |

---

## Course Progression

This is **Stage 06** of 15:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06 (this)   Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: Injects `MessageBox("GoodBoy")` into notepad.exe — harmless dialog
- The injector exits immediately; notepad.exe shows the dialog and remains running
- **This binary spawns a child process** (notepad.exe) — be aware in sandbox environments
- **EXECUTE** only in isolated VMs

---

## Requirements

Same as Stage 05, plus:
- Stage 05's `svcctl.exe` binary (for side-by-side comparison)
- BinDiff or Diaphora (optional, for structural diffing)

---

## About the Goodboy Framework

A comprehensive malware development & analysis course. All 15 binaries achieved 0/76 on VirusTotal.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
