# Stage 11: Persistence — Registry Run Key with Evasion-Gated Execution

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first stage with **persistence** — the binary writes itself to the HKCU Registry Run key so it survives reboots. After execution, it **cleans up** (deletes the key) to demonstrate the full lifecycle:

```
Set Run key → Execute shellcode → Delete Run key
```

| Step | What Happens |
|------|-------------|
| 1 | Registry path built at runtime from u16 hex segments (breaks string signatures) |
| 2 | `RegOpenKeyExW` + `RegSetValueExW` → writes own path to `HKCU\...\Run\StartupOptSvc` |
| 3 | XOR decrypt → VirtualAlloc → VirtualProtect → CreateThread → MessageBox |
| 4 | `RegDeleteValueW` → cleans up the Run key (demo only) |

Plus 7 evasion gates (benign checks, GUI lifecycle, anti-debug, anti-sandbox) inherited from Stages 09-10.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Registry Run key persistence (HKCU vs HKLM trade-offs) | Sysmon EventID 13 for registry monitoring |
| Registry path obfuscation via u16 hex segments + black_box | Sigma rule for Run key from unsigned binaries |
| Direct IAT imports vs apihash for ML evasion | YARA rule for registry + execution API cluster |
| Why aggregate persistence code mass triggers ML | PowerShell Run key auditor with signature checks |
| Demo set→execute→cleanup lifecycle | Python registry auditor + path deobfuscator |

---

## What's New vs Stages 01-10

| Concept | Stages 01-10 | Stage 11 |
|---------|-------------|----------|
| Persistence | None — single execution only | **Registry Run key (HKCU)** |
| Registry APIs | Never used | **RegOpenKeyExW, RegSetValueExW, RegDeleteValueW** |
| String obfuscation | Not needed | **u16 hex array segments with black_box()** |
| Execution APIs | Apihash (01-09) or HeapCreate (10) | **Direct IAT imports** (VirtualAlloc/VirtualProtect/CreateThread) |
| Cleanup | None | **Post-execution registry key deletion** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,371 lines** — Registry persistence deep dive, path obfuscation, 2 YARA rules, Sigma rule, 3 Python scripts, Sysmon config, defense hardening guide, 10 exercises, adversarial challenges |
| `persistence-demo.exe` | The compiled binary (~367 KB, Rust, PE64) — sets Run key, executes, cleans up |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (uses common library for anti-debug + benign code mass) |
| Persistence | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\StartupOptSvc |
| Path Obfuscation | u16 hex segments with core::hint::black_box() barriers |
| Execution | VirtualAlloc(RW) → VirtualProtect(RX) → CreateThread (direct IAT) |
| Anti-Debug | 7 techniques via common library (from Stage 09) |
| Sandbox Detection | 5 hardware checks, threshold ≥ 3 (from Stage 10) |
| Shellcode | 302-byte MessageBox("GoodBoy"), XOR encrypted |
| Cleanup | RegDeleteValueW removes Run key after demo |
| Binary Size | ~367 KB |

---

## Course Progression

This is **Stage 11** of 15 — a **MEDIUM** stage.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11 (this)   Stage 10
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless
- **Persistence**: Sets then **immediately deletes** the Run key (demo lifecycle)
- **EXECUTE** only in isolated VMs
- No permanent system modifications

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
