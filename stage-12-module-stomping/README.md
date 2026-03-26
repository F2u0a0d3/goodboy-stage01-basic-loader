# Stage 12: Module Stomping — Shellcode in a Signed DLL's .text Section

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first stage with **image-backed execution** — shellcode lives inside a loaded DLL's .text section, making it appear as legitimate module code to memory scanners. The technique:

```
LoadLibraryA("clbcatq.dll")  → Load Microsoft-signed sacrificial DLL
PE parse: find .text section  → Inline raw pointer arithmetic
VirtualProtect(RX → RW)      → Make .text writable
Copy shellcode to entry point → CFG-valid target (AddressOfEntryPoint)
VirtualProtect(RW → RX)      → Restore execute permissions
CreateThread(entry_point)     → Execute from DLL's address space
```

Memory scanners see: MEM_IMAGE region backed by `clbcatq.dll` (Microsoft-signed). Shellcode hides in plain sight.

Plus 7 evasion gates (benign checks, GUI lifecycle, anti-debug, anti-sandbox) inherited from Stages 09-10.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Module stomping with CFG-valid entry point targeting | pe-sieve / Moneta memory integrity scanning |
| Inline PE parsing (raw pointer arithmetic) | YARA rules for PE parsing + apihash combo |
| Sacrificial DLL selection criteria | Sysmon Event 7 DLL load anomaly detection |
| Why .text zeroing is harmful (destroys DLL cleanup) | 4-layer defense hardening guide |
| Apihash for all stomping APIs (zero IAT footprint) | Python: module integrity comparator, DLL scanner |

---

## What's New vs Stages 01-11

| Concept | Stages 01-11 | Stage 12 |
|---------|-------------|----------|
| Memory source | VirtualAlloc (private, no backing) or HeapCreate | **LoadLibraryA + .text overwrite (image-backed)** |
| Memory scanner evasion | None — private regions are trivially flagged | **MEM_IMAGE backed by signed DLL passes VAD scans** |
| PE parsing | Never used (except export table in Stage 04) | **Full inline PE header parsing: MZ→PE→sections→.text** |
| CFG compliance | Not addressed | **Entry point targeting (AddressOfEntryPoint in CFG bitmap)** |
| Sacrificial DLL | N/A | **clbcatq.dll (COM+ catalog, Microsoft-signed, obscure)** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,230 lines** — Module stomping deep dive, PE parsing, CFG targeting, 2 YARA rules, Sigma rule, 3 Python scripts, defense hardening, adversarial challenges |
| `module-stomping.exe` | The compiled binary (~365 KB, Rust, PE64) — stomps clbcatq.dll's entry point |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (uses common library for anti-debug + apihash) |
| Technique | Module stomping: LoadLibraryA → PE parse → .text overwrite at entry point |
| Sacrificial DLL | clbcatq.dll (COM+ Catalog, Microsoft-signed) |
| CFG Safety | Thread starts at AddressOfEntryPoint (in CFG valid targets bitmap) |
| API Resolution | All 5 stomping APIs via apihash (LoadLibraryA, VirtualProtect, CreateThread, Wait, Close) |
| Anti-Debug | 7 techniques via common library (from Stage 09) |
| Sandbox Detection | 5 hardware checks, threshold ≥ 3 (from Stage 10) |
| Shellcode | 302-byte MessageBox("GoodBoy"), XOR encrypted |
| Binary Size | ~365 KB |

---

## Course Progression

This is **Stage 12** of 15 — a **HARD** stage.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12 (this)
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless
- **DLL**: clbcatq.dll is loaded into own process (no system modification)
- **EXECUTE** only in isolated VMs

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
