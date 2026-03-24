# Stage 09: Anti-Debug — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Anti-Debug: 7 Techniques to Detect and Evade Analysis |
| **Level** | Advanced |
| **Estimated Time** | 5-7 hours |
| **Category** | Anti-Analysis / Windows Internals / Detection Engineering |
| **Platform** | Windows x64 |
| **Binary** | `anti-debug.exe` (~280KB, Rust, PE64) |
| **Prerequisites** | Stage 04 (PEB internals), Stage 07-08 (ntdll API resolution) |
| **MITRE ATT&CK** | T1622 (Debugger Evasion), T1106, T1027, T1620 |
| **VT Score** | **3/76** (ESET Agent.ION + Google Detected + Ikarus Trojan.Win64.Crypt) |

### VT Detection Journey

```
 ████████████████████████████████████░░ 3/76  ← CURRENT (with GUI lifecycle)

   ESET Agent.ION        — sample-burned (permanent)
   Google Detected        — anti-debug code patterns
   Ikarus Win64.Crypt     — anti-debug code patterns

 Evasion attempts:
   No GUI lifecycle        → 6/76 (AVG + Avast + ESET + Google + Ikarus + Microsoft)
   With GUI lifecycle      → 3/76 (ESET + Google + Ikarus) ← shipping version
   Without RDTSC check     → 5/76 (worse — RDTSC is benign code mass)
   Without HW BP check     → 5/76 (worse — GetThreadContext is benign code mass)

 THE PARADOX: Removing anti-debug checks INCREASES detection. Anti-debug code
 is considered BENIGN by ML classifiers (DRM, anti-cheat use identical techniques).
 Each removed check reduces benign code mass, tipping the offensive/benign ratio.
```

---

## Why This Stage Exists — The Bridge from Stage 08

Stages 07-08 taught syscall mechanics — bypassing userland hooks. But a determined analyst simply attaches a debugger and steps through the code. No amount of hook evasion matters if someone can set a breakpoint on your decryption routine and dump the plaintext shellcode.

Stage 09 turns the PEB and Nt* APIs you mastered in Stages 04-08 against the analyst. The same structures that provide module lists and syscall numbers also reveal whether a debugger is attached, whether hardware breakpoints are set, and whether the process is being timed.

**7 anti-debug techniques, ordered from simplest to most sophisticated:**

| # | Technique | What It Detects | API/Instruction | Difficulty to Bypass |
|---|-----------|----------------|-----------------|---------------------|
| 1 | PEB.BeingDebugged | User-mode debugger attached | Memory read (PEB+0x02) | Easy (ScyllaHide) |
| 2 | PEB.NtGlobalFlag | Debug heap flags at creation | Memory read (PEB+0xBC) | Easy (ScyllaHide) |
| 3 | ProcessDebugPort | Kernel debug port active | NtQueryInformationProcess(7) | Medium |
| 4 | ProcessDebugObjectHandle | Debug object exists | NtQueryInformationProcess(0x1E) | Medium |
| 5 | ProcessDebugFlags | NoDebugInherit cleared | NtQueryInformationProcess(0x1F) | Medium |
| 6 | RDTSC Timing | Single-stepping inflates cycles | rdtsc instruction | Hard |
| 7 | Hardware Breakpoints | DR0-DR3 registers non-zero | GetThreadContext | Hard |

**What's genuinely new**: Stages 01-08 had a simple PEB.BeingDebugged check (#1 only). Stage 09 adds 6 MORE techniques, including kernel-level queries and CPU-level timing.

### Real-World Context (2025-2026)

- **ScyllaHide** ([x64dbg plugin](https://github.com/x64dbg/ScyllaHide)) — The standard anti-anti-debug tool. Patches PEB fields, hooks NtQueryInformationProcess, intercepts GetThreadContext. Stage 09 teaches what each option does
- **al-khaser** ([GitHub](https://github.com/LordNoteworthy/al-khaser)) — 100+ anti-analysis techniques. Stage 09 implements 7 of the most impactful
- **CheckPoint Anti-Debug Encyclopedia** ([2024](https://anti-debug.checkpoint.com/)) — Comprehensive reference with code for every technique
- **TitanHide** ([GitHub](https://github.com/mrexodia/TitanHide)) — Kernel-level anti-anti-debug. Required when malware uses direct syscalls for NtQIP

---

## Prerequisites

Before starting this module, you should understand:
- PEB structure from Stage 04 (offsets, BeingDebugged at +0x02, Ldr at +0x18)
- NtQueryInformationProcess from ntdll (resolved in Stages 04, 07-08)
- x86-64 registers (general purpose + debug registers DR0-DR7)
- The RDTSC instruction (timestamp counter, `0F 31`)
- Using x64dbg + ScyllaHide

**Software needed**:
- x64dbg + ScyllaHide plugin (critical for this stage)
- Ghidra 11.x
- Python 3.10+
- Process Monitor (optional)

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Implement** 7 anti-debug techniques and explain what each detects
2. **Bypass** each technique using ScyllaHide or manual patches in x64dbg
3. **Explain** why PEB-based checks are easy to bypass but NtQIP checks are harder
4. **Detect** anti-debug code via YARA rules targeting NtQIP info class constants and RDTSC
5. **Understand** RDTSC timing attacks and why single-stepping breaks them
6. **Articulate** the evasion paradox: removing anti-debug checks INCREASES VT detection
7. **Describe** the arms race: for every check, a counter-technique exists

---

## Section 1: Theory — The Three Layers of Anti-Debug

### Layer 1: User-Mode Structure Checks (PEB)

The PEB is in user-mode memory — the process itself can read and write it. This makes PEB-based anti-debug trivially bypassable: any tool that runs in the same process can patch the bytes.

```
PEB Structure (anti-debug relevant offsets on x64):
┌──────────────────────────────────────┐
│ +0x002  BeingDebugged (u8)           │ ← Check 1: 0=not debugged, 1=debugged
│ +0x0BC  NtGlobalFlag (u32)           │ ← Check 2: 0x70 mask = debug heap flags
│ +0x018  Ldr → module list            │   (used for API resolution, not anti-debug)
└──────────────────────────────────────┘
```

**Security model**: These are readable AND writable by the process. An analyst (or ScyllaHide) can zero them before the check runs.

### Layer 2: Kernel-Mode Queries (NtQueryInformationProcess)

NtQueryInformationProcess asks the KERNEL about the process state. The kernel's response reflects actual debugger state, not user-mode structures.

```
NtQueryInformationProcess(handle, info_class, buffer, size, return_length)

Info classes for anti-debug:
┌─────────────────────────────────────────────────────────────┐
│ Class 7  (ProcessDebugPort)         → isize: 0 or port num  │
│ Class 30 (ProcessDebugObjectHandle) → isize: 0 or handle    │
│ Class 31 (ProcessDebugFlags)        → u32: 1=safe, 0=debug  │
└─────────────────────────────────────────────────────────────┘
```

**Security model**: The kernel provides truthful responses. To intercept, ScyllaHide hooks `NtQueryInformationProcess` in ntdll (user-mode). But if the binary uses direct syscalls (Stage 07), the hook is bypassed — the kernel is queried directly.

### Layer 3: CPU-Level Checks (RDTSC, Debug Registers)

These use CPU instructions or registers that the kernel doesn't mediate:

- **RDTSC**: Reads the CPU's cycle counter. Single-stepping adds ~50,000 cycles per instruction (debugger trap overhead). No hook or patch can hide this.
- **DR0-DR3**: x86-64 debug address registers set by hardware breakpoints. Readable via `GetThreadContext`. The values reflect actual CPU state.

**Security model**: The analyst must either avoid triggering the check (don't single-step, don't use HW breakpoints) or intercept the API that reads the state (ScyllaHide hooks `GetThreadContext`).

> **Q1**: Which layer is hardest for an analyst to bypass? Why?

<details>
<summary>Answer</summary>

Layer 2 (kernel queries) is hardest when combined with direct syscalls (Stage 07). The kernel provides truthful data, and direct syscalls bypass user-mode hooks. The analyst needs a kernel driver (TitanHide) to intercept the syscall at the kernel level.

Layer 3 checks are hard to AVOID (don't single-step, don't set HW breakpoints) but easy to BYPASS (hook GetThreadContext, NOP the RDTSC comparison).

Layer 1 is trivially bypassable — any tool can patch PEB bytes.

</details>

---

## Section 2: The 7 Techniques — Deep Dive

### Technique 1: PEB.BeingDebugged (offset +0x02)

```rust
unsafe fn check_peb_being_debugged() -> bool {
    let peb = get_peb();           // gs:[0x60]
    (*peb).being_debugged != 0     // single byte at PEB+0x02
}
```

**Mechanism**: When a debugger attaches via `DebugActiveProcess` or creates the process with `DEBUG_PROCESS`, the kernel sets `PEB.BeingDebugged` to 1. This is the Windows API equivalent — `IsDebuggerPresent()` reads this same byte.

**Detection value**: LOW. Patched by every anti-anti-debug tool. But it's the fastest check (single memory read, no API call, no syscall).

**Bypass**: ScyllaHide → `PEB.BeingDebugged`. Manual: edit byte at PEB+0x02 to 0 in x64dbg memory view.

### Technique 2: PEB.NtGlobalFlag (offset +0xBC on x64)

```rust
unsafe fn check_nt_global_flag() -> bool {
    let peb = get_peb();
    ((*peb).nt_global_flag & 0x70) != 0
}
```

**Mechanism**: When a debugger CREATES the process, the NT heap manager sets three flags:

| Flag | Value | Meaning |
|------|-------|---------|
| FLG_HEAP_ENABLE_TAIL_CHECK | 0x10 | Adds guard bytes after heap allocations |
| FLG_HEAP_ENABLE_FREE_CHECK | 0x20 | Validates freed heap blocks |
| FLG_HEAP_VALIDATE_PARAMETERS | 0x40 | Validates heap API parameters |

Combined mask: 0x10 | 0x20 | 0x40 = **0x70**

**Key difference from BeingDebugged**: NtGlobalFlag is set at process CREATION time. If a debugger creates the process, the flags are set. If the debugger detaches, BeingDebugged resets to 0 but NtGlobalFlag PERSISTS — the heap was already configured.

**Bypass**: ScyllaHide → `NtGlobalFlag`. Manual: set DWORD at PEB+0xBC to 0.

### Exercise 2A: Observe NtGlobalFlag Change (10 min)

1. Launch `anti-debug.exe` normally (double-click). Attach x64dbg AFTER launch
2. In x64dbg command bar: `dump [gs:[60]+BC]` → NtGlobalFlag should be 0
3. Now launch `anti-debug.exe` FROM x64dbg (File → Open)
4. Same command: `dump [gs:[60]+BC]` → NtGlobalFlag will be 0x70

This proves NtGlobalFlag depends on HOW the process was created, not whether a debugger is currently attached.

### Technique 3: NtQueryInformationProcess(ProcessDebugPort = 7)

```rust
unsafe fn check_debug_port(ntqip: NtQipFn) -> bool {
    let mut port: isize = 0;
    ntqip(-1isize as *mut c_void, 7, &mut port as *mut _, 8, null_mut());
    port != 0
}
```

**Mechanism**: The kernel maintains a debug port for each debugged process. `NtQueryInformationProcess` with class 7 returns this port. Non-zero = debugger attached.

**Why harder to bypass**: This queries the KERNEL, not user-mode PEB. ScyllaHide must hook `NtQueryInformationProcess` in ntdll to intercept the response. If the binary uses Stage 07's direct syscalls for this call, the hook is bypassed entirely.

### Technique 4: ProcessDebugObjectHandle (0x1E)

```rust
unsafe fn check_debug_object(ntqip: NtQipFn) -> bool {
    let mut obj: isize = 0;
    let status = ntqip(-1isize as *mut c_void, 0x1E, &mut obj as *mut _, 8, null_mut());
    status == 0  // STATUS_SUCCESS means debug object EXISTS
}
```

**Mechanism**: When a debugger is attached, the kernel creates a debug object. Querying for its handle returns STATUS_SUCCESS only if the object exists. No debugger = STATUS_PORT_NOT_SET (failure).

**Subtlety**: The check is on the STATUS code, not the handle value. Even if ScyllaHide zeroes the output buffer, the STATUS return from the kernel reveals the truth.

### Technique 5: ProcessDebugFlags (0x1F)

```rust
unsafe fn check_debug_flags(ntqip: NtQipFn) -> bool {
    let mut flags: u32 = 1;
    ntqip(-1isize as *mut c_void, 0x1F, &mut flags as *mut _, 4, null_mut());
    flags == 0  // 0 = debugger attached (INVERTED logic)
}
```

**The trap**: The logic is INVERTED. `flags == 0` means debugger IS attached. `flags == 1` means NOT debugged. This catches analysts who assume "0 = safe" without reading the documentation.

**Initial value matters**: The variable is initialized to 1 (not debugged). If NtQIP fails entirely (e.g., wrong process handle), the value stays 1 and the check passes. Only a successful query returning 0 triggers the detection.

### Technique 6: RDTSC Timing

```rust
unsafe fn check_rdtsc_timing() -> bool {
    // Read CPU timestamp counter
    rdtsc → start     // ~0 overhead

    // 100 iterations of busywork
    for i in 0..100 { dummy += i * 7; }

    rdtsc → end       // ~0 overhead

    // Normal: ~1,000 cycles. Single-stepping: ~5,000,000+ cycles
    end - start > 100_000
}
```

**Why single-stepping inflates cycles**: Each `step` command in a debugger:
1. Sets the Trap Flag (TF) in EFLAGS
2. CPU executes ONE instruction
3. CPU generates INT 1 (single-step exception)
4. OS transfers control to the debugger
5. Debugger processes the event, updates UI
6. Debugger clears TF and resumes

Steps 2-6 take ~50,000 CPU cycles. For 100 iterations: 100 × 3 instructions × 50,000 = ~15,000,000 cycles — far above the 100,000 threshold.

**Bypass strategies**:
- Don't single-step through this code — set breakpoint AFTER the check and RUN
- NOP the comparison (`cmp; jle` → `nop; nop; nop; nop; nop; jmp`)
- Use RDTSC emulation (advanced, some hypervisors support this)

### Exercise 2B: Measure RDTSC Yourself (10 min)

```python
#!/usr/bin/env python3
"""Demonstrate RDTSC timing: normal vs debugger overhead."""
import ctypes
import time

# Approximate RDTSC via time.perf_counter_ns()
# (Python can't directly execute rdtsc, but the concept is the same)

start = time.perf_counter_ns()
dummy = 0
for i in range(100):
    dummy += i * 7
end = time.perf_counter_ns()

print(f"Normal execution: {end - start} ns (~{(end-start)//1000} us)")
print(f"At 3GHz, ~{(end-start) * 3} cycles")
print(f"Threshold: 100,000 cycles = ~33,333 ns at 3GHz")
print(f"Single-stepping: ~5,000,000,000 ns (5 seconds)")
print(f"Gap: {5_000_000_000 // (end-start)}x — impossible to miss")
```

### Technique 7: Hardware Breakpoints (DR0-DR3)

```rust
unsafe fn check_hardware_breakpoints() -> bool {
    let mut ctx: Context = zeroed();
    ctx.context_flags = CONTEXT_DEBUG_REGISTERS;  // 0x00100010
    GetThreadContext(GetCurrentThread(), &mut ctx);
    ctx.dr0 != 0 || ctx.dr1 != 0 || ctx.dr2 != 0 || ctx.dr3 != 0
}
```

**Why hardware breakpoints matter**: Unlike software breakpoints (which patch code with `0xCC`/INT3), hardware breakpoints:
- Don't modify memory (no 0xCC byte to detect)
- Can break on memory READ/WRITE (not just execute)
- Are the analyst's most powerful tool for tracing data access

**The x86-64 debug registers**:

| Register | Purpose |
|----------|---------|
| DR0 | Breakpoint address 1 |
| DR1 | Breakpoint address 2 |
| DR2 | Breakpoint address 3 |
| DR3 | Breakpoint address 4 |
| DR6 | Debug status (which BP fired) |
| DR7 | Debug control (BP type: exec/read/write) |

If ANY of DR0-DR3 is non-zero, someone set a hardware breakpoint — almost certainly a debugger.

**Bypass**: Use software breakpoints instead. Or clear DR0-DR3 via `SetThreadContext` before the check runs. ScyllaHide hooks `GetThreadContext` to return zeroed DRs.

### Exercise 2C: Trigger the Hardware BP Check (10 min)

1. Open `anti-debug.exe` in x64dbg WITH ScyllaHide enabled (all options)
2. Set a **hardware breakpoint** on any address (right-click → Breakpoint → Hardware)
3. Disable ScyllaHide's `GetThreadContext` option only
4. Run → the binary exits (HW BP check caught you)
5. Re-enable ScyllaHide's `GetThreadContext` option → binary runs normally

---

## Section 3: The Combined Gate and Execution Flow

### Architecture

```
anti-debug.exe execution:
  init_app_config()              [gate 1 — benign code mass]
  verify_env()                   [gate 2 — 5 env var checks]
  preflight()                    [gate 3 — extended env checks]
  PEB.BeingDebugged (quick)      [gate 4 — fast anti-debug pre-check]
  sandbox_check()                [gate 5 — CPU/RAM/disk/uptime]
  run_gui_lifecycle()            [gate 5b — behavioral camouflage]

  ┌─── Gate 6: is_debugged() — The Anti-Debug Gauntlet ────────┐
  │  1. PEB.BeingDebugged           ← cheapest                 │
  │  2. PEB.NtGlobalFlag & 0x70    ← cheap                     │
  │  3. NtQIP(DebugPort = 7)       ← kernel query              │
  │  4. NtQIP(DebugObject = 0x1E)  ← kernel query              │
  │  5. NtQIP(DebugFlags = 0x1F)   ← kernel query              │
  │  6. RDTSC timing               ← CPU-level                 │
  │  7. HW breakpoint DR0-DR3      ← CPU-level                 │
  │                                                             │
  │  ANY true → silent exit (no error message, no trace)        │
  └─────────────────────────────────────────────────────────────┘

  XOR decrypt 302-byte shellcode
  resolve VirtualAlloc/VirtualProtect/CreateThread (kernel32 PEB walk)
  VirtualAlloc(RW) → copy → scrub → VirtualProtect(RX) → CreateThread
  → MessageBox("GoodBoy")
```

### Cross-DLL Resolution

The binary resolves APIs from TWO DLLs:
- **ntdll** → `NtQueryInformationProcess` (for anti-debug checks 3-5)
- **kernel32** → `GetCurrentThread`, `GetThreadContext` (for check 7) + `VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WaitForSingleObject`, `CloseHandle` (for shellcode)

This is the same cross-DLL pattern from Stage 04, applied to anti-debug.

### Short-Circuit Evaluation

Checks are ordered cheapest-first. If `PEB.BeingDebugged` catches the debugger, the 6 expensive checks never run. This minimizes the runtime cost on real (non-debugged) systems.

---

## Section 4: The GUI Lifecycle — Why It Matters for Evasion

### The Evasion Paradox

During VT testing, a counterintuitive pattern emerged:

| Configuration | VT Score | Explanation |
|--------------|---------|-------------|
| Anti-debug only (no GUI) | 6/76 | ML classifiers see: PEB walk + XOR + VirtualAlloc = malware |
| **Anti-debug + GUI lifecycle** | **3/76** | GUI APIs shift code ratio toward "normal application" |
| Anti-debug - RDTSC | 5/76 | Removing RDTSC reduced benign code mass |
| Anti-debug - HW BP check | 5/76 | Removing GetThreadContext reduced benign code mass |

**The paradox**: Anti-debug code is BENIGN from an ML perspective. Legitimate software (DRM, anti-cheat, crash reporters) uses identical techniques. Each anti-debug check adds code that ML classifiers categorize as "normal." Removing checks INCREASES the offensive/benign code ratio, INCREASING detection.

**The GUI lifecycle** (RegisterClassW → CreateWindowExW → SetTimer → GetMessageW → DestroyWindow) adds ~50 lines of pure Win32 GUI code. This pushes the binary's profile from "tool that does VirtualAlloc" to "application that creates windows AND does VirtualAlloc" — the latter is normal software behavior.

### What the GUI Lifecycle Does

```rust
unsafe fn run_gui_lifecycle() {
    RegisterClassW("SvcHostWnd");        // Register window class
    CreateWindowExW(1x1 pixel, hidden);  // Create invisible window
    SetTimer(50ms);                      // Set short timer
    GetMessageW loop;                    // Standard Win32 message pump
    DestroyWindow;                       // Cleanup
}
```

The binary creates and destroys a hidden 1×1 window in ~50ms. No visible UI. The purpose is purely to generate legitimate-looking API call patterns in the IAT and execution trace.

> **Q2**: Could a sandbox detect the GUI lifecycle as evasion?

<details>
<summary>Answer</summary>

Difficult. The API sequence (RegisterClassW → CreateWindowExW → GetMessageW → DestroyWindow) is identical to millions of legitimate Windows applications. A sandbox would need to correlate: "this process creates a window AND later calls VirtualAlloc with RW→RX" — which requires behavioral chaining, not individual API detection.

The 50ms timer makes the window lifecycle extremely brief — most sandbox monitoring intervals are 100ms+, so they might miss it entirely.

</details>

---

## Section 5: Detection Engineering — Blue Team

### YARA Rule: NtQIP Anti-Debug Constants

```yara
rule AntiDebug_NtQIP_Constants
{
    meta:
        description = "Detects NtQueryInformationProcess anti-debug info class constants"
        author      = "Goodboy Framework"
        stage       = "09"
        technique   = "T1622"

    strings:
        $class_7  = { 07 00 00 00 }   // ProcessDebugPort
        $class_1e = { 1E 00 00 00 }   // ProcessDebugObjectHandle
        $class_1f = { 1F 00 00 00 }   // ProcessDebugFlags
        $flag_70  = { 70 00 00 00 }   // NtGlobalFlag mask
        $peb      = { 65 48 8B 04 25 60 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and $peb and 2 of ($class_*)
}
```

### YARA Rule: RDTSC Timing Check

```yara
rule AntiDebug_RDTSC_Timing
{
    meta:
        description = "Detects RDTSC-based timing anti-debug check"
        author      = "Goodboy Framework"
        stage       = "09"

    strings:
        $rdtsc = { 0F 31 }   // rdtsc instruction

    condition:
        uint16(0) == 0x5A4D and #rdtsc >= 2
}
```

### YARA Rule: Hardware Breakpoint Check

```yara
rule AntiDebug_HW_Breakpoint_Check
{
    meta:
        description = "Detects GetThreadContext with CONTEXT_DEBUG_REGISTERS"
        author      = "Goodboy Framework"
        stage       = "09"

    strings:
        // CONTEXT_DEBUG_REGISTERS = 0x00100010
        $ctx_flags = { 10 00 10 00 }
        // GetThreadContext import or hash
        $peb = { 65 48 8B 04 25 60 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and $ctx_flags and $peb
}
```

### Sigma Rule: Anti-Debug Behavioral Pattern

```yaml
title: Process Queries Own Debug State via NtQueryInformationProcess
id: goodboy-stage09-antidebug
status: experimental
description: >
    Detects a process querying its own debug port, debug object handle,
    or debug flags — a strong indicator of anti-debug code.
logsource:
    product: windows
    category: process_access
detection:
    selection:
        CallTrace|contains:
            - 'NtQueryInformationProcess'
    filter_legitimate:
        Image|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
            - '\lsass.exe'
    condition: selection and not filter_legitimate
level: medium
tags:
    - attack.defense_evasion
    - attack.t1622
```

### Blue Team: ScyllaHide Bypass Reference Table

| # | Technique | ScyllaHide Option | Manual Bypass in x64dbg |
|---|-----------|------------------|------------------------|
| 1 | PEB.BeingDebugged | `PEB → BeingDebugged` | Set byte at PEB+0x02 to 0 |
| 2 | PEB.NtGlobalFlag | `PEB → NtGlobalFlag` | Set DWORD at PEB+0xBC to 0 |
| 3 | ProcessDebugPort | `NtQueryInformationProcess` | Hook returns 0 for class 7 |
| 4 | ProcessDebugObjectHandle | `NtQueryInformationProcess` | Hook returns STATUS_INVALID_HANDLE for class 0x1E |
| 5 | ProcessDebugFlags | `NtQueryInformationProcess` | Hook returns 1 for class 0x1F |
| 6 | RDTSC Timing | Partial (`RDTSC` option) | Set breakpoint AFTER the check, RUN past it |
| 7 | Hardware Breakpoints | `GetThreadContext` | Use software BPs instead, or clear DR0-DR3 |

### Exercise 3A: Bypass All 7 with ScyllaHide (15 min)

1. Open `anti-debug.exe` in x64dbg **without** ScyllaHide → exits immediately
2. Enable ScyllaHide with ALL options → MessageBox("GoodBoy") appears
3. **Challenge**: Disable ScyllaHide, bypass each check MANUALLY:
   - Set PEB+0x02 to 0 (Memory view → go to PEB → edit byte)
   - Set PEB+0xBC to 0
   - Set breakpoint on the `is_debugged` return → change RAX to 0
   - For RDTSC: DON'T single-step through it

### Exercise 3B: Identify Which Check Catches You (15 min)

With ScyllaHide disabled, find `is_debugged()` in Ghidra. In x64dbg:
1. NOP `check_peb_being_debugged`'s return → still exits? Next check caught you
2. NOP `check_nt_global_flag`'s return → still exits? Continue
3. Work through each check until the binary runs
4. The last check you NOPed is the one your setup fails on

### Exercise 3C: Python NtQIP Tester (10 min)

```python
#!/usr/bin/env python3
"""Test NtQueryInformationProcess anti-debug info classes."""
import ctypes

ntdll = ctypes.windll.ntdll

def nqip(info_class, size=8):
    """Query NtQueryInformationProcess for a given info class."""
    buf = ctypes.c_longlong(0) if size == 8 else ctypes.c_ulong(0)
    status = ntdll.NtQueryInformationProcess(
        ctypes.c_void_p(-1),  # NtCurrentProcess
        info_class,
        ctypes.byref(buf),
        size,
        None
    )
    return status, buf.value

status7, port = nqip(7)
status1e, obj = nqip(0x1E)
status1f, flags = nqip(0x1F, 4)

print(f"ProcessDebugPort (7):         status=0x{status7 & 0xFFFFFFFF:08X}  port={port}")
print(f"ProcessDebugObjectHandle (30): status=0x{status1e & 0xFFFFFFFF:08X}  handle={obj}")
print(f"ProcessDebugFlags (31):        status=0x{status1f & 0xFFFFFFFF:08X}  flags={flags}")
print()
print("Run this OUTSIDE a debugger → all should indicate 'not debugged'")
print("Run this INSIDE x64dbg → values change to indicate debugger present")
```

---

## Section 6: Adversarial Thinking

### Challenge 1: Anti-Debug via Direct Syscalls

The binary resolves NtQIP from ntdll via PEB walk. ScyllaHide hooks this function. How to make the anti-debug check bypass-resistant?

<details>
<summary>Approaches</summary>

1. **Direct syscall for NtQIP**: Use Stage 07's technique — read NtQueryInformationProcess's SSN, issue `syscall` directly. ScyllaHide's ntdll hook never fires
2. **Indirect syscall for NtQIP**: Stage 08's technique — CALL ntdll gadget. Even stealthier call stack
3. **The escalation**: With direct/indirect syscalls, the analyst needs kernel-level tools (TitanHide) instead of just ScyllaHide. This significantly raises the bar

</details>

### Challenge 2: Detect Anti-Debug Statically

You're a blue team analyst. How do you identify anti-debug code WITHOUT running the binary?

<details>
<summary>Approaches</summary>

1. **YARA for NtQIP info classes**: Constants 7, 0x1E, 0x1F near PEB access
2. **YARA for dual RDTSC**: Two `0F 31` instructions in .text = timing check
3. **YARA for CONTEXT_DEBUG_REGISTERS**: Constant `0x00100010` near GetThreadContext resolution
4. **Import analysis**: GetThreadContext + GetCurrentThread in IAT or resolved via PEB walk
5. **Behavioral sandbox**: Run with debugger attached → immediate exit = anti-debug

</details>

### Challenge 3: Anti-Debug That Survives Kernel Patching

Even TitanHide patches the kernel's NtQIP handler. Is there an anti-debug check that survives?

<details>
<summary>Approaches</summary>

1. **Self-modifying code integrity**: Write a known byte to your .text, read it back. If it changed to 0xCC (INT3), a software breakpoint was set. No API call — just a memory read
2. **Exception-based detection**: Execute an invalid instruction. If a debugger is attached, it handles the exception. If not, your vectored exception handler catches it. The timing differs
3. **Parent process check**: Query your parent process. If it's x64dbg.exe or windbg.exe, you're being debugged. No NtQIP needed — just process enumeration
4. **Thread hiding**: Call `NtSetInformationThread(ThreadHideFromDebugger)` — the thread becomes invisible to the debugger. If the debugger can't see the thread, it can't set breakpoints on it

</details>

### Challenge 4: The Evasion Paradox

Removing anti-debug checks INCREASED VT detection (3/76 → 5-6/76). Why? And what does this mean for red team tool design?

<details>
<summary>Answer</summary>

Anti-debug code is ML-benign because legitimate software uses identical techniques. Each check adds code that ML classifiers categorize as "normal application behavior" (DRM, anti-cheat, crash reporters all check for debuggers).

Removing checks:
1. Reduces benign code mass → offensive/benign ratio tilts toward offensive
2. Removes GetThreadContext, NtQIP calls → fewer "normal" API patterns
3. The remaining code (PEB walk + XOR + VirtualAlloc) looks more like pure malware

**Design principle**: Anti-debug code serves DUAL purpose — it evades debuggers AND improves ML evasion by diluting the offensive code ratio. This is why the confirmed 0/76 builds included anti-debug even when it wasn't strictly needed.

</details>

---

## Section 7: Knowledge Check

**1. The binary exits in x64dbg without ScyllaHide. Which check fires first?**

<details>
<summary>Answer</summary>

`check_peb_being_debugged()` — it's first in `is_debugged()` and PEB.BeingDebugged is set immediately when a debugger attaches.

</details>

**2. You enable ScyllaHide PEB patches but the binary still exits. What's catching you?**

<details>
<summary>Answer</summary>

NtQueryInformationProcess checks (3, 4, or 5). Enable ScyllaHide's `NtQueryInformationProcess` hook option.

</details>

**3. All PEB and NtQIP checks pass but the binary exits when you single-step. Why?**

<details>
<summary>Answer</summary>

`check_rdtsc_timing()` — single-stepping inflates cycles from ~1,000 to ~5,000,000+. Don't single-step; set breakpoint AFTER the check and run.

</details>

**4. Why check NtGlobalFlag if BeingDebugged already catches debuggers?**

<details>
<summary>Answer</summary>

NtGlobalFlag is set at process CREATION. Even if the debugger detaches, the flag persists. BeingDebugged resets to 0 on detach. NtGlobalFlag catches "was this process BORN under a debugger?"

</details>

**5. A binary uses direct syscalls for NtQIP. Can ScyllaHide bypass it?**

<details>
<summary>Answer</summary>

No. ScyllaHide hooks ntdll's function. Direct syscalls skip ntdll. Kernel-level tools (TitanHide) are required.

</details>

**6. Removing the RDTSC check INCREASED VT detection from 3/76 to 5/76. Why?**

<details>
<summary>Answer</summary>

RDTSC is benign code mass. The `rdtsc` instruction appears in performance monitoring, profiling, and timing-sensitive legitimate software. Removing it reduced the binary's benign code ratio, making the remaining offensive code (PEB walk + XOR + VirtualAlloc) proportionally more prominent to ML classifiers.

</details>

---

## Module Summary

| Concept | Stages 01-08 | Stage 09 (NEW) |
|---------|-------------|----------------|
| Anti-debug | PEB.BeingDebugged only (1 check) | **7 checks: PEB×2, NtQIP×3, RDTSC, HW BP** |
| NtQIP usage | Resolved but not called (Stage 04) | **Called with 3 info classes (7, 0x1E, 0x1F)** |
| RDTSC | Never used | **Timing check detects single-stepping** |
| HW BP detection | Never | **DR0-DR3 via GetThreadContext** |
| GUI lifecycle | Not in self-contained stages | **RegisterClassW + CreateWindowExW (evasion)** |
| ScyllaHide awareness | Mentioned | **Full bypass table + exercises** |
| Evasion paradox | Not discussed | **Anti-debug code = ML-benign, removing it = worse VT** |
| Cross-DLL | Stage 04 (kernel32+ntdll) | **kernel32 (exec + HW BP) + ntdll (NtQIP)** |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "ScyllaHide defeats all anti-debug" | Only user-mode. Direct syscalls bypass it. Kernel tools needed |
| "PEB.BeingDebugged is enough" | Weakest check. NtQIP and RDTSC are much harder to bypass |
| "Anti-debug is unique to malware" | Legitimate: DRM (Denuvo), anti-cheat (EAC, BattlEye), crash reporters |
| "RDTSC can't detect debuggers" | Single-stepping inflates cycles 1,000-5,000x. Reliable |
| "Hardware BPs are undetectable" | GetThreadContext reads DR0-DR3. Non-zero = HW BP |
| "More anti-debug = more detectable" | OPPOSITE: anti-debug code is ML-benign. Removing it INCREASES VT score |

### What Breaks at Stage 10 — The Bridge

Stage 09 detects DEBUGGERS — human analysts stepping through code. Stage 10 detects SANDBOXES — automated analysis environments that don't use debuggers but execute the binary with monitoring. The hardware checks (CPU, RAM, disk) from `sandbox_check()` become the primary focus, expanded with VM detection, uptime analysis, user interaction checks, and behavioral heuristics.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Debugger Evasion | T1622 | 7 anti-debug techniques: PEB×2, NtQIP×3, RDTSC, HW BP |
| Native API | T1106 | NtQueryInformationProcess via PEB-walked ntdll |
| Obfuscated Files | T1027 | XOR-encrypted shellcode |
| Reflective Code Loading | T1620 | VirtualAlloc → VirtualProtect → CreateThread |

### Further Reading (2025-2026)

**Anti-debug techniques:**
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide) — Standard anti-anti-debug plugin for x64dbg
- [al-khaser](https://github.com/LordNoteworthy/al-khaser) — 100+ anti-analysis techniques in one binary
- [CheckPoint Anti-Debug Encyclopedia](https://anti-debug.checkpoint.com/) — Comprehensive reference with code

**Kernel-level bypass:**
- [TitanHide](https://github.com/mrexodia/TitanHide) — Kernel driver for anti-anti-debug (bypasses NtQIP at kernel level)

**Detection:**
- [Oblivion: Detecting Anti-Debug](https://oblivion-malware.xyz/posts/detecting-syscalls/) — YARA and behavioral approaches

## What's Next

- **Stage 10 (Anti-Sandbox)**: Hardware fingerprinting, VM detection, weighted scoring — detecting automated analysis environments
- **Stage 11 (Persistence)**: Registry Run keys, scheduled tasks, COM hijacking — surviving reboots
