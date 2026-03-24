# Stage 04: API Hashing — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Dynamic API Resolution, PEB Internals, and Rainbow Tables |
| **Level** | Intermediate |
| **Estimated Time** | 5-6 hours |
| **Category** | Reversing / Windows Internals / Detection Engineering |
| **Platform** | Windows x64 |
| **Binary** | `netdiag.exe` (~290KB, Rust, PE64) |
| **Prerequisites** | Stage 01 (loader pipeline), Stage 02 or 03 (crypto concepts) |
| **MITRE ATT&CK** | T1027.007, T1106, T1620, T1036 |
| **VT Score** | **0/76** achieved (March 2026) |

---

## Why This Stage Exists — The Bridge from Stage 03

Stages 01-03 all used the same `resolve_api()` function to find VirtualAlloc, VirtualProtect, and CreateThread at runtime. You saw hash constants in `.rdata` and accepted that "API hashing happens." But you never examined HOW.

**This stage opens the black box.**

Stage 04 is the deep dive into the resolver mechanism that powers ALL 15 Goodboy binaries. Understanding it unlocks:
- **Rainbow table attacks**: Pre-compute hashes for all Windows API exports → instantly identify which APIs ANY Goodboy binary resolves
- **PEB structure knowledge**: The TEB → PEB → Ldr → module list chain is the foundation for anti-debug (Stage 09), anti-sandbox (Stage 10), and the entire syscall engine (Stages 07-08)
- **Detection invariants**: The `gs:[0x60]` PEB access instruction is present in ALL stages and extremely rare in legitimate software — a single YARA rule catches the entire framework

**What's genuinely new in this binary:**
1. **Cross-DLL resolution** — Resolves APIs from THREE DLLs (kernel32, user32, ntdll) instead of just kernel32
2. **Direct API calling** — Calls MessageBoxW directly via resolved function pointer, no shellcode needed
3. **LoadLibraryA as pivot** — Loads user32.dll at runtime, making it appear in the PEB module list
4. **ntdll enumeration** — Resolves NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx (foreshadowing Stage 07 syscalls)
5. **13 hash constants** in `.rdata` for rainbow table exercises (Stages 01-03 had only 6)
6. **Binary naming** — `netdiag.exe` mimics a legitimate Windows network diagnostic tool

### Real-World Context (2025-2026)

- **MuddyWater RustyWater** (2025) — Iranian APT's Rust RAT uses identical PEB-walking API resolution with a different hash algorithm. The structural pattern is the same
- **Microsoft RIFT** (June 2025) — Microsoft's Rust malware analysis tool specifically targets PEB-walking code patterns. [RIFT blog post](https://www.microsoft.com/en-us/security/blog/2025/06/27/unveiling-rift-enhancing-rust-malware-analysis-through-pattern-matching/)
- **Cobalt Strike 4.11** (May 2025) — Still uses PEB-walking hash resolution in its beacon loader, 20+ years after the technique was first published in Phrack

---

## Prerequisites

Before starting this module, you should be comfortable with:
- The loader pipeline from Stage 01 (VirtualAlloc → VirtualProtect → CreateThread)
- XOR encryption concept (Stage 01-02)
- PE file format basics (sections, headers, imports vs exports)
- Setting breakpoints and reading registers in x64dbg
- Python bitwise operations (shifts, XOR, masking)

**Software needed**:
- Ghidra 11.x (free) or IDA Free/Pro
- x64dbg + ScyllaHide plugin
- Python 3.10+ (on Windows for DLL export enumeration)
- PE-bear or CFF Explorer
- WinDbg (optional, for live PEB exploration)

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** the complete TEB → PEB → Ldr → module list pointer chain and navigate it in a debugger
2. **Implement** the additive hash algorithm in Python and verify it against binary constants
3. **Build** a rainbow table covering all exports from kernel32, ntdll, and user32 (~5,000 functions)
4. **Reverse** all 13 hash constants in the binary to their API names using the rainbow table
5. **Explain** cross-DLL resolution: how LoadLibraryA adds a module to the PEB list, enabling hash-based resolution of its exports
6. **Identify** the `gs:[0x60]` instruction pattern and explain why it's the strongest single-instruction detection for PEB walkers
7. **Write** a YARA rule targeting the hash seed + multiplier constants in compiled code
8. **Articulate** why the same resolver works across all 15 stages — the detection invariant

---

## Section 1: Why API Hashing Exists

### The Import Table Problem

Every Windows PE binary has an **Import Address Table (IAT)** — a list of DLL names and function names the binary needs. The Windows loader reads this at startup and fills in actual function addresses.

From a defender's perspective, the IAT is a goldmine:
```
Suspicious IAT:
  kernel32.dll
    → VirtualAlloc
    → VirtualProtect
    → CreateThread
    → WriteProcessMemory
```
A signature matching "imports VirtualAlloc + VirtualProtect + CreateThread + WriteProcessMemory" catches most basic shellcode loaders.

### The Attacker's Solution

Instead of listing API names in the IAT, the binary:
1. Walks internal Windows data structures (PEB) to find loaded DLLs
2. Parses each DLL's PE export table to enumerate function names
3. Hashes each name and compares against pre-computed target hashes
4. When a match is found, stores the function address for later use

Result: the IAT contains ZERO offensive function names. The binary achieves full API access using only integer constants.

### The Stage 04 Binary's IAT

```
Actual IAT of netdiag.exe:
  kernel32.dll
    → GetSystemInfo           (sandbox check — benign)
    → GlobalMemoryStatusEx    (sandbox check — benign)
    → GetTickCount64          (sandbox check — benign)
  advapi32.dll                (from windows-sys features — benign)
```

The offensive APIs (VirtualAlloc, VirtualProtect, CreateThread, LoadLibraryA, MessageBoxW) are **nowhere in the IAT**. They're resolved at runtime via hash constants.

> **Q1**: The IAT still contains GetSystemInfo and GetTickCount64. Why not resolve these via hashing too?

<details>
<summary>Answer</summary>

These are used in `sandbox_check()` which calls Windows APIs via direct `windows-sys` imports (standard Rust FFI). They're deliberately LEFT in the IAT because:
1. They're benign — GetSystemInfo and GetTickCount64 appear in legitimate applications
2. Having SOME imports makes the IAT look normal — a completely empty IAT is itself suspicious
3. The offensive APIs are the ones that trigger AV signatures, not monitoring APIs

This is a design choice: hide the offensive APIs, leave the benign ones visible. The IAT becomes a "camouflage layer" rather than completely empty.

</details>

---

## Section 2: The PEB Pointer Chain

### TEB → PEB → LDR: How the Resolver Finds DLLs

Every Windows thread has a **Thread Environment Block (TEB)**, accessible via the `gs` segment register on x64:

```
x64 Memory Layout:

gs:[0x00] → TEB (Thread Environment Block, per-thread)
gs:[0x30] → TEB self-pointer
gs:[0x60] → PEB (Process Environment Block, per-process)

PEB structure (key offsets):
┌──────────────────────────────────────────┐
│ +0x00  InheritedAddressSpace             │
│ +0x01  ReadImageFileExecOptions          │
│ +0x02  BeingDebugged ◄──── anti-debug    │
│ +0x10  ImageBaseAddress                  │
│ +0x18  Ldr ────────────► PEB_LDR_DATA    │
│ +0x20  ProcessParameters                 │
│ +0xBC  NtGlobalFlag ◄──── anti-debug     │
└──────────────────────────────────────────┘

PEB_LDR_DATA structure:
┌──────────────────────────────────────────┐
│ +0x10  InLoadOrderModuleList ◄── we walk │
│ +0x20  InMemoryOrderModuleList           │
│ +0x30  InInitializationOrderModuleList   │
└──────────────────────────────────────────┘

Each module (LDR_DATA_TABLE_ENTRY):
┌──────────────────────────────────────────┐
│ +0x00  InLoadOrderLinks (LIST_ENTRY)     │
│ +0x10  InMemoryOrderLinks                │
│ +0x20  InInitializationOrderLinks        │
│ +0x30  DllBase ◄──── module base address │
│ +0x38  EntryPoint                        │
│ +0x40  SizeOfImage                       │
│ +0x48  FullDllName (UNICODE_STRING)      │
│ +0x58  BaseDllName (UNICODE_STRING) ◄──  │
└──────────────────────────────────────────┘
```

**The access instruction** (x64):
```asm
mov rax, gs:[0x60]    ; RAX = PEB pointer
; Encoded as: 65 48 8B 04 25 60 00 00 00  (9 bytes)
```

This 9-byte sequence is one of the strongest single-instruction signatures for PEB-walking resolvers. It appears in ALL 15 Goodboy stages and is extremely rare in legitimate software.

### Exercise 1: Explore the PEB Live (15 min)

**Using x64dbg** (attach to any process):
```
dump gs:[60]              ; View PEB structure
dump poi(gs:[60]+18)      ; View PEB_LDR_DATA
```

**Using WinDbg**:
```
dt ntdll!_PEB @$peb
dt ntdll!_PEB_LDR_DATA poi(@$peb+0x18)
!peb
```

**Using Python** (ctypes):
```python
import ctypes

kernel32 = ctypes.windll.kernel32

# Enumerate loaded modules via GetModuleHandle
dlls = ["kernel32.dll", "ntdll.dll", "user32.dll", "kernelbase.dll"]
for dll in dlls:
    h = kernel32.GetModuleHandleA(dll.encode())
    if h:
        print(f"  {dll:20s} base: 0x{h:016x}")
    else:
        print(f"  {dll:20s} NOT LOADED")
```

**Key observation**: Run this BEFORE and AFTER `LoadLibraryA("user32.dll")`. User32 appears in the module list ONLY after being loaded. This is why Stage 04 must call LoadLibraryA before it can resolve MessageBoxW.

> **Q2**: The binary walks InLoadOrderModuleList (offset +0x10). Other malware walks InMemoryOrderModuleList (+0x20) or InInitializationOrderModuleList (+0x30). Does it matter?

<details>
<summary>Answer</summary>

All three lists contain the same modules, in different orders:
- **InLoadOrderModuleList**: Order the PE loader processed them. EXE first, then ntdll, then kernel32
- **InMemoryOrderModuleList**: Order by memory address. Traditional choice in Metasploit shellcode
- **InInitializationOrderModuleList**: Order DllMain was called. ntdll first, kernel32 second

Any list works — the resolver iterates until it finds a matching DLL hash. The Goodboy framework uses InLoadOrderModuleList. Metasploit's block_api uses InMemoryOrderModuleList.

**Detection angle**: Check all three offset patterns (`+0x10`, `+0x20`, `+0x30`) in YARA rules. Different malware families use different lists.

</details>

---

## Section 3: The Additive Hash Algorithm — Deep Dive

### Algorithm Mechanics

Stages 01-03 used this hash but never explained its internals. Here's the full breakdown:

```
function additive_hash(name):
    h = 0x1F2E3D4C              ← seed (custom, not from any standard)
    for each byte b in name:
        h = h + b               ← wrapping_add (incorporate input)
        h = h × 0x1003F         ← wrapping_mul (avalanche/mixing)
        h = h XOR (h >> 11)     ← right-shift mix (bit diffusion)
    return h                    ← 32-bit result
```

**Why these specific constants?**

| Constant | Value | Purpose |
|----------|-------|---------|
| Seed | `0x1F2E3D4C` | Non-obvious starting value. Not in any public hash database — makes algorithm identification harder |
| Multiplier | `0x1003F` | = 65,599 decimal = 2^16 + 63. Provides good bit mixing — each multiply spreads input influence across most output bits |
| Right-shift | 11 bits | Feeds high bits back into low bits. 11 is coprime with 32 (register width), ensuring different bits mix on each iteration |

**Case-insensitive variant** (for DLL names):
```
function additive_hash_ci(name):
    h = 0x1F2E3D4C
    for each byte b in name:
        if b >= 'A' and b <= 'Z':
            b = b + 32            ← ASCII toLower
        h = h + b
        h = h × 0x1003F
        h = h XOR (h >> 11)
    return h
```

Windows DLL names are case-insensitive — `KERNEL32.DLL` and `kernel32.dll` must produce the same hash. The resolver lowercases each byte before hashing. This is ASCII-only (`+32` for A-Z), which works because DLL names are always ASCII.

### In Disassembly

What the hash function looks like in Ghidra/IDA:
```asm
mov  eax, 0x1F2E3D4C           ; seed constant
; loop:
movzx ecx, byte [rsi]          ; load next byte
test  cl, cl                    ; null terminator?
jz    done
add   eax, ecx                 ; h += byte
imul  eax, eax, 0x1003F        ; h *= multiplier
mov   edx, eax
shr   edx, 11                  ; h >> 11
xor   eax, edx                 ; h ^= (h >> 11)
inc   rsi
jmp   loop
```

**Recognition pattern**: Look for `0x1F2E3D4C` as a `mov` immediate followed by an `imul` with `0x1003F` and a `shr` by 11. This triplet uniquely identifies the Goodboy additive hash across all 15 stages.

> **Note**: The compiler may optimize `imul eax, eax, 0x1003F` into a `lea` + `shl` + `add` sequence. Recognizing these optimized patterns is a key reversing skill.

### Exercise 2: Implement and Verify the Hash (15 min)

Write the hash in Python and verify against the binary's constants:

```python
def additive_hash(name: bytes) -> int:
    """Case-sensitive additive hash (function names)."""
    h = 0x1F2E3D4C
    for b in name:
        h = (h + b) & 0xFFFFFFFF
        h = (h * 0x1003F) & 0xFFFFFFFF
        h ^= (h >> 11)
    return h

def additive_hash_ci(name: bytes) -> int:
    """Case-insensitive additive hash (DLL names)."""
    h = 0x1F2E3D4C
    for b in name:
        c = b + 32 if 0x41 <= b <= 0x5A else b
        h = (h + c) & 0xFFFFFFFF
        h = (h * 0x1003F) & 0xFFFFFFFF
        h ^= (h >> 11)
    return h

# Verify against binary constants
tests = [
    ("DLL", "kernel32.dll", True,  0x0B6D79E7),
    ("DLL", "user32.dll",   True,  0x090DD676),
    ("DLL", "ntdll.dll",    True,  0x0EC9AE0F),
    ("FN",  "VirtualAlloc",           False, 0x1C02DEBA),
    ("FN",  "VirtualProtect",         False, 0xA234F8D5),
    ("FN",  "CreateThread",           False, 0x9257966A),
    ("FN",  "WaitForSingleObject",    False, 0xA63CFCB1),
    ("FN",  "CloseHandle",            False, 0xE95098B3),
    ("FN",  "LoadLibraryA",           False, 0xE8EBE5AB),
    ("FN",  "MessageBoxW",            False, 0x7AC89F36),
    ("FN",  "NtAllocateVirtualMemory",False, 0x4C5F6FA9),
    ("FN",  "NtProtectVirtualMemory", False, 0x4FA8A779),
    ("FN",  "NtCreateThreadEx",       False, 0xC0E8DF85),
]

for typ, name, ci, expected in tests:
    h = additive_hash_ci(name.encode()) if ci else additive_hash(name.encode())
    status = "OK" if h == expected else "FAIL"
    print(f"  [{status}] {typ:3s} {name:30s} -> 0x{h:08X}  (expect 0x{expected:08X})")
```

**All 13 values must match.** If any fail, check:
- `wrapping_add` vs `XOR` (this hash ADDS the byte, unlike FNV which XORs)
- `0x1003F` is the multiplier (NOT `0x01000193` which is FNV)
- The shift is 11 bits to the RIGHT (NOT rotate-left)

### Exercise 3: Find the Constants in Disassembly (15 min)

Open `netdiag.exe` in Ghidra:
1. Search for the immediate value `0x1F2E3D4C` — this is the hash seed
2. You should find it in at least THREE places:
   - `additive_hash_const()` (compile-time, might be inlined)
   - `resolve_api()` → inline hash for DLL names (case-insensitive variant)
   - `find_export()` → inline hash for function names (case-sensitive variant)
3. Near each seed, find `0x1003F` (the multiplier)
4. Near each multiplier, find `shr reg, 11` (the bit diffusion step)

**The three constants form a signature**: seed `0x1F2E3D4C` + multiplier `0x1003F` + shift `11`. Finding any one leads you to the others.

> **Q3**: The hash uses `h += byte` (addition) instead of `h ^= byte` (XOR). Does this affect collision resistance?

<details>
<summary>Answer</summary>

Addition and XOR both incorporate the input byte, but with different properties:
- **XOR** is linear over GF(2) — two inputs that differ by one bit produce outputs that differ by one bit (before the multiply). This makes XOR hashes vulnerable to differential analysis
- **Addition** creates carries that propagate upward through bit positions. This natural carry propagation adds non-linearity that XOR lacks

The multiplier `0x1003F` then amplifies these differences. Combined with the `h ^= h >> 11` feedback step, the additive approach provides reasonable avalanche. For API resolution with ~1,600 exports, the collision probability is negligible (~0.003% per lookup).

In practice, both XOR-based and addition-based hashes work fine for API resolution. The choice is more about creating a unique instruction pattern than about mathematical properties.

</details>

---

## Section 4: PE Export Table Internals

### The Three Parallel Arrays

When the resolver finds the right DLL, it searches that DLL's exports. PE export tables use three parallel arrays:

```
IMAGE_EXPORT_DIRECTORY:
┌──────────────────────────────────────────────┐
│  +0x14  NumberOfFunctions  = 1600            │
│  +0x18  NumberOfNames      = 1600            │
│  +0x1C  AddressOfFunctions → [RVA, RVA, ...] │  function addresses
│  +0x20  AddressOfNames     → [RVA, RVA, ...] │  name string pointers
│  +0x24  AddressOfNameOrdinals→ [u16, u16,...]│  index mapping
└──────────────────────────────────────────────┘

Lookup for "VirtualAlloc" (hash 0x1C02DEBA):
  1. for i in 0..NumberOfNames:
       name_ptr = DllBase + AddressOfNames[i]
       if additive_hash(name_ptr) == 0x1C02DEBA:  ← MATCH at index i
         ordinal = AddressOfNameOrdinals[i]
         func_rva = AddressOfFunctions[ordinal]
         return DllBase + func_rva
```

**Why three arrays?**
- Functions can be exported by ordinal only (no name) — AddressOfFunctions may be larger
- Names are sorted alphabetically — enables binary search (the resolver uses linear scan)
- The ordinal array bridges "name index" to "function index" — a level of indirection

### Exercise 4: Walk an Export Table (15 min)

```python
import ctypes

kernel32 = ctypes.windll.kernel32
base = kernel32.GetModuleHandleA(b"kernel32.dll")

# Parse PE headers
e_lfanew = ctypes.c_int.from_address(base + 0x3C).value
export_rva = ctypes.c_uint.from_address(base + e_lfanew + 0x88).value
export_dir = base + export_rva

num_names = ctypes.c_uint.from_address(export_dir + 0x18).value
names_rva = ctypes.c_uint.from_address(export_dir + 0x20).value
funcs_rva = ctypes.c_uint.from_address(export_dir + 0x1C).value
ords_rva  = ctypes.c_uint.from_address(export_dir + 0x24).value

print(f"kernel32.dll: {num_names} named exports")

# Find VirtualAlloc manually
for i in range(num_names):
    name_rva = ctypes.c_uint.from_address(base + names_rva + i * 4).value
    name = ctypes.string_at(base + name_rva)
    if name == b"VirtualAlloc":
        ordinal = ctypes.c_ushort.from_address(base + ords_rva + i * 2).value
        func_rva = ctypes.c_uint.from_address(base + funcs_rva + ordinal * 4).value
        addr = base + func_rva

        # Verify against GetProcAddress
        real = kernel32.GetProcAddress(base, b"VirtualAlloc")
        print(f"  Manual:          0x{addr:016x}")
        print(f"  GetProcAddress:  0x{real:016x}")
        print(f"  Match: {addr == real}")
        break
```

**Why this matters**: The resolver does EXACTLY this — but using hash comparison instead of string comparison. Understanding the three-array structure is essential for writing rainbow table tools and detection rules.

> **Q4**: The resolver does linear search (checking every name). kernel32.dll has ~1,600 exports. Is this slow?

<details>
<summary>Answer</summary>

~1,600 names × ~20 bytes/name × 3 operations/byte = ~96,000 operations per API resolution. At modern CPU speeds, this takes microseconds. Resolving 10 APIs at startup is imperceptible.

Some malware uses binary search on the sorted name array for speed, but this adds code complexity. The Goodboy framework prioritizes simplicity — linear scan is fast enough.

**Detection angle**: Linear scan means the resolver reads EVERY export name sequentially. If you set a hardware read breakpoint on the export name table, you'll see a burst of sequential reads — a distinctive behavioral pattern.

</details>

---

## Section 5: Cross-DLL Resolution — What's New in Stage 04

### The Problem: User32 Isn't Loaded Yet

Stages 01-03 only resolve APIs from kernel32.dll, which is ALWAYS loaded in every Windows process. But what if you need an API from a DLL that isn't loaded yet?

`MessageBoxW` lives in user32.dll. A console application doesn't load user32. The PEB module list doesn't contain it. The hash resolver finds nothing.

### The Solution: LoadLibraryA as a Pivot

Stage 04's execution flow:

```
Phase 1: Resolve LoadLibraryA from kernel32 (always loaded)
  resolve_api(H_KERNEL32, H_LOADLIBRARYA) → function pointer

Phase 2: Call LoadLibraryA("user32.dll")
  → Windows loads user32.dll into the process
  → user32 appears in the PEB module list

Phase 3: Resolve MessageBoxW from user32 (NOW in the PEB list)
  resolve_api(H_USER32, H_MESSAGEBOXW) → function pointer

Phase 4: Call MessageBoxW("GoodBoy", "Stage 04")
  → Dialog appears — proof of cross-DLL resolution
```

**The key insight**: `LoadLibraryA` is the **bridge** between "DLLs already in the process" and "any DLL on disk." Once you can resolve LoadLibraryA (from kernel32, which is always present), you can load ANY DLL and resolve ANY of its exports. This gives the resolver access to the entire Windows API surface.

### Exercise 5: Observe PEB Module List Changes (10 min)

**In x64dbg**:
1. Set a breakpoint at the `LoadLibraryA` call (after it's resolved via hash)
2. Before the call: examine the PEB module list — user32.dll is NOT present
3. Step over the call
4. After the call: examine the PEB module list — user32.dll NOW appears
5. Continue: the resolver finds MessageBoxW in the newly-loaded module

**In Python**:
```python
import ctypes

kernel32 = ctypes.windll.kernel32

# Before LoadLibrary
h = kernel32.GetModuleHandleA(b"user32.dll")
print(f"user32 before: {'loaded' if h else 'NOT loaded'}")

# Load it
kernel32.LoadLibraryA(b"user32.dll")

# After LoadLibrary
h = kernel32.GetModuleHandleA(b"user32.dll")
print(f"user32 after:  {'loaded' if h else 'NOT loaded'}")
```

This demonstrates that the PEB module list is **dynamic** — LoadLibraryA modifies it at runtime. The hash resolver works on the current state of the list, so newly loaded DLLs become immediately resolvable.

### The ntdll Resolution (Foreshadowing Stage 07)

Stage 04 also resolves three APIs from ntdll.dll:
- `NtAllocateVirtualMemory` (hash `0x4C5F6FA9`)
- `NtProtectVirtualMemory` (hash `0x4FA8A779`)
- `NtCreateThreadEx` (hash `0xC0E8DF85`)

These are resolved but NOT called — they exist to:
1. Add hash constants to `.rdata` for rainbow table exercises
2. Demonstrate that ntdll exports are accessible via the same resolver
3. Foreshadow Stage 07 where these Nt* functions become the primary execution path (direct syscalls bypass kernel32 entirely)

> **Q5**: ntdll.dll is always loaded (it's the first DLL in every process). Why doesn't Stage 01 resolve APIs from ntdll?

<details>
<summary>Answer</summary>

Stage 01 didn't need to — VirtualAlloc, VirtualProtect, and CreateThread from kernel32 are sufficient for basic shellcode loading. The Nt* equivalents in ntdll provide the same functionality but at a lower level.

The reason to use ntdll APIs is **hook evasion**: EDR products hook kernel32/kernelbase functions by patching their first bytes with JMP instructions. The actual syscall happens in ntdll. By calling ntdll directly (or issuing the `syscall` instruction manually), you bypass these hooks entirely.

Stage 04 demonstrates that the hash resolver CAN find ntdll exports. Stage 07 teaches you to CALL them.

</details>

---

## Section 6: Building a Complete Rainbow Table

### The Attack: Reversing All Hash Constants

The binary contains 13 hash constants in `.rdata`. Each maps to an API name. A rainbow table pre-computes `additive_hash(export_name)` for every export in every common DLL — then a simple lookup reverses any hash constant.

### Exercise 6: Build the Rainbow Table (20 min)

```python
#!/usr/bin/env python3
"""Build additive-hash rainbow table from Windows DLL exports."""
import ctypes
import json

def additive_hash(name: bytes) -> int:
    h = 0x1F2E3D4C
    for b in name:
        h = (h + b) & 0xFFFFFFFF
        h = (h * 0x1003F) & 0xFFFFFFFF
        h ^= (h >> 11)
    return h

def additive_hash_ci(name: bytes) -> int:
    h = 0x1F2E3D4C
    for b in name:
        c = b + 32 if 0x41 <= b <= 0x5A else b
        h = (h + c) & 0xFFFFFFFF
        h = (h * 0x1003F) & 0xFFFFFFFF
        h ^= (h >> 11)
    return h

def enumerate_exports(dll_name: str) -> list:
    k32 = ctypes.windll.kernel32
    base = k32.GetModuleHandleA(dll_name.encode())
    if not base:
        base = k32.LoadLibraryA(dll_name.encode())
    if not base:
        return []
    e_lfanew = ctypes.c_int.from_address(base + 0x3C).value
    export_rva = ctypes.c_uint.from_address(base + e_lfanew + 0x88).value
    if export_rva == 0:
        return []
    export_dir = base + export_rva
    num = ctypes.c_uint.from_address(export_dir + 0x18).value
    names_rva = ctypes.c_uint.from_address(export_dir + 0x20).value
    exports = []
    for i in range(num):
        rva = ctypes.c_uint.from_address(base + names_rva + i * 4).value
        name = ctypes.string_at(base + rva).decode('ascii', errors='ignore')
        exports.append(name)
    return exports

# Target DLLs
DLLS = [
    "kernel32.dll", "ntdll.dll", "kernelbase.dll",
    "user32.dll", "advapi32.dll", "ws2_32.dll",
    "winhttp.dll", "crypt32.dll", "gdi32.dll",
    "shell32.dll", "ole32.dll", "shlwapi.dll",
]

rainbow = {}

# DLL name hashes
for dll in DLLS:
    h = additive_hash_ci(dll.encode())
    rainbow[f"0x{h:08X}"] = f"[DLL] {dll}"

# Function hashes
total = 0
for dll in DLLS:
    exports = enumerate_exports(dll)
    total += len(exports)
    for name in exports:
        h = additive_hash(name.encode())
        rainbow[f"0x{h:08X}"] = f"{dll}!{name}"

print(f"[*] {total} exports from {len(DLLS)} DLLs")
print(f"[*] Rainbow table: {len(rainbow)} entries")

with open("additive_rainbow.json", "w") as f:
    json.dump(rainbow, f, indent=2)
print("[+] Saved to additive_rainbow.json")
```

### Exercise 7: Reverse the Binary's Hash Constants (10 min)

Extract the 13 hash constants from `.rdata` and look them up:

```python
import json

with open("additive_rainbow.json") as f:
    rainbow = json.load(f)

# All hash constants from netdiag.exe .rdata
BINARY_HASHES = [
    0x0B6D79E7, 0x090DD676, 0x0EC9AE0F,  # DLL hashes
    0x1C02DEBA, 0xA234F8D5, 0x9257966A,   # kernel32 functions
    0xA63CFCB1, 0xE95098B3, 0xE8EBE5AB,   # kernel32 functions
    0x7AC89F36,                             # user32 function
    0x4C5F6FA9, 0x4FA8A779, 0xC0E8DF85,   # ntdll functions
]

print("Resolved hash constants:")
for h in BINARY_HASHES:
    key = f"0x{h:08X}"
    name = rainbow.get(key, "??? UNKNOWN")
    print(f"  {key} = {name}")
```

**Expected output** — all 13 resolve:

| Hash | Resolved Name |
|------|--------------|
| `0x0B6D79E7` | `[DLL] kernel32.dll` |
| `0x090DD676` | `[DLL] user32.dll` |
| `0x0EC9AE0F` | `[DLL] ntdll.dll` |
| `0x1C02DEBA` | `kernel32.dll!VirtualAlloc` |
| `0xA234F8D5` | `kernel32.dll!VirtualProtect` |
| `0x9257966A` | `kernel32.dll!CreateThread` |
| `0xA63CFCB1` | `kernel32.dll!WaitForSingleObject` |
| `0xE95098B3` | `kernel32.dll!CloseHandle` |
| `0xE8EBE5AB` | `kernel32.dll!LoadLibraryA` |
| `0x7AC89F36` | `user32.dll!MessageBoxW` |
| `0x4C5F6FA9` | `ntdll.dll!NtAllocateVirtualMemory` |
| `0x4FA8A779` | `ntdll.dll!NtProtectVirtualMemory` |
| `0xC0E8DF85` | `ntdll.dll!NtCreateThreadEx` |

**What this reveals**: The binary has shellcode loading capability (VirtualAlloc + VirtualProtect + CreateThread), cross-DLL pivoting (LoadLibraryA → MessageBoxW), AND native syscall addresses resolved (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx). A single rainbow table lookup reveals the entire capability set.

**One rainbow table, all 15 stages**: Because the hash algorithm is the SAME across the entire Goodboy framework, this rainbow table works on every binary. Build it once, use it forever.

---

## Section 7: Detection Engineering

### YARA Rule: Additive Hash Seed + Multiplier

```yara
rule Goodboy_Additive_Hash_Resolver
{
    meta:
        description = "Detects additive hash API resolver (seed 0x1F2E3D4C, mul 0x1003F)"
        author      = "Goodboy Framework"
        stage       = "04"
        technique   = "T1027.007 (Dynamic API Resolution)"

    strings:
        // gs:[0x60] PEB access (9-byte x64 encoding)
        $peb_access = { 65 48 8B 04 25 60 00 00 00 }

        // Additive hash seed: mov reg, 0x1F2E3D4C
        $seed_eax = { B8 4C 3D 2E 1F }   // mov eax, 0x1F2E3D4C
        $seed_ecx = { B9 4C 3D 2E 1F }   // mov ecx, 0x1F2E3D4C
        $seed_edx = { BA 4C 3D 2E 1F }   // mov edx, 0x1F2E3D4C

        // Multiplier: imul reg, reg, 0x1003F
        $mul_eax = { 69 C0 3F 00 01 00 }  // imul eax, eax, 0x1003F
        $mul_ecx = { 69 C9 3F 00 01 00 }  // imul ecx, ecx, 0x1003F

        // PE magic checks (resolver validates DLL headers)
        $mz_check = { 81 ?? 4D 5A }       // cmp [reg], 0x5A4D
        $pe_check = { 81 ?? 50 45 00 00 }  // cmp [reg], 0x00004550

    condition:
        uint16(0) == 0x5A4D and
        $peb_access and
        any of ($seed_*) and
        any of ($mul_*) and
        ($mz_check or $pe_check)
}
```

### YARA Rule: Known API Hash Constants

```yara
rule Goodboy_Hash_Constants
{
    meta:
        description = "Known additive hash values for shellcode loading APIs"
        author      = "Goodboy Framework"
        stage       = "04"

    strings:
        // VirtualAlloc hash (LE): 0x1C02DEBA
        $h_va = { BA DE 02 1C }
        // VirtualProtect hash (LE): 0xA234F8D5
        $h_vp = { D5 F8 34 A2 }
        // CreateThread hash (LE): 0x9257966A
        $h_ct = { 6A 96 57 92 }
        // LoadLibraryA hash (LE): 0xE8EBE5AB
        $h_ll = { AB E5 EB E8 }

    condition:
        uint16(0) == 0x5A4D and
        3 of ($h_*)
}
```

### The Detection Invariant: gs:[0x60]

The `gs:[0x60]` PEB access byte sequence (`65 48 8B 04 25 60 00 00 00`) is present in ALL 15 Goodboy stages. It's also present in virtually all PEB-walking malware. This single 9-byte pattern is the strongest static detection point in the entire course.

The Stage 01 Sigma rule (detecting RW→RX memory transitions) also still works against Stage 04 — the VirtualAlloc(RW) → VirtualProtect(RX) behavioral pattern is the same.

> **Q6**: Can an attacker avoid the `gs:[0x60]` byte sequence?

<details>
<summary>Answer</summary>

Yes:
1. **Indirect access**: `mov rax, gs:[0x30]` (TEB self-pointer), then `mov rax, [rax+0x60]` — different bytes, same result
2. **NtQueryInformationProcess**: Syscall returning PEB address — no gs-segment access
3. **Computed offset**: Build 0x60 from arithmetic so it never appears as an immediate

**Defense response**: Target the BEHAVIOR (linked list traversal + PE header parsing) rather than a specific instruction. ETW traces all approaches.

</details>

---

## Section 7B: Blue Team — Dynamic Detection of Hash-Based Resolution

### Exercise 8: Trace Resolved APIs with API Monitor (15 min)

API Monitor intercepts at the function entry point — it catches calls regardless of how the binary found the address (IAT import, GetProcAddress, or PEB-walking hash resolution).

**Steps**:
1. Download API Monitor (free, rohitab.com)
2. Configure to monitor: `kernel32.dll!VirtualAlloc`, `kernel32.dll!VirtualProtect`, `kernel32.dll!CreateThread`, `kernel32.dll!LoadLibraryA`, `user32.dll!MessageBoxW`
3. Launch `netdiag.exe` under API Monitor
4. Observe: ALL five calls appear in the trace even though NONE are in the IAT

**Key insight**: Dynamic API resolution defeats static analysis (IAT examination) but NOT runtime monitoring. API Monitor, ETW, and debugger breakpoints all see the resolved calls. The hiding is partial — it only works against tools that examine the binary without executing it.

**Compare with IAT analysis**: Open `netdiag.exe` in PE-bear. The import table shows only benign APIs (GetSystemInfo, GetTickCount64). Now compare with the API Monitor trace — the gap between "what the IAT shows" and "what actually gets called" is the entire attack surface that hash-based resolution hides.

### Exercise 9: Capability Assessment from Rainbow Table (15 min)

**Scenario**: You're a threat analyst. You've built the rainbow table and reversed the 13 hash constants. Write a capability assessment.

**Your rainbow table output**:
```
0x0B6D79E7 = [DLL] kernel32.dll
0x090DD676 = [DLL] user32.dll
0x0EC9AE0F = [DLL] ntdll.dll
0x1C02DEBA = kernel32.dll!VirtualAlloc
0xA234F8D5 = kernel32.dll!VirtualProtect
0x9257966A = kernel32.dll!CreateThread
0xA63CFCB1 = kernel32.dll!WaitForSingleObject
0xE95098B3 = kernel32.dll!CloseHandle
0xE8EBE5AB = kernel32.dll!LoadLibraryA
0x7AC89F36 = user32.dll!MessageBoxW
0x4C5F6FA9 = ntdll.dll!NtAllocateVirtualMemory
0x4FA8A779 = ntdll.dll!NtProtectVirtualMemory
0xC0E8DF85 = ntdll.dll!NtCreateThreadEx
```

**Complete this assessment**:

| Capability | Evidence (APIs) | Risk Level |
|-----------|----------------|------------|
| Code injection (same-process) | ___ | ___ |
| Cross-DLL pivoting | ___ | ___ |
| Native syscall capability | ___ | ___ |
| User interaction | ___ | ___ |

<details>
<summary>Completed Assessment</summary>

| Capability | Evidence | Risk Level |
|-----------|----------|------------|
| Code injection (same-process) | VirtualAlloc + VirtualProtect + CreateThread = allocate → protect → execute chain | HIGH — classic shellcode loader pattern |
| Cross-DLL pivoting | LoadLibraryA = can load ANY DLL and resolve ANY export | HIGH — extends attack surface beyond pre-loaded DLLs |
| Native syscall capability | NtAllocateVirtualMemory + NtProtectVirtualMemory + NtCreateThreadEx resolved from ntdll | HIGH — can bypass kernel32/kernelbase hooks entirely. Even if these aren't called NOW, the binary has the addresses ready |
| User interaction | MessageBoxW from user32.dll | LOW — proof-of-execution indicator, not offensive by itself |

**Threat summary**: This binary is a shellcode loader with cross-DLL pivoting and latent syscall capability. The ntdll API resolution suggests the framework has or will have direct syscall variants (confirmed: Stage 07). The VirtualAlloc+VirtualProtect+CreateThread chain combined with PEB-walking resolution is consistent with Cobalt Strike beacon loaders, MuddyWater RustyWater, and similar post-exploitation frameworks.

**Recommended detection priority**:
1. YARA: Deploy `Goodboy_Additive_Hash_Resolver` and `Goodboy_Hash_Constants` rules
2. EDR: Alert on processes that call LoadLibraryA followed by immediate export table reads (not GetProcAddress)
3. ETW: Monitor NtProtectVirtualMemory for RW→RX transitions from unsigned binaries
4. Memory: Scan for executable private memory regions (pe-sieve/Moneta) in processes matching YARA hits

</details>

### Exercise 10: Detect the LoadLibraryA → Export Walk Pattern (10 min)

Stage 04 introduces a new behavioral pattern not seen in Stages 01-03: after calling `LoadLibraryA`, the binary immediately walks the PEB module list and parses the newly loaded DLL's export table. Legitimate software calls `GetProcAddress` after `LoadLibraryA` — it doesn't manually parse PE headers.

**Detection approach using ETW**:

The Microsoft-Windows-Kernel-Process provider logs `LoadLibraryA` calls. If an unsigned process loads a DLL and then accesses the DLL's export table memory region (readable via page fault telemetry or hardware breakpoints), the sequence is suspicious.

**Detection approach using x64dbg** (for manual analysis):

1. Set breakpoint on `LoadLibraryA` (system function, not the resolved one)
2. When it hits, note which DLL is loaded (RCX = pointer to DLL name string)
3. After the call returns (RAX = DLL base address), set a hardware read breakpoint on that module's export directory
4. If the export directory breakpoint fires from the SAME process within milliseconds — the process is walking exports manually instead of using GetProcAddress

**Why this pattern matters**: `GetProcAddress` is the legitimate way to resolve functions from a loaded DLL. Manual export table parsing after LoadLibraryA indicates the binary is avoiding `GetProcAddress` — either to hide from IAT analysis or because it uses hash-based resolution. Both are strong indicators of offensive tooling.

> **Q7**: Could a legitimate application trigger this pattern (LoadLibraryA + immediate export walk)?

<details>
<summary>Answer</summary>

Rarely, but yes:
- **Plugin systems** that support multiple DLL formats may parse PE headers to validate the plugin before calling its entry point
- **DRM/anti-cheat** software sometimes walks export tables to verify DLL integrity
- **.NET CLR** and **Java JNI** perform some PE introspection when loading native libraries

However, the COMBINATION of: (1) PEB-walking API resolution, (2) hash constants in .rdata, (3) LoadLibraryA + export walk, and (4) subsequent VirtualAlloc + VirtualProtect + CreateThread is extremely unlikely in legitimate software. Each indicator alone has false positives; together they are definitive.

</details>

---

## Section 8: Adversarial Thinking

### Challenge 1: Defeat the Rainbow Table

An analyst builds a rainbow table and reverses all 13 hash constants. How do you prevent this?

<details>
<summary>Approaches</summary>

1. **Per-binary salt**: XOR the hash seed with a value derived from the PE timestamp. Each build uses a different effective seed — the analyst's rainbow table doesn't work on the next binary
2. **Runtime seed derivation**: Compute the seed from environment data (e.g., hostname hash). The seed changes per machine
3. **Obfuscated constants**: Store hashes as `hash ^ 0xDEADBEEF` in .rdata. XOR with mask at runtime. The analyst can't rainbow-table the obfuscated values without finding the mask
4. **Algorithm polymorphism**: Compile a different hash algorithm per build. The analyst must reverse the algorithm for each binary independently

**The practical reality**: Most malware doesn't bother defeating rainbow tables. The value of API hashing is eliminating IAT strings (defeating STATIC analysis). A human analyst with a debugger can always trace runtime API resolution regardless of the hash algorithm.

</details>

### Challenge 2: Defeat the PEB Access YARA Rule

Your YARA rule targets `65 48 8B 04 25 60 00 00 00`. How does the attacker avoid this exact byte sequence?

<details>
<summary>Approaches</summary>

1. **TEB self-pointer**: `mov rax, gs:[0x30]` then `mov rax, [rax+0x60]` — two instructions instead of one
2. **NtQueryInformationProcess**: Returns PEB address via syscall — no gs-segment access
3. **Computed offset**: `xor rcx, rcx; add cl, 0x60; mov rax, gs:[rcx]` — offset built at runtime
4. **Different segment usage**: On WoW64, `fs:[0x30]` points to the 32-bit PEB

**Defense**: Write YARA rules that match ANY `gs:` access (`{ 65 48 8B }`) near PE header parsing patterns. The combination of segment register access + export table walking is the invariant, not the specific encoding.

</details>

### Challenge 3: The Binary Leaks Framework Capabilities

The 13 hash constants reveal VirtualAlloc + CreateThread (shellcode loading), LoadLibraryA (DLL pivoting), MessageBoxW (UI interaction), AND NtAllocateVirtualMemory/NtCreateThreadEx (syscall capability). How do you prevent this information leak?

<details>
<summary>Approaches</summary>

1. **Only include needed constants**: Stage 04 resolves 10 APIs but the 3 ntdll constants are unused. A per-binary build that strips unused constants leaks less
2. **Runtime computation**: Instead of storing pre-computed hashes in .rdata, hash the API name string at runtime (encrypted strings, decrypted on the fly). No hash constants in the binary
3. **Hash chaining**: Store `hash(hash(name))` and iterate twice at runtime. The outer hash doesn't match a standard rainbow table
4. **The real lesson**: Shared code libraries (like `common`) leak capabilities. Every Goodboy binary contains ALL hash constants from the library, even unused ones. Modular compilation (per-crate constants only) is the fix

</details>

---

## Section 9: The Complete Execution Chain

### Stage 04 Flow — What's New vs Stages 01-03

```
netdiag.exe execution:
  init_app_config()              [gate 1 — benign code mass]
  verify_env()                   [gate 2 — 5 env var checks]
  preflight()                    [gate 3 — extended env checks]
  PEB.BeingDebugged check        [gate 4 — anti-debug]
  sandbox_check()                [gate 5 — CPU/RAM/disk/uptime]

  ┌─── NEW: Cross-DLL Resolution ────────────────────────────┐
  │ resolve_api(kernel32, LoadLibraryA)  → function pointer  │
  │ LoadLibraryA("user32.dll")           → user32 loaded     │
  │ resolve_api(user32, MessageBoxW)     → function pointer  │
  │ MessageBoxW("GoodBoy", "Stage 04")  → dialog appears     │
  └──────────────────────────────────────────────────────────┘

  ┌─── NEW: ntdll Enumeration ───────────────────────────────┐
  │ resolve_api(ntdll, NtAllocateVirtualMemory)  → stored    │
  │ resolve_api(ntdll, NtProtectVirtualMemory)   → stored    │
  │ resolve_api(ntdll, NtCreateThreadEx)         → stored    │
  │ (resolved but not called — foreshadows Stage 07)         │
  └──────────────────────────────────────────────────────────┘

  XOR decrypt shellcode            [same as Stages 01-02]
  resolve VirtualAlloc             [kernel32 hash resolution]
  VirtualAlloc(RW)                 [allocate]
  copy shellcode                   [memcpy]
  write_volatile scrub             [anti-forensics]
  VirtualProtect(RX)               [W^X transition]
  CreateThread                     [execute]
  WaitForSingleObject + CloseHandle
```

**The user sees TWO MessageBoxes**:
1. First: "GoodBoy" / "Stage 04" — from the direct API call (cross-DLL resolution proof)
2. Second: "GoodBoy" / "OK" — from the shellcode (same as Stages 01-03)

---

## Section 10: Knowledge Check

**1. The binary contains hash `0x4C5F6FA9`. What API does this resolve to, and from which DLL?**

<details>
<summary>Answer</summary>

`ntdll.dll!NtAllocateVirtualMemory`. This is the native API equivalent of `kernel32!VirtualAlloc`. It's resolved in Stage 04 but not called — foreshadowing Stage 07 where it becomes the primary allocation function (bypassing kernel32 hooks).

</details>

**2. Why must LoadLibraryA be resolved BEFORE MessageBoxW?**

<details>
<summary>Answer</summary>

MessageBoxW lives in user32.dll. In a console application (no GUI), user32.dll is not loaded by default — it's not in the PEB module list. The hash resolver walks the module list and won't find user32. LoadLibraryA loads user32.dll into the process, adding it to the PEB module list. Only then can the resolver find MessageBoxW.

The order is: resolve LoadLibraryA (from kernel32, always loaded) → call LoadLibraryA("user32.dll") → resolve MessageBoxW (from user32, now loaded).

</details>

**3. You find `0x1F2E3D4C` and `0x1003F` near each other in a binary. What is this?**

<details>
<summary>Answer</summary>

The Goodboy additive hash algorithm. `0x1F2E3D4C` is the seed, `0x1003F` is the multiplier. The third component is `shr reg, 11` (bit diffusion). Finding these two constants together is sufficient to identify the algorithm and build a rainbow table.

</details>

**4. Your rainbow table resolves 10 of 13 constants but 3 return "UNKNOWN." What went wrong?**

<details>
<summary>Answer</summary>

The 3 unknowns are likely the DLL name hashes (case-insensitive). Your rainbow table was built with `additive_hash()` (case-sensitive) for everything. DLL names require `additive_hash_ci()` (case-insensitive). Rebuild with both hash variants.

Alternatively: the unknowns might be from a DLL not in your scan list (e.g., winhttp.dll, iphlpapi.dll). Expand your DLL list.

</details>

**5. The `gs:[0x60]` instruction is the strongest detection point. It appears in all 15 stages. Why can't it be eliminated?**

<details>
<summary>Answer</summary>

The PEB is the ONLY undocumented-but-stable source of loaded module information accessible from user mode without calling any API. You need the module list to find DLL base addresses. You need DLL base addresses to parse export tables. You need export tables to resolve API functions by hash.

The alternatives (NtQueryInformationProcess, scanning memory for MZ headers) all have their own detection signatures. The fundamental requirement — "find loaded DLLs without calling documented APIs" — always leads back to the PEB.

This is why the PEB walk is a detection **invariant**: the technique can evolve (different lists, different access patterns) but the underlying data source cannot be avoided.

</details>

---

## Module Summary

| Concept | Stage 01-03 | Stage 04 (NEW) |
|---------|-------------|----------------|
| Hash algorithm | Used but unexplained | **Full deep dive: seed, multiplier, shift, disassembly patterns** |
| DLLs resolved | kernel32 only (5 APIs) | **3 DLLs: kernel32 (6) + user32 (1) + ntdll (3) = 13 constants** |
| Cross-DLL pivot | Never done | **LoadLibraryA → user32 → MessageBoxW** |
| Rainbow tables | Never built | **Build table for ~5,000 exports, reverse all 13 constants** |
| PEB internals | Shallow (gs:[0x60] → Ldr) | **Full chain: TEB → PEB → Ldr → module list → LDR_DATA_TABLE_ENTRY** |
| Export table | Implicit (find_export exists) | **Three parallel arrays, ordinal lookup, linear scan analysis** |
| Detection | Generic RW→RX Sigma | **YARA for seed+multiplier, gs:[0x60] invariant, hash constant matching** |
| Direct API call | Never (always via shellcode) | **MessageBoxW called directly — no shellcode needed for proof** |
| ntdll awareness | None | **3 Nt* API hashes resolved — foreshadows Stage 07** |
| Binary naming | Stage numbers in filenames | **netdiag.exe — operational naming tradecraft** |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "API hashing completely hides which APIs are used" | It hides them from STATIC analysis (IAT). Dynamic analysis (debugger, ETW, API Monitor) sees every resolved call. Rainbow tables reverse the hash constants statically |
| "Changing the hash algorithm defeats rainbow tables" | Only until the analyst reverses the new algorithm. The structural PATTERN (loop over exports, hash, compare) is detectable regardless |
| "32-bit hashes have too many collisions" | With ~1,600 kernel32 exports, collision probability per lookup is ~0.003%. Negligible in practice |
| "PEB walking is unique to malware" | Some legitimate software walks the PEB (DRM, anti-cheat, crash reporters). But PEB walk + hash comparison + export parsing is overwhelmingly malware-associated |
| "The gs:[0x60] YARA rule is easy to bypass" | Technically yes (TEB indirection, syscall). In practice, 95%+ of PEB-walking malware uses the direct gs:[0x60] encoding. The YARA rule has excellent real-world coverage |
| "ntdll hashes in the binary mean it uses syscalls" | Not necessarily — Stage 04 resolves them but doesn't call them. The hash constants are a capability indicator, not proof of use. Stage 07 is where syscalls actually happen |

### What Breaks at Stage 05 — The Bridge

You've mastered how the binary resolves APIs from any DLL. Stage 05 uses the SAME resolver but escalates: **cross-process injection**.

Stages 01-04 execute shellcode in their own process. Stage 05 opens a target process (e.g., notepad.exe), allocates memory INSIDE it, writes shellcode into it, and creates a thread in the target's context. This means:
- The offensive APIs change: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
- Sysmon Event ID 8 (CreateRemoteThread) fires for the first time
- The shellcode runs under the target's identity, not the loader's
- Memory scanners must scan EVERY process, not just the suspect one

Your rainbow table already covers these APIs — but detecting cross-process injection requires behavioral analysis beyond static hash matching.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Dynamic API Resolution | T1027.007 | PEB-walking + additive hash resolution |
| Native API | T1106 | VirtualAlloc, VirtualProtect, CreateThread via resolved pointers |
| Obfuscated Files | T1027 | XOR-encrypted shellcode in .rdata |
| Reflective Code Loading | T1620 | VirtualAlloc + VirtualProtect + CreateThread in own process |
| Shared Modules | T1129 | LoadLibraryA to load user32.dll at runtime |
| Masquerading | T1036 | Binary named "netdiag.exe" (mimics system utility) |

### Further Reading (2025-2026)

**API hashing techniques:**
- [cocomelonc: Syscalls Part 1-2](https://cocomelonc.github.io/malware/2023/06/07/syscalls-1.html) — From API hashing to direct syscalls (the Stage 04 → Stage 07 progression)
- [cocomelonc: Malware Tricks 27-55](https://cocomelonc.github.io/malware/2023/04/27/malware-tricks-27.html) — Offensive techniques including hash-based resolution

**PEB internals:**
- ReactOS source code (`reactos.org`) — Open-source PEB/LDR structure definitions
- [Microsoft RIFT](https://www.microsoft.com/en-us/security/blog/2025/06/27/unveiling-rift-enhancing-rust-malware-analysis-through-pattern-matching/) — How defenders analyze Rust binaries using PEB structures

**Detection engineering:**
- [Oblivion: Detecting Syscalls](https://oblivion-malware.xyz/posts/detecting-syscalls/) — Detection approaches for PEB-walking patterns
- [WindShock: Endpoint Evasion 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — Where API hashing fits in the evasion evolution

## What's Next

- **Stage 05 (APC Injection)**: The loader breaks out of its own process — injecting shellcode into a remote process via Early Bird APC injection
- **Stage 07 (Direct Syscalls)**: The ntdll hashes you found in Stage 04's `.rdata` become the execution path — bypassing kernel32 entirely
