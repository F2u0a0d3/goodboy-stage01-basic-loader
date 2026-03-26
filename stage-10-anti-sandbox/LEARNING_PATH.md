# Stage 10: Anti-Sandbox — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Sandbox Detection and Environment Fingerprinting |
| **Level** | Intermediate-Advanced |
| **Estimated Time** | 5-6 hours |
| **Category** | Anti-Analysis / Evasion |
| **Platform** | Windows x64 |
| **Binary** | `anti-sandbox.exe` (~264KB, Rust, PE64, self-contained) |
| **Prerequisites** | Stage 09 (anti-debug fundamentals) |
| **VT Score** | **0/76 → 1/76** (achieved 0/76 on 2026-03-12, decayed to 1/76 by 2026-03-17) |

### VT Detection Journey

```
 ██████████████████████████████████████ 0/76  ← ACHIEVED (March 12, 2026)
 █████████████████████████████████████░ 1/76  ← CURRENT  (March 17, 2026)
                                               ESET Agent.ION (sample-burned)

 KEY EVASION LESSON: The original anti-sandbox implementation used string-based
 VM detection (username checks for "sandbox"/"malware", file checks for
 "VBoxMouse.sys", MAC OUI prefixes). These STRINGS triggered CrowdStrike ML
 at 60% confidence — the word "sandbox" in your binary IS a malware signature.

 The fix: remove ALL string-based VM/sandbox checks. Keep ONLY hardware-metric
 checks (CPU, RAM, disk, uptime, screen) that use numeric comparisons without
 suspicious strings. Result: 0/76.

 This binary uses direct windows-sys imports (GetSystemInfo, GlobalMemoryStatusEx,
 GetDiskFreeSpaceExW, GetTickCount64, GetSystemMetrics) which are CFG-safe.
 Self-contained (no common library) — all PEB walking, hash resolution,
 anti-debug, and sandbox checks are inlined.
```

---

## Why This Stage Exists — The Bridge from Stage 09

Stage 09 detects **human analysts** (debuggers, analysis tools). Stage 10 detects **automated systems** (sandboxes, VMs, detonation chambers).

The distinction matters because the adversaries are different:
- **Debuggers** use PEB flags, debug ports, timing anomalies, hardware breakpoints
- **Sandboxes** use minimal hardware, default usernames, fresh environments, accelerated sleep

**What's new in this binary compared to Stage 09:**
1. **5 hardware-metric sandbox checks** — CPU cores, RAM, disk, uptime, screen resolution
2. **Weighted scoring** — not binary pass/fail but a threshold score (≥3 = sandbox)
3. **Direct windows-sys imports** for system info APIs (CFG-safe, no common library sandbox module)
4. **No string-based VM detection** — removed username/computername/MAC/registry/file checks that triggered CrowdStrike ML

**What the learning path also covers** (general sandbox detection knowledge beyond what this binary implements):
- Username/computername detection (removed from binary but important to understand)
- MAC OUI prefixes (removed but taught for analysis context)
- VM registry keys and driver files (removed but relevant for threat intel)
- Sleep acceleration and cursor movement detection (advanced techniques for reference)

### Real-World Context (2025-2026)

- **GuLoader** (2023-2025) — Uses 14+ sandbox checks including all techniques taught here
- **Cobalt Strike 4.11** (May 2025) — Profile-based sandbox evasion with configurable checks
- **cocomelonc: Malware Tricks 36-55** ([2023-2025](https://cocomelonc.github.io/malware/2023/09/25/malware-trick-36.html)) — Latest anti-sandbox techniques in C
- **Altered Security CETP** ([March 2026](https://www.alteredsecurity.com/evasionlab)) — Sandbox bypass as a core assessment competency

---

## Section 0: Source Code Deep Dive — Hardware-Only Sandbox Detection

### What the Binary Actually Checks

```rust
unsafe fn check_sandbox() -> (bool, u32) {
    let mut score = 0u32;

    // Check 1: CPU cores < 2 (score +1)
    let mut si: SYSTEM_INFO = core::mem::zeroed();
    GetSystemInfo(&mut si);
    if si.dwNumberOfProcessors < 2 { score += 1; }
    // ^^^ GetSystemInfo is a benign system info API — used by every hardware
    // diagnostic tool, game, and system utility. NOT suspicious in IAT.

    // Check 2: RAM < 4 GB (score +1)
    let mut mem: MEMORYSTATUSEX = core::mem::zeroed();
    mem.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut mem);
    if mem.ullTotalPhys / (1024 * 1024 * 1024) < 4 { score += 1; }

    // Check 3: Disk < 60 GB (score +1)
    let c_path = to_wide("C:\\");
    GetDiskFreeSpaceExW(c_path.as_ptr(), ...);
    if total_bytes / (1024 * 1024 * 1024) < 60 { score += 1; }

    // Check 4: Uptime < 30 minutes (score +1)
    if GetTickCount64() / 60000 < 30 { score += 1; }
    // ^^^ Uses GetTickCount64 (standard Windows API).
    // The 30-minute threshold catches sandboxes with fresh VM snapshots.
    // GetTickCount64 is hookable by EDR — see "Unhookable System Info"
    // in the Adversarial Thinking section for alternatives.

    // Check 5: Screen < 800x600 (score +1)
    let width = GetSystemMetrics(0);  // SM_CXSCREEN
    let height = GetSystemMetrics(1); // SM_CYSCREEN
    if width < 800 || height < 600 { score += 1; }

    (score >= SANDBOX_THRESHOLD, score)
    // SANDBOX_THRESHOLD = 3 — need 3+ checks to fail
    // Real workstation: score 0 (all pass)
    // Default sandbox VM: score 3-5 (CPU + RAM + uptime typically fail)
}
```

### Comparison with Stage 09: Two Sides of Anti-Analysis

```
Stage 09 (Anti-Debug)                   Stage 10 (Anti-Sandbox)
─────────────────────                   ──────────────────────
Detects: HUMAN analysts                 Detects: AUTOMATED systems
How:     Reads debug structures          How:     Reads hardware metrics
         (PEB, kernel objects, DR regs)           (CPU, RAM, disk, uptime, screen)
APIs:    NtQueryInformationProcess       APIs:    GetSystemInfo, GlobalMemoryStatusEx
         GetThreadContext                         GetDiskFreeSpaceExW, GetTickCount64
         RDTSC (no API call)                      GetSystemMetrics
Result:  Binary (debugged or not)        Result:  Weighted score vs. threshold
Exit:    Immediate (any check fails)     Exit:    Only if score >= SANDBOX_THRESHOLD
False+:  Low (debug structures clear)    False+:  Very low (real HW always passes)
```

Anti-debug detects a state (is a debugger attached right now?). Anti-sandbox detects an environment (does this machine look real?). A real analyst machine passes all sandbox checks but fails debug checks. A sandbox passes debug checks (no debugger attached) but fails hardware checks.

### The SANDBOX_THRESHOLD Constant

```rust
const SANDBOX_THRESHOLD: u32 = 3;
```

The threshold of 3 is calibrated against two populations:

```
Real workstation scores:
  CPU: 8 cores  → 0    (passes < 2)
  RAM: 16 GB    → 0    (passes < 4)
  Disk: 500 GB  → 0    (passes < 60)
  Uptime: 4320m → 0    (passes < 30)
  Screen: 1920  → 0    (passes < 800)
  Total: 0 — well below threshold

Default sandbox scores:
  CPU: 1 core   → 1    (fails < 2)
  RAM: 2 GB     → 1    (fails < 4)
  Disk: 40 GB   → 1    (fails < 60)
  Uptime: 3 min → 1    (fails < 30)
  Screen: 1024  → 0    (passes < 800)
  Total: 4 — well above threshold

Hardened sandbox scores:
  CPU: 4 cores  → 0    (passes)
  RAM: 8 GB     → 0    (passes)
  Disk: 100 GB  → 0    (passes)
  Uptime: 5 min → 1    (still fails < 30)
  Screen: 1920  → 0    (passes)
  Total: 1 — below threshold, BYPASSES detection
```

A threshold of 3 separates default sandboxes (score 3-5) from real workstations (score 0) with maximum margin. Lowering to 2 risks false positives on constrained laptops. Raising to 4 misses some sandboxes that fix one or two settings. The value 3 is the empirical sweet spot.

### Why Hardware-Only (No String-Based Checks)

A critical evasion lesson from the development of this binary:

> **Sandbox evasion string literals trigger CrowdStrike ML**: Plaintext strings "sandbox", "malware", "virus", "vmmouse.sys", "VBoxMouse.sys" etc. in the binary trigger CrowdStrike win/malicious_confidence_60%. Removing them and keeping only hardware-metric checks achieved 0/76.

Earlier versions included username checks, MAC OUI checks, registry probes, and driver file checks. ALL of these required string literals that ARE malware signatures:
- `"sandbox"` → AV ML signature
- `"VBoxMouse.sys"` → AV ML signature
- `"VMware"` → AV ML signature

The hardware-only approach uses NUMERIC comparisons — no suspicious strings, no filesystem access patterns, no registry probes. The APIs (GetSystemInfo, GlobalMemoryStatusEx, etc.) are the same ones that ANY system utility calls.

### Architecture: 7-Gate Progression

```
Gate 1: init_app_config()           ← benign config (BTreeMap, env vars, paths)
Gate 2: verify_env()                ← environment validation (SystemRoot, USERPROFILE, etc.)
Gate 3: preflight()                 ← benign preflight (env vars, directory checks)
Gate 4: PEB.BeingDebugged           ← quick anti-debug (direct PEB read)
Gate 5: run_gui_lifecycle()         ← GUI camouflage (RegisterClassW + CreateWindowExW + message pump)
Gate 6: is_debugged()               ← full anti-debug gauntlet (7 checks from Stage 09)
Gate 7: check_sandbox() ≥ 3        ← hardware sandbox detection (Stage 10 NEW)
```

Each stage adds one or two gates. By Stage 10, the binary has 7 sequential checks that an analyst or sandbox must pass before reaching the payload. All gates are self-contained (no common library).

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** the difference between anti-debug and anti-sandbox techniques
2. **Categorize** sandbox detection methods by layer (hardware, environment, behavioral, VM artifacts)
3. **Analyze** weighted scoring systems and threshold-based decision logic
4. **Identify** VM fingerprints across VMware, VirtualBox, Hyper-V, QEMU/KVM, and Xen
5. **Understand** timing-based evasion (sleep acceleration, cursor tracking)
6. **Build** detection rules for sandbox-evasive binaries
7. **Harden** analysis environments to defeat common sandbox checks

---

## Section 1: Theory — Sandbox vs. Debugger

### Different Threats, Different Evasion

```
Debugger (Stage 09):                Sandbox (Stage 10):
┌─────────────────────┐            ┌─────────────────────┐
│ Analyst is present  │            │ Automated analysis  │
│ Real-time control   │            │ No human operator   │
│ Can modify state    │            │ Fixed time window    │
│ Real hardware       │            │ Usually virtualized │
│ Normal environment  │            │ Minimal environment │
└─────────────────────┘            └─────────────────────┘

Detection approach:                Detection approach:
  Check debug structures            Check environment reality
  (PEB, kernel objects)             (hardware, users, activity)
```

Anti-debug answers: "Is someone watching me?"
Anti-sandbox answers: "Is this a real computer?"

### Sandbox Lifecycle

```
1. Sample received → queued for analysis
2. VM snapshot restored (clean state)
3. Sample executed in VM
4. Behavioral monitoring for 60-120 seconds
5. Report generated (API calls, network, files)
6. VM reverted to snapshot

Key sandbox weaknesses:
- Short execution window (Sleep evasion)
- Fresh VM state (no user artifacts)
- Minimal hardware allocation (cost optimization)
- Known VM software artifacts
- No real user activity
```

### Exercise 1.1: Why Not Just Check for VMs?

**Question**: Many legitimate users run Windows in VMs (developers, IT admins). Why does the binary use a scoring system instead of a single "is this a VM?" check?

<details>
<summary>Answer</summary>

A scoring system reduces false positives on legitimate VM users:

1. **Single-check approach**: If `check_vm_registry_keys()` alone triggered exit, every developer running VirtualBox would be affected. This is too aggressive.

2. **Scoring approach**: A developer's VM typically has:
   - 4+ CPUs (score: 0), 8+ GB RAM (0), real username (0), real screen (0)
   - But: VirtualBox registry keys (+2), VBox MAC address (+2)
   - Total: 4 — above threshold, still exits

3. **Optimal scoring**: The threshold of 3 with weighted scores means:
   - A sandbox with 1 CPU + sandbox username + sleep accel = 1+2+3 = 6 ✓ (detected)
   - A developer VM with only VBox keys = 2 (below threshold, safe)
   - Adding MAC OUI check = 2+2 = 4 (detected — developer VMs still caught)

4. **The real trade-off**: Malware authors must balance detection rate (catch all sandboxes) vs. false positive rate (don't crash on legitimate VMs). The scoring system allows tuning this balance by adjusting weights and threshold.

In practice, sophisticated malware uses much higher thresholds (10-15) with many low-weight checks, accepting that some sandboxes may pass in exchange for never false-positive-ing on real users.

</details>

---

## Section 2: Hardware Fingerprinting

### CPU, RAM, and Disk Checks

Sandboxes minimize resource allocation to run multiple instances:

```
Check          | Threshold | Typical Sandbox | Typical Workstation
─────────────────────────────────────────────────────────────────
CPU cores      | < 2       | 1-2 cores       | 4-16 cores
Total RAM      | < 4 GB    | 1-2 GB          | 8-32 GB
Disk size      | < 60 GB   | 20-40 GB        | 256 GB - 2 TB
Uptime         | < 30 min  | 1-5 min         | Hours to days
```

### System Uptime

```
GetTickCount64() returns milliseconds since boot.

Sandbox timeline:
  t=0s:   VM snapshot restored
  t=2s:   Sample starts executing
  t=5s:   Uptime check: 5000ms / 60000 = 0.08 minutes → DETECTED

Real system:
  t=0:    Boot (hours/days ago)
  ...:    Normal use
  t=now:  Sample runs: uptime = 480+ minutes → CLEAN
```

### Exercise 2.1: Hardening Your Analysis VM

**Question**: How would you configure a VirtualBox analysis VM to pass all four hardware checks?

<details>
<summary>Answer</summary>

VirtualBox settings:

1. **CPU Count** (pass `< 2` check):
   ```
   Settings → System → Processor → Processor(s): 4
   ```

2. **RAM Size** (pass `< 4 GB` check):
   ```
   Settings → System → Motherboard → Base Memory: 8192 MB
   ```

3. **Disk Size** (pass `< 60 GB` check):
   ```
   VBoxManage modifymedium disk "vm.vdi" --resize 102400  (100 GB)
   Then extend partition inside guest OS
   ```

4. **Uptime** (pass `< 30 min` check):
   ```
   Boot the VM and wait 30+ minutes before running samples
   Or: use a saved state (not snapshot) that preserves uptime
   ```

Key insight: These are the **cheapest** checks to bypass. Allocating 4 CPUs and 8 GB RAM to an analysis VM is trivial. The uptime check requires patience or saved state tricks. This is why hardware checks have low weight (+1) in the scoring system.

</details>

---

## Section 3: Environment Fingerprinting (Reference — NOT in Stage 10 Binary)

> **Note**: The techniques in Sections 3-4 (username detection, MAC OUI, registry probes, driver file checks) are **NOT implemented** in the Stage 10 binary. This stage intentionally avoids string-based VM detection because those strings are AV ML signatures. These sections teach general sandbox detection knowledge for threat intelligence and blue team context. The actual Stage 10 binary uses **only** the hardware-metric checks from Section 2.

### Username and Computer Name Detection

Sandbox platforms use default or predictable names:

```
Known sandbox usernames (18 entries):
  Generic:   sandbox, malware, virus, sample, test, user, admin, currentuser
  Specific:  john doe, tequilaboomboom, joe sandbox, peter wilson,
             miller, phil, hong lee, emily, hapubws, maltest, sandbox_user

Known sandbox computer patterns (10 entries):
  Generic:   sandbox, malware, virus, sample, test, analysis
  Prefix:    desktop-, win-, pc-
  Specific:  john-pc

Special rule: computer name < 4 characters → suspicious
  (auto-generated sandbox names are often short random strings)
```

### Screen Resolution

```
GetSystemMetrics(SM_CXSCREEN) → width
GetSystemMetrics(SM_CYSCREEN) → height

Sandbox: 800x600 or 1024x768 (minimal display)
Real:    1920x1080+ (modern monitors)

Check: width < 800 OR height < 600 → sandbox
```

### Process Count

```
CreateToolhelp32Snapshot + Process32First/NextW → count all processes

Sandbox:  10-25 processes (minimal OS + monitoring agent)
Real:     50-200+ processes (browser, Outlook, Teams, services, etc.)

Check: total_processes < 30 → sandbox
```

### Exercise 3.1: The "tequilaboomboom" Username

**Question**: Several sandbox usernames in the list seem random or humorous. Where do these come from?

<details>
<summary>Answer</summary>

These usernames are defaults from specific commercial and open-source sandbox platforms:

- **"tequilaboomboom"**: Norman Sandbox (legacy automated malware analysis)
- **"joe sandbox"**: Joe Sandbox (commercial platform, joesandbox.com)
- **"peter wilson"**: Cuckoo Sandbox default in some configurations
- **"hapubws"**: ANY.RUN default user profile
- **"emily"**: Hybrid Analysis (CrowdStrike Falcon Sandbox)
- **"hong lee"**: Threat Grid (Cisco) default profile
- **"miller"** / **"phil"**: Various AV vendor sandbox environments

Malware authors maintain lists of known sandbox defaults by:
1. Submitting benign test binaries to sandbox services
2. The test binary logs `GetUserNameW` and `GetComputerNameW` results
3. The results are exfiltrated (DNS, HTTP) and added to the detection list

This is an ongoing cat-and-mouse: sandbox vendors change defaults, malware lists get updated. Modern sandboxes use randomized usernames from realistic name pools.

</details>

---

## Section 4: VM Artifact Detection (Reference — NOT in Stage 10 Binary)

### MAC Address OUI Prefixes

Network adapter manufacturers are assigned unique 3-byte OUI (Organizationally Unique Identifier) prefixes. VM software uses vendor-specific OUI ranges:

```
OUI Prefix    Vendor            Binary Constant
──────────────────────────────────────────────────
00:0C:29      VMware            mac[0..3] == [0x00, 0x0C, 0x29]
00:50:56      VMware (manual)   mac[0..3] == [0x00, 0x50, 0x56]
00:05:69      VMware (legacy)   mac[0..3] == [0x00, 0x05, 0x69]
08:00:27      VirtualBox        mac[0..3] == [0x08, 0x00, 0x27]
00:15:5D      Hyper-V           mac[0..3] == [0x00, 0x15, 0x5D]
52:54:00      QEMU/KVM          mac[0..3] == [0x52, 0x54, 0x00]
00:16:3E      Xen               mac[0..3] == [0x00, 0x16, 0x3E]
```

A string-based implementation would load `iphlpapi.dll` dynamically (via `LoadLibraryA` + `GetProcAddress`) and call `GetAdaptersInfo` to enumerate all network adapters. **This binary does NOT do this** — MAC OUI checks are taught here as reference knowledge only.

### VM Registry Keys

A string-based implementation would probe 11 registry paths under HKLM (again, **NOT in this binary** — reference only):

```
VMware artifacts:
  SOFTWARE\VMware, Inc.\VMware Tools
  SYSTEM\CurrentControlSet\Services\vmci
  SYSTEM\CurrentControlSet\Services\vmhgfs
  SYSTEM\CurrentControlSet\Services\vmmouse
  SYSTEM\CurrentControlSet\Services\vmrawdsk
  SYSTEM\CurrentControlSet\Services\vmusbmouse

VirtualBox artifacts:
  SOFTWARE\Oracle\VirtualBox Guest Additions
  SYSTEM\CurrentControlSet\Services\VBoxGuest
  SYSTEM\CurrentControlSet\Services\VBoxMouse
  SYSTEM\CurrentControlSet\Services\VBoxSF
  SYSTEM\CurrentControlSet\Services\VBoxVideo
```

In a full implementation, registry APIs (`RegOpenKeyExW`, `RegCloseKey`) would be resolved at runtime from `advapi32.dll`.

### VM Driver Files (Reference)

A comprehensive implementation would check 9 file paths via `GetFileAttributesW`:

```
VMware:
  C:\Windows\System32\drivers\vmmouse.sys
  C:\Windows\System32\drivers\vmhgfs.sys
  C:\Windows\System32\drivers\vm3dmp.sys

VirtualBox:
  C:\Windows\System32\drivers\VBoxMouse.sys
  C:\Windows\System32\drivers\VBoxGuest.sys
  C:\Windows\System32\drivers\VBoxSF.sys
  C:\Windows\System32\drivers\VBoxVideo.sys
  C:\Windows\System32\vmGuestLib.dll
  C:\Windows\System32\vboxdisp.dll
```

### Exercise 4.1: Evading MAC Detection

**Question**: How can you change the MAC address of a VirtualBox VM to bypass OUI detection?

<details>
<summary>Answer</summary>

**VirtualBox CLI**:
```bash
# Set a custom MAC address with non-VM OUI prefix
VBoxManage modifyvm "AnalysisVM" --macaddress1 D89EF3A12B45

# Use Dell OUI (D8:9E:F3) — looks like real hardware
# Or use Lenovo, HP, Intel OUI prefixes
```

**VirtualBox GUI**:
Settings → Network → Adapter 1 → Advanced → MAC Address → Enter custom value

**Key point**: Only the first 3 bytes (OUI) matter for detection. The last 3 bytes can be anything. Common non-VM OUIs:

```
Intel:    00:1B:21, 3C:97:0E, A0:36:9F
Dell:     D8:9E:F3, 18:66:DA, F8:DB:88
Lenovo:   E8:6A:64, 54:AB:3A, 98:FA:9B
Realtek:  00:E0:4C, 54:B2:03, 08:BE:AC
```

**Important**: After changing the MAC, also remove the VirtualBox Guest Additions to eliminate registry keys and driver files. Otherwise, those checks will still trigger.

</details>

---

## Section 5: Timing-Based Evasion

### Sleep Acceleration Detection

Sandboxes often "fast-forward" Sleep() calls to reduce analysis time:

```
Normal execution:
  t=0:     Sleep(2000) called
  t=2000:  Sleep returns
  elapsed: 2000ms ✓ (real sleep)

Sandbox fast-forward:
  t=0:     Sleep(2000) called
  t=100:   Sandbox intercepts, returns immediately
  elapsed: 100ms ✗ (accelerated)

Detection:
  start = GetTickCount64()
  Sleep(2000)
  elapsed = GetTickCount64() - start
  if elapsed < 1500 → sleep was accelerated → SANDBOX
```

**Weight +3**: This is the highest-weighted single check because it has virtually zero false positives. No legitimate system completes a 2-second sleep in under 1.5 seconds.

### Cursor Movement Detection

```
p1 = GetCursorPos()     → record initial position
Sleep(3000)             → wait 3 seconds
p2 = GetCursorPos()     → record new position

if p1 == p2 → cursor never moved → no human user → sandbox

False positive risk: LOW but possible
  - User walks away during execution
  - Cursor at screen edge
  - Touch-only device
```

### Exercise 5.1: Why Might You Randomize Check Order?

**Question**: If you had three check groups (hardware, env, VM) executing in randomized order, what specific sandbox technique would this defeat?

<details>
<summary>Answer</summary>

**Behavioral sequence detection**:

Sandbox engines build signatures based on API call sequences. For example:

```
Fixed-order signature (easily detected):
  GetSystemInfo → GlobalMemoryStatusEx → GetDiskFreeSpaceExW
  → GetUserNameW → GetComputerNameW → GetSystemMetrics
  → CreateToolhelp32Snapshot → RegOpenKeyExW → GetFileAttributesW

This exact sequence = "sandbox detection routine" → sandbox skips/ignores
```

By randomizing to 6 possible orderings, a sandbox engine would see a different API pattern each run:

```
Run 1: GetUserNameW → GetComputerNameW → GetSystemInfo → ...
Run 2: RegOpenKeyExW → GetFileAttributesW → GetSystemInfo → ...
Run 3: GetSystemInfo → GlobalMemoryStatusEx → RegOpenKeyExW → ...
```

**Additional measures in sophisticated malware**:
- Benign API noise between groups (`GetDesktopWindow` + `GetSystemTimeAsFileTime` + `Sleep(0)`) dilutes the suspicious sequence
- Variable delays between checks prevent timing-based behavioral signatures

**Note**: The Stage 10 binary does NOT implement randomization or noise injection — it executes checks in fixed order. This is a reference technique for understanding advanced sandbox evasion. Advanced sandboxes use set-based detection (which APIs were called, regardless of order) rather than sequence-based detection.

</details>

---

## Section 6: Detection Engineering

### YARA Rule: Anti-Sandbox Binary

```yara
rule Antisandbox_Environment_Checks
{
    meta:
        description = "Detects binary with multiple sandbox evasion techniques"
        author = "Goodboy Course"
        stage = "10"

    strings:
        // GetSystemInfo for CPU count
        $hw_cpu = { 48 8D (4C|44|54|5C) 24 ?? E8 }

        // GlobalMemoryStatusEx
        $hw_ram = "GlobalMemoryStatusEx" ascii

        // GetDiskFreeSpaceExW
        $hw_disk = "GetDiskFreeSpaceExW" ascii

        // GetTickCount64 for uptime/timing
        $timing = "GetTickCount64" ascii

        // GetUserNameW
        $env_user = "GetUserNameW" ascii

        // GetComputerNameW
        $env_comp = "GetComputerNameW" ascii

        // VM MAC OUI bytes
        $mac_vmware1 = { 00 0C 29 }
        $mac_vmware2 = { 00 50 56 }
        $mac_vbox    = { 08 00 27 }
        $mac_hyperv  = { 00 15 5D }
        $mac_qemu    = { 52 54 00 }

        // VM registry paths (even obfuscated, the deobfuscated strings hit memory)
        $reg_vmware = "VMware" wide ascii nocase
        $reg_vbox = "VirtualBox" wide ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($hw_*) and 1 of ($env_*)) or
        (3 of ($mac_*)) or
        ($reg_vmware and $reg_vbox)
}
```

### Sigma Rule: Sandbox Detection Behavior

```yaml
title: Process Performs Sandbox Environment Fingerprinting
id: d4e5f6a7-b8c9-0123-def0-stage10
status: experimental
description: >
    Detects a process performing multiple environment queries
    characteristic of sandbox detection
logsource:
    product: windows
    service: sysmon
detection:
    selection_sysinfo:
        EventID: 1  # Process creation
    selection_registry:
        EventID: 13  # Registry value set/query
        TargetObject|contains:
            - 'VMware'
            - 'VirtualBox'
            - 'VBoxGuest'
    selection_file:
        EventID: 1
        CommandLine|contains:
            - 'vmmouse.sys'
            - 'VBoxGuest.sys'
    timeframe: 10s
    condition: selection_registry or selection_file
level: medium
tags:
    - attack.defense_evasion
    - attack.t1497.001
```

---

## Section 7: Sandbox Hardening Guide

### Comprehensive VM Hardening Checklist

```
Hardware Layer:
  ☐ 4+ CPU cores allocated
  ☐ 8+ GB RAM allocated
  ☐ 100+ GB virtual disk
  ☐ Uptime > 30 minutes before analysis

Network Layer:
  ☐ Custom MAC address (non-VM OUI)
  ☐ Real-looking hostname in DHCP
  ☐ DNS resolving normally

User Layer:
  ☐ Realistic username (e.g., "jsmith", not "malware" or "test")
  ☐ Realistic computer name (e.g., "DESKTOP-A1B2C3D")
  ☐ User profile with documents/pictures/desktop items
  ☐ Browser history populated
  ☐ Recent files exist

Display Layer:
  ☐ 1920x1080 or higher resolution
  ☐ Mouse cursor simulation (AutoIt/PowerShell)
  ☐ Multiple monitors (optional)

VM Artifact Removal:
  ☐ Guest additions removed (VMware Tools / VBox GA)
  ☐ VM-specific drivers removed from System32\drivers
  ☐ VM registry keys cleaned
  ☐ VM-specific DLLs removed
  ☐ VM BIOS strings patched (SMBIOS)

Process Layer:
  ☐ 30+ background processes running
  ☐ Analysis tools renamed or not running during initial execution
  ☐ Common apps installed (Office, browser, PDF reader)
```

### Exercise 7.1: Can You Really Remove All VM Artifacts?

**Question**: Is it practically possible to remove ALL VM artifacts from a VirtualBox VM to make it indistinguishable from physical hardware?

<details>
<summary>Answer</summary>

**Short answer**: No, with sufficient effort, a determined binary can always detect virtualization.

**What you CAN remove**:
- Guest additions (registry, drivers, files) ✓
- MAC address OUI ✓
- Some SMBIOS strings (via VBoxManage setextradata) ✓
- Process names (VMware/VBox services) ✓

**What you CANNOT fully remove**:
1. **CPUID leaf**: `CPUID(0x1)` bit 31 of ECX = hypervisor present. The CPU itself reports virtualization.
2. **CPUID hypervisor info**: `CPUID(0x40000000)` returns "VBoxVBoxVBox" or "VMwareVMware"
3. **Hardware IDs**: PCI device IDs for virtual hardware (VirtIO, VMXNET3, etc.)
4. **Timing side-channels**: VM exit/entry causes measurable timing differences
5. **ACPI tables**: SLIC, RSDT contain VM vendor strings
6. **Firmware**: BIOS/UEFI vendor strings, SMBIOS manufacturer

**Practical approach**: Use nested virtualization or bare-metal analysis for samples with advanced VM detection. For most malware, removing guest additions + changing MAC + hardening the environment is sufficient.

</details>

---

## Section 8: Build Your Own — Environment Analyzer

### Challenge: Sandbox Score Calculator

Build a tool that evaluates the current system against common sandbox checks:

**Requirements**:
1. Run all 14 checks from this module
2. Display each check's result and weight
3. Calculate total score and compare against threshold
4. Color-code results: GREEN (pass), RED (fail)
5. Accept `--harden` flag that suggests fixes for failed checks

**Expected output**:
```
Sandbox Detection Score:
═══════════════════════════════════════════════════
  [PASS] CPU Cores: 8         (threshold: < 2)       +0
  [PASS] RAM: 16 GB           (threshold: < 4 GB)    +0
  [PASS] Disk: 476 GB         (threshold: < 60 GB)   +0
  [PASS] Uptime: 1440 min     (threshold: < 30 min)  +0
  [PASS] Username: jsmith     (not in blocklist)      +0
  [PASS] Computer: DESKTOP-X  (not in blocklist)      +0
  [PASS] Screen: 1920x1080    (threshold: < 800x600)  +0
  [PASS] Processes: 127       (threshold: < 30)       +0
  [FAIL] VM Registry: VBoxGuest found                 +2
  [FAIL] VM Files: VBoxMouse.sys exists               +2
  [FAIL] MAC OUI: 08:00:27 (VirtualBox)              +2
  [PASS] Analysis Tools: none detected                +0
  [PASS] Sleep: 2003ms elapsed (expected ~2000ms)     +0
  [PASS] Cursor: moved 45px in 3s                     +0
═══════════════════════════════════════════════════
  Total Score: 6 / Threshold: 3
  Result: SANDBOX DETECTED

Hardening suggestions:
  - Remove VirtualBox Guest Additions
  - Delete C:\Windows\System32\drivers\VBoxMouse.sys
  - Change MAC: VBoxManage modifyvm "VM" --macaddress1 D89EF3A12B45
```

---

## Adversarial Thinking — Evolving Past Sandbox Detection

### Challenge 1: The Well-Resourced Sandbox

**Scenario**: A sandbox allocates 8 CPU cores and 16 GB RAM to defeat your hardware checks. CPU and RAM checks both pass. Which of the 5 checks still catch it?

**Uptime**: Most sandbox orchestrators restore from a snapshot and immediately detonate the sample. Even with high-spec hardware, the VM was freshly booted seconds ago. `GetTickCount64() / 60000 < 30` catches this because no sandbox operator waits 30 minutes between snapshot restore and detonation — it would reduce throughput by 10-50x.

**Screen resolution**: Headless sandbox VMs frequently run with minimal display drivers. Even when a virtual display is configured, many sandbox frameworks use 1024x768 as default. The `< 800x600` threshold is conservative, but raising it to `< 1080` would catch more sandboxes (most real monitors are 1080p+) at the cost of false positives on VMs with 720p displays.

**Disk size**: Sandbox operators CAN allocate 100GB+ disks, but storage is expensive at scale. Running 50 concurrent analysis VMs with 100GB each requires 5TB of fast storage. Most operators keep disks at 40-60GB to manage costs.

**Key insight**: Uptime is the hardest check for sandboxes to defeat because it directly trades analysis throughput for evasion. Every minute of uptime padding is a minute the sandbox isn't analyzing samples.

### Challenge 2: The Unfakeable Check

**Scenario**: Design a sandbox check that NO amount of VM configuration can defeat. The sandbox operator can set any CPU count, RAM size, disk size, resolution, and uptime.

**Approach A — CPUID Hypervisor Bit**:
`CPUID(EAX=1)` returns ECX with bit 31 set if a hypervisor is present. This is a CPU-level flag that VMs cannot hide without nested virtualization or custom hypervisor patches. Even with hardware resources matching real hardware, the CPU itself reports "I am running inside a hypervisor."

```
CPUID leaf 0x1, ECX bit 31:
  Physical machine: 0 (no hypervisor)
  Any VM:           1 (hypervisor present)
```

**Approach B — Timing Side Channels**:
VM exits (transitions from guest to host) take measurable time. Execute a sequence of privileged-adjacent instructions (like CPUID, which always causes a VM exit) and measure the cycle cost with RDTSC. On bare metal, CPUID takes ~100-200 cycles. Inside a VM, it takes ~1000-5000 cycles due to the VM exit and re-entry. No amount of resource allocation changes this — it is an architectural property of virtualization.

**Approach C — Hardware Serialization**:
Query the SMBIOS/DMI tables via `GetSystemFirmwareTable()`. The BIOS manufacturer, product name, and serial number fields contain VM vendor strings ("QEMU", "VirtualBox", "VMware Virtual Platform") that are baked into the virtual firmware. Some hypervisors allow overriding these, but most sandbox operators don't bother.

**Why this binary doesn't use these**: CPUID bit 31 would flag ALL VMs, including developer workstations. The hardware-metric approach is deliberately conservative — it catches sandboxes (minimal resources) while sparing legitimate VMs (adequate resources). An "unfakeable" check is too aggressive for most operational contexts.

### Challenge 3: Unhookable System Info

**Scenario**: Your hardware checks use `GetSystemInfo` and `GlobalMemoryStatusEx` — these are API calls that EDR/sandbox can hook to return fake values. How do you make them unhookable?

**Approach A — KUSER_SHARED_DATA Direct Read**:
Some system information is available via direct memory read of the KUSER_SHARED_DATA structure at `0x7FFE0000` (mapped read-only into every process). No API call, no hook surface:

```
0x7FFE0000 + 0x0320: InterruptTime   (uptime — already used in Gate 3)
0x7FFE0000 + 0x02D4: KdDebuggerEnabled (bonus: kernel debugger check)
0x7FFE0000 + 0x0264: NumberOfPhysicalPages (RAM, requires page size math)
```

Not all checks can be done this way — CPU count and disk size require actual API calls.

**Approach B — Inline Syscalls**:
For `NtQuerySystemInformation`, extract the SSN and execute the syscall instruction directly. The ntdll function is never called, so hooks in ntdll are bypassed. This works for any Nt* function but requires SSN resolution (Hell's Gate, Halo's Gate, or hardcoded per-OS-version).

**Approach C — WMI Queries**:
`SELECT NumberOfLogicalProcessors FROM Win32_Processor` returns CPU count via WMI, which takes a completely different code path than `GetSystemInfo`. Hooking both GetSystemInfo AND WMI would require the sandbox to intercept two unrelated subsystems. However, WMI queries are slow (~100ms) and pull in significant code mass.

**This binary's approach**: Direct windows-sys imports (CFG-safe, linker-resolved) for all 5 checks. Using IAT-imported functions avoids both CFG issues and hookability concerns for most sandboxes (only kernel-level hooks can intercept linker-resolved imports).

---

## Dynamic Analysis — Observing Sandbox Detection in Action

### Exercise: Default VM Detection (10 min)

**Setup**: Use a default VirtualBox VM (1 CPU core, 2 GB RAM, dynamically-sized disk ~20-40 GB, freshly booted).

1. Copy `anti-sandbox.exe` to the VM
2. Run it from a command prompt
3. The process exits silently within 2-3 seconds — no MessageBox appears
4. Observe the behavior:

```
Expected on default sandbox VM:
  - Process starts, runs benign gate checks (env vars, BTreeMap operations)
  - GUI window lifecycle runs (1x1 hidden window, 50ms timer)
  - Anti-debug gauntlet passes (no debugger attached)
  - Sandbox check: CPU(1 core)=+1, RAM(2GB)=+1, Disk(~30GB)=+1,
    Uptime(<30min)=+1, Screen(depends)=+0 or +1
  - Total score: 3-5 → above threshold of 3 → EXITS silently
  - No MessageBox, no shellcode execution
```

With default VirtualBox settings, the sandbox score is 3-5, above the threshold of 3.

### Exercise: Hardened VM Pass-Through (15 min)

**Setup**: Configure a hardened VirtualBox VM:
- 4+ CPU cores (Settings > System > Processor)
- 8 GB RAM (Settings > System > Motherboard)
- 100+ GB disk (VBoxManage modifymedium + extend partition)
- Boot and wait 30+ minutes before running the sample
- Set 1920x1080 resolution (install Guest Additions for display driver, then remove GA)

1. Copy `anti-sandbox.exe` to the hardened VM
2. Run it from a command prompt
3. Observe:

```
Expected on hardened VM:
  - Benign gates pass (env vars, BTreeMap, directory checks)
  - GUI lifecycle runs (1x1 hidden window, 50ms timer)
  - Anti-debug passes (no debugger)
  - Sandbox check: CPU(4)=0, RAM(8GB)=0, Disk(100GB)=0,
    Uptime(30+min)=0, Screen(1920x1080)=0
  - Total score: 0 → below threshold of 3 → PROCEEDS to payload
  - XOR decrypts shellcode, resolves APIs via apihash PEB walk
  - VirtualAlloc(RW) → memcpy → VirtualProtect(RX) → CreateThread
  - MessageBox("GoodBoy") appears!
```

All checks pass. The binary behaves identically on a hardened VM and a real workstation.

### Exercise: x64dbg Score Inspection (15 min)

**Advanced**: Use x64dbg to observe the scoring in real time.

1. Open `anti-sandbox.exe` in x64dbg (with ScyllaHide enabled to pass anti-debug gates)
2. Set a breakpoint on `GetSystemInfo` — this is the first sandbox check API
3. Run (F9) — gates 1-6 pass (benign checks, GUI lifecycle, anti-debug), breakpoint hits at Gate 7
4. Step through each check, observing register values:
   - After `GetSystemInfo`: `si.dwNumberOfProcessors` in memory (compare to threshold 2)
   - After `GlobalMemoryStatusEx`: `mem.ullTotalPhys` in memory (compare to 4GB)
   - After `GetDiskFreeSpaceExW`: total bytes (compare to 60GB)
   - After `GetTickCount64`: RAX = milliseconds since boot (compare to 1,800,000 = 30 min)
   - After `GetSystemMetrics(0)` and `GetSystemMetrics(1)`: EAX = width/height
5. After all 5 checks, find the local variable holding the score (stack or register)
6. If the score is >= 3, change it to 0 in the register/memory to force the check to pass
7. Continue execution — the payload runs despite being in a sandbox

This exercise demonstrates that anti-sandbox checks are advisory, not enforced — with a debugger, you can always override the decision.

---

## Summary Table

| Check Category | Checks | Weight | Detection Layer | Bypass Difficulty |
|---------------|--------|--------|-----------------|-------------------|
| Hardware | CPU, RAM, Disk, Uptime | +1 each | OS query | Easy (VM config) |
| User/Environment | Username, Computer, Screen, Processes | +1 to +2 | OS query | Easy (rename/config) |
| VM Artifacts | Registry, Files, MAC, Tools | +2 each | Filesystem/Registry | Medium (remove GA) |
| Timing | Sleep acceleration | +3 | Behavioral | Hard (sandbox design) |
| User Activity | Cursor movement, Recent files | +1 each | Behavioral | Medium (simulate) |
| **Threshold** | | **≥ 3** | | |
| **MITRE ATT&CK** | | | **T1497.001** (System Checks) | |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "Anti-sandbox = checking for VM names" | This binary uses ZERO string-based VM detection. The word "VMware" never appears. Hardware metrics (CPU, RAM, disk, uptime, screen) are sufficient and avoid the string-based ML signatures that burned earlier versions |
| "Sandboxes can't be detected by hardware checks" | Default sandbox VMs typically have 1-2 cores, 2GB RAM, 40GB disk, and <5 min uptime. These are trivially detectable. The fix is on the sandbox side (allocate more resources), not on the malware side |
| "A scoring threshold of 3 is too low" | With 5 checks each worth +1, a real workstation scores 0 and a default sandbox scores 3-5. The threshold of 3 catches 95%+ of sandboxes while having near-zero false positives on real systems. Higher thresholds miss more sandboxes |
| "GetTickCount64 is the same as KUSER_SHARED_DATA" | Both return uptime, but GetTickCount64 is an API call (hookable by EDR) while KUSER_SHARED_DATA is a direct memory read (unhookable). This binary uses GetTickCount64 only (30-min threshold in check_sandbox). An advanced variant could add a KUSER_SHARED_DATA read at `0x7FFE0320` as a secondary unhookable check — see the Adversarial Thinking section |
| "String-based VM checks are better than hardware checks" | String-based checks (username="sandbox", files="VBoxMouse.sys") are WORSE because the strings themselves are malware signatures. CrowdStrike ML flagged the binary at 60% just from containing "sandbox" and "VBoxMouse.sys" as string literals. Hardware checks use only numeric comparisons — invisible to string-based ML |
| "CFG doesn't matter for sandbox checks" | Earlier versions using GetProcAddress-resolved function pointers crashed with STATUS_STACK_BUFFER_OVERRUN because the pointer wasn't in the CFG bitmap. This binary uses direct windows-sys imports (GetSystemInfo, etc.) which are CFG-safe because the linker adds them to the bitmap at compile time |

### What Breaks at Stage 11 — The Bridge

Stages 09-10 protect against analysis. Stage 11 adds **persistence** — surviving reboots. The payload doesn't just execute once; it installs itself to run again after the system restarts. Five persistence methods: Registry Run key, Scheduled Task, Startup folder, COM Hijacking, WMI Event Subscription.

But there's a critical lesson: the persistence modules add ~124KB of offensive code that pushed ML classifiers over detection thresholds. In the final build, persistence was DISABLED to maintain 0/76.

### Knowledge Check (Additional)

**6. Why does the binary use `to_wide("C:\\")` for the disk check instead of a raw byte array?**

<details>
<summary>Answer</summary>

`GetDiskFreeSpaceExW` is a wide-string (UTF-16) API — it requires `LPCWSTR` (pointer to null-terminated UTF-16). The `to_wide()` helper converts `&str` to `Vec<u16>` with a null terminator. Using a raw byte array like `[0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x00, 0x00]` would work but is less readable. The string "C:\\" in the binary is benign — it's a standard path, not a suspicious constant.

</details>

**7. The self-contained version removed all diagnostic file writes. How would you observe the sandbox score during analysis?**

<details>
<summary>Answer</summary>

Without diagnostic breadcrumbs, you must use a debugger:

1. **Static analysis**: Find the `check_sandbox()` function in Ghidra/IDA. The threshold comparison `score >= 3` is at the function return. Set a breakpoint there.

2. **Dynamic analysis**: In x64dbg (with ScyllaHide), break after all 5 check API calls. Read the score from the stack or register holding the accumulated value. You can manually set it to 0 to force the check to pass.

3. **API monitoring**: Use API Monitor to log `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`, `GetTickCount64`, and `GetSystemMetrics` calls. The return values tell you what the binary saw.

In earlier development versions, diagnostic files like `diaghost_5_sandbox_score_N.txt` were written to `%TEMP%` for testing. These were removed from the final binary because they create forensic artifacts.

</details>

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | CPU, RAM, disk, uptime, screen checks |
| Debugger Evasion | T1622 | PEB + NtQIP + RDTSC + HW BP (from Stage 09) |
| Reflective Code Loading | T1620 | XOR decrypt → VirtualAlloc → VirtualProtect → CreateThread |
| Dynamic API Resolution | T1027.007 | 5 kernel32 APIs + 3 ntdll APIs via additive hash PEB walk |
| Masquerading | T1036 | Window class "DiagHostWnd" |

### Further Reading (2025-2026)

**Sandbox detection techniques:**
- [cocomelonc: Malware Tricks 36-55](https://cocomelonc.github.io/malware/2023/09/25/malware-trick-36.html) — Anti-sandbox techniques in C (2023-2025)
- [cocomelonc: Malware Tricks 22-25](https://cocomelonc.github.io/malware/2022/07/21/malware-tricks-22.html) — Anti-analysis fundamentals

**Sandbox hardening:**
- [Altered Security CETP](https://www.alteredsecurity.com/evasionlab) — Evasion Lab includes sandbox bypass and hardening (March 2026)
- FlareVM (`github.com/mandiant/flare-vm`) — Pre-configured analysis VM with better defaults

**Detection:**
- [WindShock: Endpoint Evasion 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — Evolution of sandbox evasion in the EDR era
- [CrowdStrike: EMBER2024](https://www.crowdstrike.com/en-us/blog/ember-2024-advancing-cybersecurity-ml-training-on-evasive-malware/) — ML training includes sandbox-evasive samples
