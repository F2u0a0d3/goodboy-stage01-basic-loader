# Safety Rules — Goodboy Framework

## The Golden Rule

**WRITE code on your host. EXECUTE only in VMs.**

Compilation is safe. `cargo build --release` produces a PE file — the compiler does NOT execute shellcode during compilation. The danger is ONLY in running the binary.

## Do NOT Submit to VirusTotal

**Every VT submission feeds the sample to 76+ AV vendors.** They use your submissions to train ML classifiers against the binary. You cannot check if a binary is clean without making it dirty. This is called **sample burning** — see Stage 03's Learning Path for the full forensic timeline.

If you want to test AV detection:
- Use a local AV install in your VM (Windows Defender, etc.)
- Do NOT upload to any multi-scanner service (VT, Hybrid Analysis, ANY.RUN, etc.)

## Development Workflow

```
HOST (safe)                          VM (dangerous)
───────────────────────────────────  ──────────────────────────────
1. Write / edit Rust code            4. Revert VM to clean snapshot
2. cargo build --release             5. Transfer .exe via host-only net
3. Copy .exe to payloads/            6. Run with Defender + Sysmon ON
                                     7. Analyze detection / logs
                                     8. Revert VM again
```

## VM Setup Checklist

- [ ] Windows 10/11 VM (VMware, VirtualBox, or Hyper-V)
- [ ] Host-only networking (isolate from internet)
- [ ] Take clean snapshot BEFORE any testing
- [ ] Windows Defender enabled (test real AV)
- [ ] Sysmon installed + logging (observe EDR telemetry)
- [ ] x64dbg + ScyllaHide (debugging with anti-anti-debug)
- [ ] PE-bear / PE-sieve (binary analysis)
- [ ] 4+ CPU cores, 8+ GB RAM, 100+ GB disk (required for sandbox gates)
- [ ] 30+ minutes uptime before running binaries (uptime gate)

## What is SAFE on Host

- Writing Rust / Python code
- Running `cargo build --release`
- Running Python tools (encrypt, format, hash, entropy)
- Analyzing PE files with `strings`, `dumpbin`, PE tools
- Reading Learning Paths and doing static analysis exercises

## What is DANGEROUS (VM Only)

- Executing ANY compiled .exe from crates/
- Running shellcode in any form
- Testing against live AV/EDR
- Network beaconing to C2 (Stage 15)

## Payload Safety

All binaries ship with **MessageBox("GoodBoy")** as the payload. This pops a harmless dialog box and exits cleanly. No network activity, no persistence, no file writes, no system modifications.

## Emergency

If you accidentally run a binary on your host:
1. Don't panic — the payload is MessageBox("GoodBoy"), it's harmless
2. Click OK on the dialog if it appeared
3. The process exits cleanly via ExitProcess
4. No cleanup needed for the default payload
