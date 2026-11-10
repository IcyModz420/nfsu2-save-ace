# NFS Underground 2 — Save File Remote Code Execution

Three memory corruption vulnerabilities in the Need for Speed Underground 2 career save deserializer that chain together for **full EIP control** from a crafted save file.

| | |
|---|---|
| **Product** | Need for Speed Underground 2 (SPEED2.EXE) |
| **Vendor** | Electronic Arts |
| **Platform** | Windows x86 (32-bit PE) |
| **Severity** | Critical (CVSS 3.1: 8.6) |
| **Attack vector** | Crafted career save file |
| **Impact** | Arbitrary code execution |
| **Date** | November 2026 |

## Overview

The career save file loader in NFS Underground 2 copies 54,930 bytes of attacker-controlled data directly into a global struct with no validation beyond a magic number and version check. No hash, no signature, no bounds checking. Several fields from this payload are then used as raw pointer operands and array indices in the deserialization code, producing multiple exploitable memory corruption primitives.

Two of the three vulnerabilities chain together to achieve arbitrary code execution:

1. **Vuln 2** provides a write-what-where primitive — both the destination pointer and the written value come from save-controlled memory
2. **Vuln 3** performs a C++ virtual function call through a global pointer that Vuln 2 can overwrite

The binary ships with no ASLR (fixed base `0x00400000`), no stack cookies, no DEP, and all addresses are deterministic across every installation. The save file format has no integrity protection whatsoever.

## The Chain

```
Save file loaded
    │
    ▼
54,930 bytes copied verbatim into career struct at 0x0083a9e0
    │
    ▼
Vuln 2 fires (FUN_004792b0)
    *(*(ECX+0x98) + 0x14) = param_1
    Both operands are save-controlled
    Attacker writes fake object pointer → DAT_0082b974
    │
    ▼
Vuln 3 fires (FUN_00469050)
    MOV ECX, [0x0082b974]     ← now points to fake object in career struct
    MOV EAX, [ECX]            ← fake vtable (self-referencing pointer)
    CALL [EAX + 0x14]         ← attacker-controlled function pointer
    │
    ▼
EIP = 0x41414141   ✓ Controlled
```

## Proof

EIP control was proven dynamically via Frida instrumentation. The exception handler captured:

```
EIP = 0x41414141
EAX = 0x0083ace0   (fake object in career struct)
ECX = 0x0083ace0
ESP = 0x001afc6c
EBP = 0x001afcac
```

The write-what-where mechanism in Vuln 2 performed the overwrite through its own code path — no direct memory stamps were needed. The full chain fires naturally during save deserialization.

## Repository Contents

```
├── DISCLOSURE.md          Full technical write-up
├── poc/
│   ├── eip_control.js     Frida PoC script (EIP control proof)
│   └── README.md          Reproduction steps
├── reference/
│   └── save-format.md     Save file format documentation
├── samples/
│   └── career.bin         Clean career save (format reference only)
└── LICENSE
```

## Reproduction

1. Launch `SPEED2.EXE`
2. Attach Frida to the process: `frida -p <PID> -l poc/eip_control.js`
3. Load any career save profile in the game menu
4. Observe: access violation at `EIP = 0x41414141`

See [`poc/README.md`](poc/README.md) for detailed steps.

## Vulnerabilities

| ID | Function | Address | Type | Severity |
|----|----------|---------|------|----------|
| Vuln 1 | `FUN_005344e0` | `0x5344e0` | Out-of-bounds array index (CWE-787) | Medium |
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
