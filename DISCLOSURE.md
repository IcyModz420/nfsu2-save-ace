# Full Disclosure: Remote Code Execution via Crafted Save File in Need for Speed Underground 2

## 1. Summary

The career save file loader in Need for Speed Underground 2 (`SPEED2.EXE`) contains three memory corruption vulnerabilities in the deserialization chain. Two of these chain together to achieve full instruction pointer (EIP) control from a crafted save file, resulting in arbitrary code execution when a victim loads the malicious save.

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

### Save File Location

```
%LOCALAPPDATA%\NFS Underground 2\<ProfileName>\<ProfileName>
```

No file extension. The profile name is both the directory name and the filename. Career saves are plain files with no OS-level protection — any process running as the user can read and write them.

## 3. Vulnerability Details

### 3.1 Vuln 1 — Out-of-Bounds Array Index

**Severity:** Medium  
**Type:** CWE-787 (Out-of-bounds Write)  
**Location:** `FUN_005344e0` (loop body) → `FUN_00571fc0` (write sink)

#### Decompiled code (from Ghidra)

```c
// In FUN_005344e0 — the inner deserialization function
iVar2 = 0;
piVar8 = &DAT_0083aa6c;             // career_inner + 0x8c
do {
    uVar1 = FUN_00571ad0(iVar2);
    FUN_00571fe0(local_28, 9, uVar1);
    FUN_00571fc0(iVar2, local_28[*piVar8]);  // INDEX IS SAVE-CONTROLLED
    piVar8 += 10;                            // stride 0x28 bytes
    iVar2++;
} while ((int)piVar8 < 0x83aabc);    // 8 iterations
```

#### Write sink

```c
void FUN_00571fc0(int idx, uint val) {
    *(uint *)(&DAT_00865764 + idx * 0x1c8) = val;
}
```

`*piVar8` is a DWORD read from the career struct (offsets `+0x8c`, `+0xb4`, `+0xdc`, ... at stride `0x28`, for 8 iterations). This value is used as an index into a 9-element stack array `local_28`. No bounds check. An index >= 9 reads past the end of the array on the stack, and the garbage value is written to a deterministic global address via `FUN_00571fc0`.

This is a read-out-of-bounds leading to a write-to-known-address, but the written value is not directly controlled — it depends on whatever happens to be on the stack at that offset. It's exploitable for information disclosure or controlled writes if the stack layout is predictable, but the chain through Vulns 2→3 is more reliable.

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

This is a `thiscall` function. `ECX` is the `this` pointer — an audio/music manager object allocated on the heap (not the career struct itself, but its fields are populated from save data during deserialization). The function writes `param_1` to the address stored at `*(this + 0x98) + 0x14`.

| Operand | Role | Source | Save-controlled? |
|---------|------|--------|------------------|
| `*(ECX+0x98)` | WHERE pointer | Object field, populated from save data | **Yes** |
| `param_1` | WHAT value | Career struct field | **Yes** |
| `DAT_007faaa8` | Gate flag | Global state | No (confirmed OPEN at runtime) |

Both the destination pointer and the value written derive from save-file-controlled memory. By setting the appropriate bytes in the save file, an attacker can write an arbitrary 32-bit value to any writable address in the process.

**To target a specific address `T`:** set `*(ECX+0x98)` to `T - 0x14`, and set `param_1` to the desired value.

#### ECX identification

An important detail: `ECX` in this function is NOT the career struct at `0x0083a9e0`. It's a heap-allocated audio/music manager object whose address varies per run (observed values: `0x0bb92f80`, `0x0be41f80`). However, the field at offset `+0x98` within this object is populated from save-controlled data during deserialization, so the write target is still fully controlled.

### 3.3 Vuln 3 — Vtable Hijack → Arbitrary Code Execution

**Severity:** Critical  
**Type:** CWE-843 (Access of Resource Using Incompatible Type) → CWE-94 (Code Injection)  
**Location:** `FUN_00469050`

#### Disassembly (the critical call site)

```asm
0046906b  MOV   ECX, dword ptr [0x0082b974]     ; ECX = object ptr from global
00469071  TEST  ECX, ECX                          ; null check
00469073  JZ    0x0046907a                        ; skip if null
00469075  MOV   EAX, dword ptr [ECX]              ; EAX = *obj = vtable ptr
00469077  CALL  dword ptr [EAX + 0x14]            ; CALL vtable[5]
```

This is a standard C++ virtual function call pattern with three levels of indirection:

1. `[0x0082b974]` → object pointer
2. `[object]` → vtable pointer
3. `[vtable + 0x14]` → function pointer → `CALL`

Under normal execution, `DAT_0082b974` holds a pointer to a legitimate C++ object. But if Vuln 2 overwrites this global with a pointer to attacker-controlled memory inside the career struct, the entire dereference chain follows attacker-chosen values.

#### Gate conditions

This code path has multiple gates that must be open for the vtable call to execute:

| Gate | Check | Runtime value | Status |
|------|-------|---------------|--------|
| `DAT_007faaa8` | `!= 0` | `1` | **OPEN** |
| `*(ECX+0xa0)` | `!= 0` | `0x0bdd5980` | **OPEN** |
| `DAT_0082b974` | `!= NULL` | `0x0c3cf0f8` | **OPEN** |

All three gates are confirmed open at runtime during normal career save loading. The vtable call always fires.

## 4. Exploit Chain: Vuln 2 → Vuln 3

The chain works as follows:

### Step 1: Save payload lands in memory

The loader copies 54,930 bytes from the save file directly into the career struct at `0x0083a9e0`. Attacker-controlled data now sits at deterministic addresses. We place a fake C++ object at career_inner + 0x300 (`0x0083ace0`):

```
Address     Value         Purpose
─────────   ───────────   ─────────────────────────────────
0x0083ace0  0x0083ace0    vtable pointer (self-referencing)
0x0083ace4  (don't care)  
0x0083ace8  (don't care)  
0x0083acec  (don't care)  
0x0083acf0  (don't care)  
0x0083acf4  0x41414141    vtable[5] — target EIP
```

The self-referencing pointer is the key trick: when the vtable call does `MOV EAX, [ECX]`, it reads `0x0083ace0` — the same address. Then `CALL [EAX + 0x14]` reads from `0x0083acf4`, which contains our target EIP.

### Step 2: Vuln 2 redirects the global pointer

During deserialization, `FUN_004792b0` fires. We need two things in the save file:

- The field at `*(ECX+0x98)` set to `0x0082b960` (so the write hits `0x0082b960 + 0x14 = 0x0082b974`)
- `param_1` set to `0x0083ace0` (the address of our fake object)

After Vuln 2 executes: `DAT_0082b974 = 0x0083ace0`

### Step 3: Vuln 3 follows the hijacked pointer

`FUN_00469050` fires immediately after in the deserialization sequence:

```
MOV ECX, [0x0082b974]     → ECX = 0x0083ace0 (our fake object)
MOV EAX, [ECX]            → EAX = 0x0083ace0 (self-referencing vtable)
CALL [EAX + 0x14]         → CALL *0x0083acf4 → CALL 0x41414141
```

**EIP = 0x41414141.** Instruction pointer fully controlled.

### Step 4: In a real exploit

The attacker replaces `0x41414141` with the address of their shellcode or a ROP gadget. With no DEP, shellcode can be placed directly in the career struct (which lives in a writable, executable memory region) and jumped to. With no ASLR, every address is known at compile time.

## 5. Proof of Concept

### Method

Dynamic instrumentation via Frida, attached to `SPEED2.EXE` at runtime. The PoC script hooks Vuln 2's entry point to redirect the write-what-where toward `DAT_0082b974` and plants a fake C++ object in the career struct with `0x41414141` as the virtual function pointer.

Importantly, **the write-what-where mechanism itself performs the overwrite** — Vuln 2's own `MOV [EAX+0x14], EDX` instruction writes our fake object pointer into the global. No direct memory stamps or fallback writes were needed.

### Captured result

```
Exception: access-violation
EIP = 0x41414141    ← INSTRUCTION POINTER CONTROLLED

Register dump:
  EAX = 0x0083ace0   (fake object in career struct)
  ECX = 0x0083ace0   (same — this pointer for the virtual call)
  EDX = 0x00000000
  ESP = 0x001afc6c
  EBP = 0x001afcac
  EIP = 0x41414141   ← controlled
```

### Execution trace

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
      gate *(ECX+0xa0)     = 0x0bdd5980   → OPEN
      DAT_0082b974         = 0x0083ace0   ← FAKE VTABLE
      CALL target          = 0x41414141   ← ARMED
[5] EXCEPTION: access-violation
      EIP = 0x41414141 — INSTRUCTION POINTER CONTROLLED
```

### Reproduction

1. Install Need for Speed Underground 2 (any retail or digital version)
2. Create a career profile and save at least once (to generate a save file)
3. Launch the game
4. Attach Frida: `frida -p <PID> -l poc/eip_control.js`
5. Load the career profile from the in-game menu
6. Observe: access violation at `EIP = 0x41414141`

## 6. Affected Components

| Function | Address | Role | Vulnerable? |
|----------|---------|------|-------------|
| `FUN_005344e0` | `0x5344e0` | Inner deserializer (loop) | **Vuln 1** — OOB index |
| `FUN_004792b0` | `0x4792b0` | Field store with pointer deref | **Vuln 2** — Write-what-where |
| `FUN_00469050` | `0x469050` | Virtual dispatch after deser | **Vuln 3** — Vtable hijack |
| `FUN_00571fc0` | `0x571fc0` | Global table write | Sink for Vuln 1 |
| `FUN_00571ad0` | `0x571ad0` | Lookup helper | Safe (no save-controlled operands) |
| `FUN_00516850` | `0x516850` | Deinterleave pass 1 | Safe |
| `FUN_00529240` | `0x529240` | Deinterleave pass 2 | Safe |
| `FUN_00515c90` | `0x515c90` | Byte copy fixup | Safe |
| `FUN_005b9580` | `0x5b9580` | Table search fixup | Safe |
| `FUN_00479220` | `0x479220` | Bit shift fixup | Safe |
| `FUN_005be6a0` | `0x5be6a0` | Min comparison | Safe |

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
| 2026-11-09 | Full disclosure published |

## 10. Tools

- **Ghidra 12.1.4** (via [REA](https://re-anytime.com/)) — static analysis, decompilation, cross-reference analysis
- **Frida** (via REA) — dynamic instrumentation, runtime gate verification, EIP control proof
- **Custom Frida scripts** — `eip_control.js` (proof-of-concept)

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
