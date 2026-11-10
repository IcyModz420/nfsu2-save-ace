# NFS Underground 2 — Career Save File Format

Reverse-engineered format documentation for the career save files used by Need for Speed Underground 2.

## File Location

```
%LOCALAPPDATA%\NFS Underground 2\<ProfileName>\<ProfileName>
```

No file extension. The profile name serves as both the directory name and the filename. For example, a profile named "Player" would be stored at:

```
C:\Users\<user>\AppData\Local\NFS Underground 2\Player\Player
```

## Container: "20CM" Format

The save file uses a container format identified by the magic bytes `20CM` (ASCII `0x32 0x30 0x43 0x4D`, stored as little-endian DWORD `0x4D433032`).

### Header (28 bytes)

```
Offset  Size  Type    Field
──────  ────  ──────  ──────────────────────────────────────────────
0x00    4     u32     Magic: 0x4D433032 ("20CM" in ASCII)
0x04    4     u32     Total file size (header + career header + payload)
0x08    4     u32     Unknown / reserved
0x0C    4     u32     Payload size (file size minus headers)
0x10    12    byte[]  Hash (MD5 or similar — read but NEVER VERIFIED)
0x1C    —     —       End of container header
```

### Career Header (8 bytes)

Immediately follows the container header:

```
Offset  Size  Type    Field
──────  ────  ──────  ──────────────────────────────────────────────
0x1C    4     u32     Version (must equal 0x10d = 269 decimal)
0x20    4     u32     Payload size (redundant, same as offset 0x0C)
0x24    —     —       Start of career payload
```

### Career Payload (variable, typically 54,930 bytes)

```
Offset  Size    Field
──────  ──────  ──────────────────────────────────────────────
0x24    54,930  Raw career data — copied verbatim into memory
```

## Typical File Size

A standard career save is **54,966 bytes** total:

| Component | Size |
|-----------|------|
| Container header | 28 bytes |
| Career header | 8 bytes |
| Career payload | 54,930 bytes |
| **Total** | **54,966 bytes** |

Hex values: total = `0xD6B6`, payload = `0xD692`.

## Validation

The loader performs exactly three checks:

1. **Version check:** The DWORD at offset `0x1C` must equal `0x10d`
2. **Size check:** The payload size must match the expected career struct size
3. **Error counter:** An internal error variable must remain zero

### What is NOT validated

- The 12-byte hash at offset `0x10` is read into a local variable but **never compared** against a computed hash of the payload
- No HMAC, no signature, no CRC, no checksum
- No bounds checking on individual fields within the payload
- No type checking on values used as pointers or indices

Any file that passes the version and size checks has its payload `memcpy`'d directly into the career singleton struct at `0x0083a9e0`.

## Memory Layout

The career data lives at a fixed global address (no ASLR):

| Label | Address | Description |
|-------|---------|-------------|
| Career wrapper | `0x0083a9d0` | Outer career struct |
| Career inner | `0x0083a9e0` | Inner struct — save payload destination |
| Payload end | `0x0083a9e0 + 0xD692` | End of career data |

The entire payload region is in the `.data` section of the PE, which is both readable and writable. On systems without DEP enforcement (which includes this binary), it may also be executable.

## Key Offsets Within the Payload

These offsets are relative to the career inner struct at `0x0083a9e0` (file offset `0x24`):

| Struct offset | Address | Used by | Description |
|---------------|---------|---------|-------------|
| `+0x8c` | `0x0083aa6c` | Vuln 1 | Array index (1 of 8, stride 0x28) |
| `+0x98` | `0x0083aa78` | Vuln 2 (indirectly) | Related to WHERE pointer |
| `+0x300` | `0x0083ace0` | PoC | Fake object placement site |
| `+0x314` | `0x0083acf4` | PoC | Fake vtable slot (fake_obj + 0x14) |

## Crafting a Save File

To create a valid save file that passes the loader's checks:

1. Start with 54,966 bytes of zeros (or copy a legitimate save)
2. Write magic bytes `0x4D433032` at offset `0x00`
3. Write total size `0x0000D6B6` at offset `0x04`
4. Write payload size `0x0000D692` at offset `0x0C`
5. Write version `0x0000010D` at offset `0x1C`
6. Write payload size `0x0000D692` at offset `0x20`
7. Fill the payload (offset `0x24` onward) with your career data
8. The hash at offset `0x10` can be anything — it's never checked

All multi-byte values are little-endian.
