# Sample Save Files

## career.bin

A clean, unmodified career save file from normal gameplay. Included as a format reference for anyone studying the file structure documented in [`../reference/save-format.md`](../reference/save-format.md).

This is **not** a crafted exploit file. It's a normal save that the game loads without issues.

### Quick verification

```
File size:  54,966 bytes (0xD6B6)
Magic:      20CM (offset 0x00)
Version:    0x10d (offset 0x1C)
Payload:    54,930 bytes (0xD692)
```

You can use this file to:

- Study the save file header format
- Compare byte offsets against the format documentation
- Test that your save file parsing tools handle a valid file correctly
- Use as a base for manual analysis of the career struct layout
