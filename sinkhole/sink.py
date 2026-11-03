#!/usr/bin/env python3
"""
Faraday sinkhole: the only resident of the cage's internal bridge.

Why this exists. The obvious way to contain an agent is `--network none`, and
for the PARSE stage that is exactly right. But for the AGENT stage it is the
wrong tool, because a null network makes an exfiltration attempt SILENT -- the
agent's request fails with EAI_NONAME and nobody ever learns it tried.

So the agent cage runs on an internal bridge (no route off the host) with this
process as its only neighbour and its only DNS resolver. Every lookup resolves
here. Every connection lands here. Nothing leaves. And every attempt is
recorded with its hostname, path, method, headers and body size, which is what
turns containment from an assertion into an exhibit.

Listeners:
    udp/53   DNS   -- answers every A query with its own address
    tcp/80   HTTP  -- logs method, host, path, headers, body size; returns 200
    tcp/443  RAW   -- logs the TCP connect and the TLS SNI if legible, then closes
    tcp/25   RAW   -- SMTP, because "email it to opposing counsel" is the
                      canonical exfiltration instruction in this threat model

Attempts are appended as JSONL to $SINK_LOG (default /var/log/faraday/egress.jsonl)
and echoed to stdout.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

SINK_IP = os.environ.get("SINK_IP", "0.0.0.0")


def _self_address() -> str:
    """
    The address to hand back in DNS answers: our own IP on the cage bridge.

    This was hardcoded to 10.255.0.2, which is not where the sinkhole actually
    lives, so a resolved name pointed nowhere and the follow-up connection was
    never made -- the attempt stayed invisible, which is the one thing this
    process exists to prevent.
    """
    override = os.environ.get("SINK_ANSWER_IP")
    if override:
        return override
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


ANSWER_IP = _self_address()
LOG_PATH = Path(os.environ.get("SINK_LOG", "/var/log/faraday/egress.jsonl"))
_lock = threading.Lock()


def record(**fields) -> None:
    entry = {"ts": time.time(), "blocked": True, **fields}
    line = json.dumps(entry, default=str)
    with _lock:
        try:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOG_PATH.open("a") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    print(f"BLOCKED {line}", flush=True)


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def _parse_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    labels, i = [], offset
    while i < len(data):
        ln = data[i]
        if ln == 0:
            i += 1
            break
        labels.append(data[i + 1:i + 1 + ln].decode("utf-8", "replace"))
        i += 1 + ln
    return ".".join(labels), i


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        if len(data) < 12:
            return
        try:
            qname, end = _parse_qname(data)
            qtype, qclass = struct.unpack(">HH", data[end:end + 4])
        except Exception:
            return

        record(kind="dns", host=qname, qtype=qtype,
               peer=self.client_address[0], answer=ANSWER_IP,
               note="resolved to sinkhole; no external resolver reachable")

        txid = data[:2]
        header = txid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
        question = data[12:end + 4]
        # answer: name pointer to the question, A/IN, ttl 30, 4-byte rdata
        answer = struct.pack(">HHHIH", 0xC00C, 1, 1, 30, 4)
        answer += socket.inet_aton(ANSWER_IP)
        try:
            sock.sendto(header + question + answer, self.client_address)
        except OSError:
            pass


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class HTTPHandler(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self) -> None:
        try:
            request_line = self.rfile.readline(65536).decode("latin-1").strip()
        except Exception:
            return
        if not request_line:
            return
        parts = request_line.split()
        method = parts[0] if parts else "?"
        path = parts[1] if len(parts) > 1 else "?"

        headers: dict[str, str] = {}
        while True:
            try:
                raw = self.rfile.readline(65536)
            except Exception:
                break
            if not raw or raw in (b"\r\n", b"\n"):
                break
            line = raw.decode("latin-1").strip()
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body_len = int(headers.get("content-length", "0") or 0)
        body_preview = ""
        if body_len:
            try:
                chunk = self.rfile.read(min(body_len, 2048))
                body_preview = chunk.decode("utf-8", "replace")[:512]
            except Exception:
                pass

        record(kind="http", method=method, host=headers.get("host", "?"),
               path=path, body_bytes=body_len, body_preview=body_preview,
               user_agent=headers.get("user-agent", ""),
               peer=self.client_address[0],
               note="request absorbed by sinkhole; never left the host")

        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 44\r\nConnection: close\r\n\r\n"
            b"faraday-sinkhole: request logged and dropped"
        )


# --------------------------------------------------------------------------
# Raw TCP (443 / 25)
# --------------------------------------------------------------------------
def _sni(buf: bytes) -> str | None:
    """Best-effort SNI lift from a TLS ClientHello, for the log line only."""
    try:
        if len(buf) < 45 or buf[0] != 0x16:
            return None
        i = 43
        i += 1 + buf[i]                                   # session id
        i += 2 + struct.unpack(">H", buf[i:i + 2])[0]     # cipher suites
        i += 1 + buf[i]                                   # compression
        i += 2                                            # extensions length
        while i + 4 <= len(buf):
            etype, elen = struct.unpack(">HH", buf[i:i + 4])
            if etype == 0x0000:
                j = i + 4 + 5
                nlen = struct.unpack(">H", buf[j - 2:j])[0]
                return buf[j:j + nlen].decode("utf-8", "replace")
            i += 4 + elen
    except Exception:
        return None
    return None


class RawHandler(socketserver.BaseRequestHandler):
    timeout = 5
    port_label = "raw"

    def handle(self) -> None:
        try:
            self.request.settimeout(3)
            buf = self.request.recv(4096)
        except Exception:
            buf = b""
        record(kind=self.port_label, host=_sni(buf) or "?",
               bytes_offered=len(buf),
               preview=buf[:120].decode("utf-8", "replace"),
               peer=self.client_address[0],
               note="TCP connect absorbed; no route off the internal bridge")
        try:
            self.request.close()
        except Exception:
            pass


class TLSHandler(RawHandler):
    port_label = "tls"


class SMTPHandler(RawHandler):
    port_label = "smtp"

    def handle(self) -> None:
        try:
            self.request.sendall(b"220 faraday-sinkhole ESMTP\r\n")
        except Exception:
            pass
        super().handle()


class ReuseUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class ReuseTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(server) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    servers = [
        ("udp/53  DNS ", ReuseUDP((SINK_IP, 53), DNSHandler)),
        ("tcp/80  HTTP", ReuseTCP((SINK_IP, 80), HTTPHandler)),
        ("tcp/443 TLS ", ReuseTCP((SINK_IP, 443), TLSHandler)),
        ("tcp/25  SMTP", ReuseTCP((SINK_IP, 25), SMTPHandler)),
    ]
    for label, srv in servers:
        serve(srv)
        print(f"sinkhole listening {label} on {SINK_IP}", flush=True)
    print(f"sinkhole answering all A queries with {ANSWER_IP}", flush=True)
    print(f"sinkhole log -> {LOG_PATH}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
