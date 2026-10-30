#!/usr/bin/env python3
"""Summarise HTTP and HTTPS traffic from a Wireshark .pcap/.pcapng file.

Uses tshark (installed together with Wireshark) to extract fields, then
counts protocols, HTTP methods/hosts/status codes, TLS handshakes and
checks whether credentials are visible in plaintext.

Usage:
    python analyze_pcap.py captures/http_capture.pcapng
    python analyze_pcap.py captures/https_capture.pcapng --out results/https_summary.txt
"""
import argparse
import os
import shutil
import subprocess
import sys
from collections import Counter

FIELDS = [
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "urlencoded-form.key",
    "urlencoded-form.value",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions.supported_version",
]

TLS_VERSIONS = {"0x0304": "TLS 1.3", "0x0303": "TLS 1.2", "0x0302": "TLS 1.1", "0x0301": "TLS 1.0"}
CRED_WORDS = ("user", "login", "uname", "pass", "pwd", "email")
WIN_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def find_tshark():
    path = shutil.which("tshark")
    if path:
        return path
    for p in WIN_PATHS:
        if os.path.exists(p):
            return p
    sys.exit("tshark not found. Install Wireshark or add its folder to PATH.")


def read_packets(pcap):
    cmd = [find_tshark(), "-r", pcap, "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=;"]
    for f in FIELDS:
        cmd += ["-e", f]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(result.stderr)
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(FIELDS) - len(parts))
        rows.append(dict(zip(FIELDS, parts)))
    return rows


def summarise(rows, name):
    out = [f"=== Traffic summary for {name} ===", f"Total packets: {len(rows)}", ""]

    protos = Counter(r["frame.protocols"].split(":")[-1] for r in rows)
    out.append("Top protocols (last layer):")
    out += [f"  {p:<10}{c}" for p, c in protos.most_common(8)]

    # Web HTTP runs over TCP; SSDP discovery (UDP 1900) also looks like HTTP, so exclude it
    web = [r for r in rows if ":tcp" in r["frame.protocols"]]
    methods = Counter(r["http.request.method"] for r in web if r["http.request.method"])
    hosts = Counter(r["http.host"] for r in web if r["http.host"])
    codes = Counter(r["http.response.code"] for r in web if r["http.response.code"])
    out += ["", "HTTP (plaintext):",
            f"  Requests by method : {dict(methods) or 'none'}",
            f"  Hosts contacted    : {dict(hosts) or 'none'}",
            f"  Response codes     : {dict(codes) or 'none'}"]

    creds = []
    for r in rows:
        keys = r["urlencoded-form.key"].split(";")
        vals = r["urlencoded-form.value"].split(";")
        if r["http.request.method"] == "POST" and any(w in k.lower() for k in keys for w in CRED_WORDS):
            creds.append(dict(zip(keys, vals)))
    out.append(f"  Credentials visible in plaintext: {'YES' if creds else 'no'}")
    for c in creds[:3]:
        out.append(f"    -> {c}")

    sni, versions, ciphers = Counter(), Counter(), Counter()
    hellos = 0
    for r in rows:
        types = r["tls.handshake.type"].split(";")
        if "1" in types:
            hellos += 1
            if r["tls.handshake.extensions_server_name"]:
                sni[r["tls.handshake.extensions_server_name"].split(";")[0]] += 1
        if "2" in types:
            v = r["tls.handshake.extensions.supported_version"].split(";")[-1]
            versions[TLS_VERSIONS.get(v, v or "TLS 1.2 or older")] += 1
            ciphers[r["tls.handshake.ciphersuite"].split(";")[0]] += 1
    out += ["", "HTTPS (TLS):",
            f"  Client Hello messages : {hellos}",
            f"  Servers (SNI)         : {dict(sni) or 'none'}",
            f"  Negotiated version    : {dict(versions) or 'none'}",
            f"  Cipher suite (code)   : {dict(ciphers) or 'none'}",
            "  Application data is encrypted, so no URLs or form fields are readable."
            if hellos else "  No TLS traffic in this capture."]
    return "\n".join(out), protos


def save_chart(protos, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    labels, counts = zip(*protos.most_common(6))
    plt.figure(figsize=(6, 4))
    plt.bar(labels, counts)
    plt.title("Packets per protocol")
    plt.tight_layout()
    plt.savefig(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--out", help="save the text summary to this file")
    args = ap.parse_args()

    text, protos = summarise(read_packets(args.pcap), os.path.basename(args.pcap))
    print(text)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        save_chart(protos, os.path.splitext(args.out)[0] + "_chart.png")


if __name__ == "__main__":
    main()
