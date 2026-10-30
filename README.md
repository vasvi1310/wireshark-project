# Analysis of HTTP and HTTPS Traffic Using Wireshark

Computer Networks (CN) Mini Project

**Team:** Patel Vasvi (202407020076), Vishva Patel (202407020531)
**Guide:** Ms. Pragya Vats
**Institute / Semester:** UnitedWorld Institute of Technology, Karnavati University, B.Tech CSE Sem 5

## Objective
Capture and analyse web traffic with Wireshark to show how HTTP (plaintext) and
HTTPS (TLS-encrypted) differ at the packet level, and what an observer on the
network can and cannot see in each case.

## Tools Used
- Wireshark 4.x (packet capture and display filters)
- Python 3 + tshark (command-line Wireshark) for automated summary of captures
- Test sites: `http://neverssl.com`, `http://testphp.vulnweb.com`, `https://example.com`

## Repository Structure
```
.
├── README.md
├── analyze_pcap.py        # summarises a capture (protocols, HTTP, TLS, credentials)
├── captures/              # .pcapng files from Wireshark
├── screenshots/           # numbered screenshots used in report and PPT
├── results/               # output of analyze_pcap.py
└── report/                # final report and presentation
```

## How to Reproduce
1. Install Wireshark (with Npcap) and Python 3.
2. Capture HTTP and HTTPS traffic as described in the report and save into `captures/`.
3. Run the analysis:
   ```
   python analyze_pcap.py captures/http_capture.pcapng --out results/http_summary.txt
   python analyze_pcap.py captures/https_capture.pcapng --out results/https_summary.txt
   ```
   `tshark` must be installed (it comes with Wireshark). Optional: `pip install matplotlib` for a protocol chart.

## Display Filters Used
| Filter | Purpose |
|---|---|
| `http` | Show all HTTP packets |
| `http.request.method == "GET"` | HTTP GET requests |
| `http.request.method == "POST"` | Form submissions (login) |
| `tcp.port == 80` | Plain HTTP traffic |
| `tcp.port == 443` | HTTPS traffic |
| `tls` | All TLS packets |
| `tls.handshake.type == 1` | TLS Client Hello |
| `tls.handshake.type == 2` | TLS Server Hello |
| `dns` | DNS lookups before connections |

## Key Findings
<Fill in after your captures: e.g. HTTP showed readable GET/POST and credentials; HTTPS showed only the TLS handshake and encrypted Application Data.>

## Conclusion
HTTPS protects confidentiality and integrity of web traffic, while HTTP exposes
requests, responses and credentials to anyone who can capture packets.

## References
- Cisco CyberOps lab: Using Wireshark to Examine HTTP and HTTPS Traffic
- Wireshark User Guide, https://www.wireshark.org/docs/
