# SBT-DF203 — Lab 5: ARP Poisoning Forensics

Forensic analysis of an ARP capture — request/reply field extraction, IP-to-MAC claim summarisation, unsolicited-reply isolation, and detection of poisoning indicators.

## Author

| Field | Detail |
| :--- | :--- |
| **Student** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Instructor** | Aminu Idris, AMCPN |
| **Delivery Block** | 2/3 of 3 |
| **Submission Date** | 16 September 2026 |

## Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Environment](#environment)
4. [Methodology](#methodology)
5. [Key Findings](#key-findings)
6. [Analysis](#analysis)
7. [Evidence and Integrity](#evidence-and-integrity)
8. [Repository Structure](#repository-structure)
9. [Reproducing the Analysis](#reproducing-the-analysis)
10. [Detection and Mitigation](#detection-and-mitigation)
11. [Safety and Ethics](#safety-and-ethics)
12. [References](#references)
13. [License](#license)

## Overview

This repository contains the forensic analysis of an ARP packet capture (`arp.pcap`) supplied by ICDFA as an authorised training artefact for Lab 5 of the SBT-DF203 course. The capture records eight ARP frames from an internal `136.160.215.0/24` network.

The analysis identifies request/reply roles, extracts the full ARP field structure, summarises IP-to-MAC claims, and isolates unicast replies. The workflow demonstrates the analytical methodology used to detect ARP poisoning — the same filters and rules that flag a real attack in a hostile capture.

The live host-only poisoning simulation was **not performed**, because the lab VM's network could not be confirmed as an isolated host-only switch. The reasoning is documented in Section 7.

## Objectives

1. Explain how ARP maps IPv4 addresses to MAC addresses on a local network.
2. Inspect ARP caches on Linux systems.
3. Identify ARP requests, legitimate replies, and unsolicited or conflicting replies.
4. Detect one IP address being associated with multiple MAC addresses.
5. Capture and document a bounded ARP-poisoning simulation in a host-only network.
6. Restore network state and recommend preventive controls.

## Environment

| Component | Version |
| :--- | :--- |
| Operating System | Kali Linux (ICDFA lab VM) |
| TShark | 4.6.6 |
| Wireshark | 4.6.6 |
| Python | 3.14.6 |
| Scapy | 2.7.0 |
| Analysis Mode | Offline pcap — no live capture performed |

## Methodology

| Phase | Description | Output |
| :---: | :--- | :--- |
| 1 | Create folder structure and install tools | Environment ready |
| 2 | Download and preserve the supplied capture | `evidence/arp.pcap`, `working/arp_working.pcap` |
| 3 | Record baseline interface, route, and ARP cache | `interfaces.txt`, `routes.txt`, `arp_table_initial.txt` |
| 4 | Extract ARP request/reply fields | `normal_arp_fields.tsv` |
| 5 | Summarise IP-to-MAC claims and unicast replies | `ip_mac_claims.txt`, `unicast_arp_replies.tsv` |
| 6 | Run expert analysis and confirm restoration state | `expert_info.txt`, `process_check.txt` |

## Key Findings

| Indicator | Value |
| :--- | :--- |
| Capture file | `arp.pcap` — 1.1 KB |
| Packet count | 8 ARP frames |
| Total requests | 6 |
| Total replies | 2 |
| Gratuitous requests | 2 (from gateway `136.160.215.1`) |
| Probe requests | 2 (for non-existent hosts `.199` and `.183`) |
| Request/reply pair | Victim `136.160.215.194` ↔ Analyst `136.160.215.15` |
| Duplicate IP conflict | None |
| Unsolicited replies | None — both replies follow requests |
| Expert info warnings | None |
| Poisoning indicators | None — capture shows clean ARP behaviour |
| MITM confirmed | No |
| Live simulation | Not performed — see Section 7 |

The capture demonstrates a clean ARP exchange with no poisoning indicators. Every IP maps to exactly one MAC, and both unicast replies are direct answers to specific requests. The analytical workflow applied here — field extraction, claim summarisation, unicast-reply isolation — is directly transferable to hostile captures, where the same filters would surface duplicate-IP conflicts, unsolicited replies, and gateway MAC changes.

## Analysis

### 1. Environment Setup

The lab folder structure was created to separate evidence, working copies, reports, and screenshots.

```bash
mkdir -p ~/SBT-DF203-Lab5/{evidence,working,exported,reports,screenshots,scripts}
cd ~/SBT-DF203-Lab5
find . -maxdepth 1 -type d -print
https://screenshots/fig_3.1_folder_structure.png

Figure 3.1 — Lab folder structure created successfully.

bash
sudo apt update
sudo apt install -y wireshark tshark python3-scapy net-tools
tshark --version
python3 --version
https://screenshots/fig_3.2_tools_installed.png

Figure 3.2 — TShark 4.6.6, Python 3.14.6, and Scapy 2.7.0 installed and verified.

2. Supplied Capture and Integrity
bash
wget -O evidence/arp.pcap \
  'https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Networking_Forensics/lab_files/ARP_spoofing/arp.pcap'

cp --preserve=timestamps evidence/arp.pcap working/arp_working.pcap
capinfos evidence/arp.pcap | tee reports/arp_capinfos.txt
sha256sum evidence/arp.pcap working/arp_working.pcap | tee reports/arp_capture_hashes.txt
Capture metadata:

Field	Value
File size	1.1 KB
Packet count	8
Encapsulation	Ethernet
Capture filter	arp
Capture OS	Linux 6.1.0-kali5-amd64
Capture application	Dumpcap 4.0.3
SHA-256	342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e
SHA-1	003c0b130e09d431e28602907ac48b79ab81175f
https://screenshots/fig_3.3_capture_hashes.png

Figure 3.3 — arp.pcap details, capinfos summary, and matching SHA-256 hashes.

3. Baseline ARP State
bash
ip -br address | tee reports/interfaces.txt
ip route | tee reports/routes.txt
ip neigh show | tee reports/arp_table_initial.txt
Lab VM network state:

Field	Value
Interface	eth0
IPv4	192.168.137.192/24
Default gateway	192.168.137.1
Assignment	DHCP
https://screenshots/fig_3.4_baseline_state.png

Figure 3.4 — Lab VM interface addresses, route, and initial ARP table.

4. Part A — Normal ARP Resolution
The gateway entry was cleared to force a fresh ARP exchange.

bash
IFACE=$(ip route | awk '/default/ {print $5; exit}')
GATEWAY_IP=$(ip route | awk '/default/ {print $3; exit}')
sudo ip neigh flush "$GATEWAY_IP" dev "$IFACE"
ip neigh show | grep "$GATEWAY_IP" || echo "Gateway entry cleared"
https://screenshots/fig_4.1_gateway_flushed.png

Figure 4.1 — Gateway entry cleared from the ARP cache.

bash
sudo tshark -i "$IFACE" -f 'arp' -a duration:20 -w evidence/normal_arp.pcapng
Result: Permission denied — dumpcap dropped privileges before opening the target path.

https://screenshots/fig_4.2_capture_permission_error.png

Figure 4.2 — TShark capture attempt blocked by the dumpcap privilege model.

The capture was retried against /tmp (world-writable). A short 4-packet baseline was written.

bash
sudo tshark -i eth0 -f 'arp' -p -w /tmp/normal_arp.pcapng
ls -lh /tmp/normal_arp.pcapng
Result: 656 bytes, 4 ARP frames, /tmp file owned by root.

https://screenshots/fig_4.3_partial_baseline_capture.png

Figure 4.3 — Partial ARP baseline captured to /tmp — 4 frames, root-owned.

Ping to the gateway after the flush confirmed connectivity.

bash
ping -c 1 "$GATEWAY_IP"
https://screenshots/fig_4.4_ping_after_flush.png

Figure 4.4 — Successful ICMP ping to 10.0.2.2 after the ARP entry was cleared.

The partial capture was inspected and found to contain request-only traffic (no reply), consistent with the VMware NAT shortcut.

bash
tshark -r /tmp/normal_arp.pcapng
https://screenshots/fig_4.5_baseline_inspection.png

Figure 4.5 — Inspection of the partial baseline — request frames only.

5. Part B — ARP Request and Reply Fields
Because the local baseline contained no reply, the supplied capture was used for the field-level analysis.

bash
PCAP=working/arp_working.pcap
tshark -r "$PCAP" -Y 'arp' -T fields \
  -e frame.number -e frame.time -e eth.src -e eth.dst -e arp.opcode \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/normal_arp_fields.tsv
Field comparison — request vs. reply:

Field	Normal Request (Frame 3)	Normal Reply (Frame 4)
Ethernet destination	ff:ff:ff:ff:ff:ff	00:50:56:86:cb:fc
ARP opcode	1	2
Sender protocol address	136.160.215.15	136.160.215.194
Sender hardware address	00:50:56:86:02:65	00:50:56:86:02:65
Target protocol address	136.160.215.194	136.160.215.15
Target hardware address	00:00:00:00:00:00	00:50:56:86:cb:fc
https://screenshots/fig_5.1_arp_fields.png

Figure 5.1 — ARP request and reply field extraction.

6. Part C — Analyse the Supplied Poisoning Capture
6.1 ARP Reply Inventory
bash
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/arp_replies.tsv
Frame	Time (epoch)	eth.src	eth.dst	src_ip	src_mac	dst_ip
4	1678591364.904	00:50:56:86:02:65	00:50:56:86:cb:fc	136.160.215.194	00:50:56:86:02:65	136.160.215.15
6	1678591369.943	00:50:56:86:cb:fc	00:50:56:86:02:65	136.160.215.15	00:50:56:86:cb:fc	136.160.215.194
https://screenshots/fig_6.1_arp_replies.png

Figure 6.1 — ARP reply inventory — every ARP reply in the capture.

6.2 IP-to-MAC Claim Summary
bash
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort | uniq -c | sort -nr | tee reports/ip_mac_claims.txt
Count	Claimed IP	Claimed MAC	Legitimate Owner
1	136.160.215.194	00:50:56:86:02:65	Victim (VMware)
1	136.160.215.15	00:50:56:86:cb:fc	Analyst host (VMware)
Each IP is claimed by exactly one MAC — no duplicate-IP conflict is present.

https://screenshots/fig_6.2_ip_mac_claims.png

Figure 6.2 — IP-to-MAC claim summary.

6.3 Unsolicited (Unicast) Replies
bash
tshark -r "$PCAP" -Y 'arp.opcode==2 && eth.dst!=ff:ff:ff:ff:ff:ff' -T fields \
  -e frame.number -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac -e eth.dst \
  | tee reports/unicast_arp_replies.tsv
Frame	Timestamp	src_ip	src_mac	eth.dst
4	2023-03-11T22:22:44.904123642-0500	136.160.215.194	00:50:56:86:02:65	00:50:56:86:cb:fc
6	2023-03-11T22:22:49.943043799-0500	136.160.215.15	00:50:56:86:cb:fc	00:50:56:86:02:65
Both replies are unicast, and both have matching requests in the capture (frame 4 answers frame 3; frame 6 answers frame 5). Neither is unsolicited.

https://screenshots/fig_6.3_unicast_replies.png

Figure 6.3 — Unicast ARP replies from the capture.

6.4 Expert Information
bash
tshark -r "$PCAP" -q -z expert | tee reports/expert_info.txt
Output: (empty) — no warnings raised.

Wireshark's expert analysis returned no duplicate-IP warnings, no sequence anomalies, and no malformed ARP frames. This is consistent with the claim summary and confirms the capture contains clean ARP behaviour.

https://screenshots/fig_6.4_expert_info.png

Figure 6.4 — Wireshark expert information — no warnings raised.

6.5 Visual Confirmation in Wireshark
bash
wireshark working/arp_working.pcap &
Display filter: arp.opcode==2. Two reply frames are listed; each expands to show the sender and target fields extracted in Section 6.1.

https://screenshots/fig_6.5_wireshark_view.png

Figure 6.5 — Wireshark GUI view of arp_working.pcap, filtered to ARP replies.

7. Part D — Controlled Host-Only Simulation (Not Performed)
The lab VM's final network configuration placed it on 192.168.137.0/24 with a default route via 192.168.137.1. A default route indicates the VM could reach addresses beyond the local subnet — by definition not an isolated host-only switch.

bash
ip -br address
ip route
https://screenshots/fig_7.1_final_network_state.png

Figure 7.1 — Final VM network state showing the default route via 192.168.137.1.

The lab manual states:

The live component is optional and must use instructor-assigned RFC1918 addresses on a host-only/internal virtual switch. Never poison a home, school, office, hotel or public Wi-Fi network.

A poisoning attempt against 192.168.137.1 would have affected the host machine's ARP cache — outside ICDFA authorisation. The simulation was therefore not performed.

bash
sudo tshark -i "$IFACE" -f 'arp' -a duration:40 -w evidence/controlled_arp_poison.pcapng
sudo timeout 30 python3 scripts/arp.py "$VICTIM_IP" "$GATEWAY_IP"
Result: Both commands failed — capture write blocked by dumpcap privileges; scripts/arp.py not present. No poisoning traffic was generated.

https://screenshots/fig_7.2_simulation_not_performed.png

Figure 7.2 — Attempts to start the live simulation failed; no poisoning traffic was generated.

8. Part E — Detection Logic
Applying the detection rules from the report:

Rule	Present?	Evidence
Duplicate IP detected by Wireshark expert info	No	Section 6.4
ARP reply without a recent request	No	Frames 3 → 4, 5 → 6
Gateway IP claimed by non-gateway MAC	No	Gateway MAC consistent
Single MAC claiming ≥2 IPs	No	Section 6.2
ARP reply rate above baseline	No	2 replies over 8.6 s
The capture therefore demonstrates clean ARP behaviour with no poisoning indicators.

9. Restoration
bash
ps aux | grep -E '[a]rp.py|[s]capy' | tee reports/process_check.txt
cat /proc/sys/net/ipv4/ip_forward
ip neigh show
Results:

Check	Result
arp.py / scapy process running	None
net.ipv4.ip_forward	0 (disabled)
Current ARP cache	Contains only legitimate entries
https://screenshots/fig_9.1_restoration.png

Figure 9.1 — Process check and IP forwarding state — no poisoning artefacts remain.

Evidence and Integrity
Original capture preserved unmodified. All analysis performed on a timestamp-preserved working copy.

File	Size	SHA-256
evidence/arp.pcap	1.1 KB	342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e
working/arp_working.pcap	1.1 KB	342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e
The original and working copy are byte-identical.

Capture Metadata:

Field	Value
File size	1.1 KB
Packet count	8
Encapsulation	Ethernet
Capture filter	arp
SHA-1	003c0b130e09d431e28602907ac48b79ab81175f
Case Metadata:

Field	Value
Case ID	SBT-DF203-Lab5-2025-FWSD-11521
Analyst	Ibrahim Diseh Garba
Registration No.	2025/FWSD/11521
Evidence source	ICDFA-supplied historical capture
Workstation	Kali Linux VM (ICDFA lab)
Repository Structure
text
SBT-DF203-Lab5-2025-FWSD-11521/
├── README.md
├── SBT-DF203-Lab5_2025-FWSD-11521_Ibrahim_Diseh_Garba.pdf
│
├── evidence/
│   ├── arp.pcap
│   └── normal_arp.pcapng
├── working/
│   └── arp_working.pcap
├── exported/
├── reports/
│   ├── arp_capture_hashes.txt
│   ├── arp_capinfos.txt
│   ├── interfaces.txt
│   ├── routes.txt
│   ├── arp_table_initial.txt
│   ├── arp_table_after_ping.txt
│   ├── normal_arp_fields.tsv
│   ├── arp_replies.tsv
│   ├── ip_mac_claims.txt
│   ├── unicast_arp_replies.tsv
│   ├── expert_info.txt
│   └── process_check.txt
├── screenshots/
│   ├── fig_3.1_folder_structure.png
│   ├── fig_3.2_tools_installed.png
│   ├── fig_3.3_capture_hashes.png
│   ├── fig_3.4_baseline_state.png
│   ├── fig_4.1_gateway_flushed.png
│   ├── fig_4.2_capture_permission_error.png
│   ├── fig_4.3_partial_baseline_capture.png
│   ├── fig_4.4_ping_after_flush.png
│   ├── fig_4.5_baseline_inspection.png
│   ├── fig_5.1_arp_fields.png
│   ├── fig_6.1_arp_replies.png
│   ├── fig_6.2_ip_mac_claims.png
│   ├── fig_6.3_unicast_replies.png
│   ├── fig_6.4_expert_info.png
│   ├── fig_6.5_wireshark_view.png
│   ├── fig_7.1_final_network_state.png
│   ├── fig_7.2_simulation_not_performed.png
│   └── fig_9.1_restoration.png
└── scripts/
Reproducing the Analysis
Setup
bash
git clone https://github.com/Disehdon/SBT-DF203-Lab5-ARP-Forensics.git
cd SBT-DF203-Lab5-ARP-Forensics

sudo apt update
sudo apt install -y wireshark tshark python3-scapy net-tools

tshark --version
python3 --version
Capture Integrity
bash
cp --preserve=timestamps evidence/arp.pcap working/arp_working.pcap
sha256sum evidence/arp.pcap working/arp_working.pcap | tee reports/arp_capture_hashes.txt
capinfos evidence/arp.pcap | tee reports/arp_capinfos.txt
ARP Field Extraction
bash
PCAP=working/arp_working.pcap

tshark -r "$PCAP" -Y 'arp' -T fields \
  -e frame.number -e frame.time -e eth.src -e eth.dst -e arp.opcode \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/normal_arp_fields.tsv
ARP Reply Inventory
bash
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/arp_replies.tsv
IP-to-MAC Claim Summary
bash
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort | uniq -c | sort -nr | tee reports/ip_mac_claims.txt
Unsolicited Reply Isolation
bash
tshark -r "$PCAP" -Y 'arp.opcode==2 && eth.dst!=ff:ff:ff:ff:ff:ff' -T fields \
  -e frame.number -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac -e eth.dst \
  | tee reports/unicast_arp_replies.tsv
Expert Analysis
bash
tshark -r "$PCAP" -q -z expert | tee reports/expert_info.txt
Restoration Check
bash
ps aux | grep -E '[a]rp.py|[s]capy' | tee reports/process_check.txt
cat /proc/sys/net/ipv4/ip_forward
ip neigh show
Detection and Mitigation
Detection Controls
Control	Description
Duplicate IP detection	Alert when one IP is claimed by two MACs
Unsolicited reply monitoring	Flag ARP replies without a recent request
Gateway MAC change	Track gateway IP-to-MAC over time
Reply rate threshold	Alert when ARP reply rate exceeds baseline
Mitigation Controls
Control	Description
Dynamic ARP Inspection	Validate ARP against DHCP snooping bindings on managed switches
DHCP Snooping	Build trusted IP-to-MAC bindings used by DAI
Port Security	Limit the number of MAC addresses per switch port
Static ARP for critical hosts	Pin gateway and server IP-to-MAC mappings
Encrypted protocols	Mitigate impact — intercepted traffic remains confidential
Network segmentation	Reduce broadcast domain size and attack surface
Forensic Practice
Retain full packet capture during incidents — not just flow data.

Synchronise system clocks across devices for accurate timeline correlation.

Preserve ARP cache state on endpoints before reboot.

Treat any captured credentials as confidential; mask in public reporting.

Document whether the capture was taken at the client, relay, or destination — this determines MAC relevance.

Safety and Ethics
This lab was conducted under ICDFA authority using the supplied historical capture. No live poisoning was performed against any network.

Original arp.pcap preserved unmodified; all analysis performed on a timestamp-preserved working copy.

SHA-256 hashes recorded for chain of custody.

Live host-only poisoning simulation not performed — the VM network could not be confirmed as an isolated host-only switch (see Section 7).

No home, campus, office, or public Wi-Fi network was targeted.

No credentials, personal messages, or confidential traffic were collected.

No IP forwarding, ARP cache, or firewall settings were altered during the lab.

Warning: Any ARP poisoning tool is intended for authorised training only. Never execute ARP poisoning against a home, campus, office, hotel, or public network. The correct decision when a network cannot be confirmed as isolated is to skip the live simulation and document the reasoning.

References
ICDFA. (2026). SBT-DF203 — Module 4: ARP Protocol and ARP Poisoning Forensics — Course Materials.

ICDFA. (2026). SBT-DF203 Lab 5 — ARP Poisoning Forensics — Official Lab Manual.

RFC 826. (1982). An Ethernet Address Resolution Protocol.

RFC 5227. (2008). IPv4 Address Conflict Detection.

Wireshark Foundation. (2026). Wireshark User Guide.

Scapy Project. (2026). Scapy Documentation.

frankwxu. (2026). digital-forensics-lab — ARP_spoofing. GitHub.

License
Submitted as academic coursework for SBT-DF203 Lab 5 at ICDFA. Contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.

© 2026 Ibrahim Diseh Garba. All rights reserved.
