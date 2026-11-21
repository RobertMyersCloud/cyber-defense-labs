# Packet Triage with tshark

**Summary:** I took the same eight-minute capture from [lab 01](../01-zeek-snort-own-traffic/) and worked it packet by packet with tshark instead of through Zeek's logs. Working below the logs turned up traffic Zeek never reports, identified every chatty device on my network without sending a single packet, and settled a disagreement between three tools about whether my own packets were corrupt.

Addresses, MAC addresses and device names from my home network are replaced with labels.

## Setup

| Role | Host | Notes |
|---|---|---|
| Capture and analysis | LINUX-01 | Ubuntu laptop, wired to the home LAN |
| Packet analysis | tshark 4.6.4 | Read-only against the capture file |

**Evidence:** the same capture as lab 01. SHA-256 `6914ec4af89fb4be525fc2c77b36f18754e2e931db7a5be09e9767648097ecc9`, checked before this lab started and unchanged.

## What I ran and why

| Step | Command | Why |
|---|---|---|
| Inventory | `tshark -r <pcap> -q -z io,phs` | Every protocol in the capture, nested by layer, before looking at a single packet |
| Unknown traffic | `-Y 'udp && data' -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport` | UDP no dissector recognized, stack-counted by flow |
| Device identity | `-Y 'ip.src in {...}' -T fields -e ip.src -e eth.src_resolved` | MAC vendor for each unknown talker |
| Protocol detail | `-Y tplink-smarthome -V -O eth,ip,udp,tplink-smarthome` | Full decode of one frame, limited to the layers that matter |
| ARP behavior | `-Y 'arp.opcode == 1' -T fields -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4` | Who is asking for whom |
| Checksums | `-o tcp.check_checksum:TRUE` / `-o ip.check_checksum:TRUE` | Turn on validation that tshark leaves off by default |
| Conversation | `-q -z follow,tcp,ascii,5` | Rebuild one full request and response from raw bytes |

`-Y` takes Wireshark display filter syntax (`udp.port == 5355`), not the BPF capture filter syntax tcpdump uses (`udp port 5355`). They are different languages, and mixing them up is a common mistake.

## What it left behind

### Protocol inventory

The protocol counts line up exactly with Zeek's logs from lab 01:

| Protocol | tshark frames | Zeek entries |
|---|---|---|
| mDNS | 7,434 IPv4 + 6,374 IPv6 = 13,808 | 13,808 |
| DNS | 26 (13 queries, 13 responses) | 13 |
| LLMNR | 4 | 4 |
| HTTP | 8 (4 requests, 4 responses) | 4 |

Two tools built differently agree on the counts.

### Traffic Zeek never shows

Zeek's logs are built around IP. Everything directly on Ethernet is invisible there:

| Protocol | Frames | What it is |
|---|---|---|
| ARP | 1,680 | IP-to-MAC resolution (see below) |
| EtherType 0x88ca, decoded as TIPC | 501 | Unicast between TP-Link mesh nodes |
| IEEE 1905.1 | 24 | The control protocol Wi-Fi EasyMesh runs on |
| LLDP | 8 | A device announcing itself and its port |

Wireshark labels 0x88ca as TIPC from the EtherType alone. That's the registered number, but I can't confirm the mesh actually runs TIPC rather than reusing the number. The MACs show three TP-Link units with nearly sequential addresses, which means a mesh kit bought together.

### Unknown UDP

2,098 UDP frames had no protocol match. Stack counting broke them down:

- **1,736 frames** were LINUX-01's QUIC session to a web application. tshark identifies QUIC by its long-header handshake, and this session started before the capture, so only short-header packets were seen. Zeek's `weird.log` reported the same thing in lab 01.
- **250 frames** from a Samsung device to multicast `224.0.0.7:8001`, plus broadcasts to port 15600. Port 8001 is commonly associated with Samsung smart TV remote control.
- **Port 20002 broadcasts** from three TP-Link devices, which fits TP-Link's device discovery.
- **Port 56700 broadcasts** from an LG device.

### Identifying devices without touching them

MAC vendor prefixes named every chatty device:

| Label | Vendor | Behavior |
|---|---|---|
| MESH-NODE-A, B, C | TP-Link | Mesh coordination over 0x88ca and IEEE 1905.1, discovery on 20002 |
| TP-LINK-01 | TP-Link | Different serial range from the mesh, discovery on 20002 |
| SMART-TV-01 | Samsung | Multicast on 8001, discovery broadcasts on 15600 |
| SMART-HUB-01 | LG | Discovery probes for other vendors' devices (below) |

Port 56700 first pointed me at LIFX bulbs. The MAC showed an LG device, and the next finding showed why both were partly right: the port was the LIFX protocol, but the LG device was the one asking for LIFX bulbs, not answering as one. A port number tells you the protocol. It doesn't tell you which side a device is on.

### A smart-home hub probing for other vendors' devices

The one TP-Link Smart Home (Kasa) frame came from SMART-HUB-01, broadcast to the whole network on port 9999:

```
{"system":{"get_sysinfo":{}},"emeter":{"get_realtime":{}}}
```

It's asking every Kasa plug on the network for its device details and its live power reading. Kasa's local protocol uses a fixed XOR scheme, not encryption, so tshark decoded the command with no key. Nothing answered, so there was no Kasa device on the network during the capture.

Live power readings are pattern-of-life data: they show when people are home, awake or away. Anyone on the network can send the same broadcast.

### ARP: a hub chasing devices that are gone

Half of all ARP traffic came from one device. SMART-HUB-01 asked for the same 10 IP addresses about every 6 seconds for the entire capture:

| Measure | Result |
|---|---|
| Distinct targets | 10 |
| Requests per target | about 84 |
| Replies received | 0 |

It's a stale device list, not a sweep. A sweep walks the whole subnet and moves on, while this kept asking for the same 10 addresses that no longer exist.

### Three tools, one packet, three verdicts

In lab 01, Snort went from 6 alerts to 0 when I removed `-k none`. Here's what each tool said about the same bytes:

| Tool | Verdict on LINUX-01's outbound packets |
|---|---|
| tshark 4.6.4 | Checksums "Good" on all 604 outbound TCP packets |
| Snort 3 (`-k all`) | 593 bad TCP, 1,697 bad UDP over IPv4, 1 bad UDP over IPv6; 2,330 packets discarded |
| Zeek (no `-C`) | Bad TCP and UDP checksums on LINUX-01's connections, plus a warning about NIC offloading |

The full decode of one flagged packet explained it:

```
Checksum: 0x4f19 [correct] (matches partial checksum, not 0x9af3, likely caused by "TCP checksum offload")
```

LINUX-01's network card offloads checksums. The driver writes only a partial (pseudo-header) checksum, and the card finishes it as the packet leaves. The capture copies the packet before that happens. tshark recognizes the partial checksum and calls it correct. Snort and Zeek compute the full checksum, see a mismatch, and throw the packet away.

The bytes were the same in all three tools. What differed was how each tool judged them.

### Rebuilding the marked request

Following TCP stream 5 gave the full exchange:

```
GET /uploadiframe.php HTTP/1.1
Host: example.com
User-Agent: GSEC-drill
Accept: */*

HTTP/1.1 404 Not Found
Server: cloudflare
Age: 5
cf-cache-status: HIT
CF-RAY: <redacted>
alt-svc: h3=":443"; ma=86400
```

- **Four headers is curl's default set.** A browser sends many more. That's how you tell a script from a person.
- **`cf-cache-status: HIT` with `Age: 5`:** the CDN answered from cache. The request never reached the origin server.
- **`alt-svc: h3`:** the server advertises HTTP/3. That's why browser sessions in this capture moved to QUIC.
- **The server's `Date` header matched Snort's alert time to the second.** A clock I don't control backs up my sensor's timeline.

## How I detected it

Every finding here came from four moves: inventory with `io,phs`, filter to what's unknown, stack count with `-T fields` and `sort | uniq -c`, then decode one example in full with `-V -O`.

## Response

Nothing in this capture was hostile. The findings are hardening items for the network:

- Clear the stale device list on SMART-HUB-01, so it stops asking for addresses anyone could claim.
- Put smart TVs, hubs and other IoT devices on their own network segment, away from laptops. Their discovery traffic is a free inventory for anyone on the same network.
- Treat local smart-home protocols that use XOR or no encryption as readable by anyone on the network.

## What broke

- **AppArmor blocked tshark from reading my own files.** tshark couldn't open my Wireshark preferences or the capture file, even though both were readable by my user. File ownership was fine and tshark had no special privileges. No denial showed up in the kernel log. `aa-status` showed a tshark profile was loaded, and reading the profile showed it only allows system paths and `/tmp`. The rule that allows reading `.pcap` files is in its `dumpcap` child profile, not tshark's. I added three read-only, owner-only rules in `/etc/apparmor.d/local/tshark`, Ubuntu's supported override file, reloaded only that profile, and the same command worked.
- **Filter syntax changed between versions.** `ip.src in {a b c}` fails in Wireshark 4.6. It needs commas: `{a, b, c}`. The error pointed straight at it.
- **I read a tool's verdict instead of its evidence.** tshark's checksum status said "Good" for all 1,233 TCP packets, and I briefly took that to mean nothing was wrong with them. The full decode showed tshark had recognized offloaded partial checksums and accepted them. The status field is the tool's conclusion. The detail line is the evidence.

## Walking it backward

- Logs are someone else's summary. Zeek's logs never showed the mesh traffic, the 0x88ca frames or the IEEE 1905.1 control traffic. Going down to the packets shows what the summary left out.
- Eight minutes of listening, without sending anything, gave a map of every chatty device and what it is. An attacker on the same network gets the same map for free. A defender gets an asset inventory without installing anything.
- A device asking out loud for addresses nobody holds can be answered by anyone. Whoever claims one of those addresses receives whatever the device meant to send.
- When tools disagree, decode one packet in full before choosing a side. Here the data was the same in all three. The difference was the rule each one applied.
- A timestamp from someone else's server that matches your sensor's is strong corroboration for a timeline.
