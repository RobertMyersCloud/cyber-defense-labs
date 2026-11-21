# Zeek and Snort 3 on My Own Traffic

**Summary:** I captured about eight minutes of my own home network traffic, including HTTP requests I marked on purpose, and worked it with Zeek and Snort 3. What looked like a DNS flood was normal device chatter. The real finding was one of my Windows laptops broadcasting LLMNR, which leaves it open to credential capture on the local network. I turned LLMNR off and proved the fix with a before-and-after capture.

Addresses and device names from my home network are replaced with labels. Snort alert times are UTC.

## Setup

| Role | Host | Notes |
|---|---|---|
| Capture and analysis | LINUX-01 | Ubuntu laptop, wired to the home LAN |
| Exposed host | WIN-HOST-01 | Windows 11 laptop on home Wi-Fi |
| Network monitor | Zeek | `zeek/zeek` container |
| IDS | Snort 3.10.0.0 | `ciscotalos/snort3` container, DAQ 3.0.23 |

**Evidence:** one capture, 22,068 packets over 500 seconds.
SHA-256 `6914ec4af89fb4be525fc2c77b36f18754e2e931db7a5be09e9767648097ecc9`

## What I ran and why

### The traffic

I ran tcpdump on LINUX-01 while I generated traffic I could hunt for later:

- `dig @8.8.8.8` lookups for three names
- HTTP requests to `example.com/uploadiframe.php` with the User-Agent set to `GSEC-drill`. The page doesn't exist and returns 404. The point was a known marker, not a real exploit.

Everything else in the capture is whatever my network was doing at the time.

### Evidence handling

I hashed the capture before any tool touched it, mounted it read-only into every container, and hashed it again at the end. Both hashes match.

### Zeek

```
docker run --rm --user "$(id -u):$(id -g)" \
  -v <pcap-dir>:/pcap:ro -v <out-dir>:/out -w /out \
  zeek/zeek zeek -C -r /pcap/capture.pcap
```

`-C` tells Zeek to ignore bad checksums. The capture host offloads checksums to its network card: the driver writes only a partial checksum and the card finishes it after the capture copies the packet, so the host's own outbound packets show the wrong checksum. Without `-C`, Zeek warned about offloading, dropped some DNS, NTP and TLS records, and mis-tracked a few connections. It still logged the four HTTP requests. [Lab 02](../02-tshark-packet-triage/) shows the partial checksum in a single packet.

### Snort 3

I wrote two rules of my own for the marker, one per field, so changing either the User-Agent or the path still trips the other:

```
alert http (msg:"LAB drill marker in User-Agent"; flow:established,to_server; http_header:field user-agent; content:"GSEC-drill"; sid:1000001; rev:1;)
alert http (msg:"LAB request for uploadiframe.php"; flow:established,to_server; http_uri; content:"/uploadiframe.php", nocase; sid:1000002; rev:1;)
```

```
docker run --rm --entrypoint /home/snorty/snort3/bin/snort \
  -v <pcap-dir>:/pcap:ro -v <rules-dir>:/rules:ro \
  ciscotalos/snort3 -c /home/snorty/snort3/etc/snort/snort.lua \
  -R /rules/local.rules -r /pcap/capture.pcap -k none -A alert_fast -q
```

`-k none` is the Snort version of Zeek's `-C`. Without it, Snort counted 593 TCP and 1,698 UDP packets as having bad checksums and discarded 2,330 packets. The rules are in [rules/local.rules](rules/local.rules).

## What it left behind

### The DNS "flood"

`dns.log` held 13,825 entries against 319 connections in `conn.log`. That's roughly 27 DNS transactions a second, enough to look like tunneling or a loop. Splitting it by port showed what it really was:

| Port | Protocol | Entries | What it is |
|---|---|---|---|
| 5353 | mDNS | 13,808 | Household devices (printer, phones, TVs) announcing themselves on multicast |
| 53 | DNS | 13 | LINUX-01's real lookups |
| 5355 | LLMNR | 4 | WIN-HOST-01 |

99.9% of it was normal mDNS. The loudest talkers were a printer advertising its print service and devices announcing their `.local` names.

LINUX-01's 13 real lookups fell into two patterns:

- **A record only, one query each, to 8.8.8.8:** my `dig` drills. `dig` asks for an A record unless told otherwise.
- **A and AAAA pairs to 1.1.1.1:** the operating system's resolver, which asks for IPv4 and IPv6 together. One of these was Ubuntu's connectivity check.

The shape of a query tells you whether a person ran a tool or the OS did it on its own.

### HTTP

Four requests. Three were my marked requests, each answered with a 404, spread across two different IPs for `example.com` because it sits behind a CDN. The fourth was Ubuntu's connectivity check, which came back 204 and had no User-Agent. Blocking a single IP for a CDN domain would only have caught part of the traffic.

### TLS

The marked HTTPS request completed normally on TLS 1.3. Two other sessions to a web application were flagged as never finishing their handshake. `conn.log` explained why:

- None of their TCP histories start with a SYN (`AaDd`, `^dADa`, `AadFf`). The sessions were already open when the capture started.
- They lasted 454 to 499 seconds of a 500-second capture.
- UDP 443 sessions to the same server show the browser was also using QUIC.
- The one entry in `weird.log` was a QUIC short-header packet for a session whose setup was never captured.

Four logs agree: these sessions were cut off by the capture window, not failed.

## How I detected it

Snort fired 6 alerts: 3 marked requests, each matching both rules. Ubuntu's connectivity check was also plain HTTP on port 80, and it didn't trigger anything.

```
[1:1000002:1] "LAB request for uploadiframe.php" {TCP} LINUX-01:44578 -> 104.20.23.154:80
[1:1000001:1] "LAB drill marker in User-Agent"   {TCP} LINUX-01:44578 -> 104.20.23.154:80
```

The Snort alerts match Zeek's `http.log` one for one: the same three requests to the same two IPs.

## Response

### The finding

WIN-HOST-01 had LLMNR enabled, which is the Windows default. When DNS can't resolve a name, Windows falls back to asking the entire local network over LLMNR, and any machine can answer. An attacker on the same network running a tool like Responder answers those queries and gets a password hash back. The host was also announcing its own default `DESKTOP-` hostname to the network every time it connected, as a name-conflict check.

### Baseline

I checked the registry first. There was no policy under `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, so the default (LLMNR on) applied.

To trigger the fallback, I pinged a name that doesn't exist while LINUX-01 captured UDP 5355 for 90 seconds. The result was 12 packets from WIN-HOST-01: an A and an AAAA query for the fake name, over IPv4 (`224.0.0.252`) and IPv6 (`ff02::1:3`), each sent twice, plus its own hostname check.

### The fix

This laptop runs a Windows edition without the Group Policy editor, so I set the same value the GPO *Turn off multicast name resolution* writes:

```
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
New-ItemProperty -Path $p -Name EnableMulticast -Value 0 -PropertyType DWord -Force
```

The `Test-Path` check matters. `New-Item -Force` on a registry key that already exists recreates it empty and wipes any values in it.

### Proving it

I ran the same test with a new fake name, so the negative cache couldn't hide the lookup, and added a control. WIN-HOST-01 also pinged LINUX-01 directly, which proves it was on the network during the capture. A result of zero packets without a control proves nothing.

| Capture | LLMNR packets | Control (ICMP) |
|---|---|---|
| Before | 12 | none |
| After | 0 | 4 (2 requests, 2 replies) |

It took effect without a reboot.

Not covered here: NetBIOS name service, the other fallback the same attack uses.

## What broke

- **I lost my first Zeek output.** On the first run, the logs ended up outside the evidence folder and weren't kept. This time every run writes inside the lab folder.
- **Checksum offloading hides traffic, and Snort doesn't tell you.** I ran Snort again with `-k none` removed and everything else the same. The result went from 6 alerts to 0, with no warning unless you read its end-of-run counters. A sensor on a host with offloading can report clean when it isn't. Zeek without `-C` at least prints a warning, but it still drops records. Tools also disagree on these packets: tshark recognizes the partial checksum and calls it correct, while Snort and Zeek call it bad. [Lab 02](../02-tshark-packet-triage/) works through all three.
- **The Snort image ignored my commands.** `snort -V` printed nothing. `docker inspect` showed a shell-form entrypoint (`/bin/sh -c /bin/bash`) that throws away arguments. Setting `--entrypoint` to the Snort binary fixed it.
- **My first "before" capture showed 0 packets.** The Windows laptop's Wi-Fi had a `169.254.x.x` address, so it wasn't on the home network at all and its LLMNR went out on another network. I only caught this because I required a positive result before testing the fix. That's also why the "after" test has a control.

## Walking it backward

- A volume spike isn't an incident until it's broken down. Two counts took this one from possible DNS tunneling to printers announcing themselves.
- Query shape separates a person at a keyboard from the OS working on its own. That separation is what puts a human in the timeline.
- A specific marker in a specific field gives you the host, source port and exact time of each request, and two independent tools agreeing on it makes the finding hold up.
- If someone had been answering this host's LLMNR queries, the trail would be an LLMNR response from an unexpected machine, followed by the victim authenticating to that machine over SMB or HTTP. Capturing LLMNR responses, not just queries, is where to look.
- A capture only shows its own window. Sessions that started earlier look broken, and the connection history is how you tell the difference.
