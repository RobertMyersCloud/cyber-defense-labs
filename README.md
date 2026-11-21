# Cyber Defense Labs

Hands-on labs I built and ran on my own home lab while working through the SANS Technology Institute Applied Cybersecurity program. Each lab is my own setup, my own traffic, and my own results. No course material is reproduced here.

Every lab follows the same shape: run it, see what it leaves behind, detect it, and decide what to do about it.

## Incident Handling

Attack techniques run against my own targets, then traced back through the evidence they leave.

## Security Essentials

Network monitoring, host defense, and crypto, worked on real captures and real machines.

| Lab | What it shows |
|---|---|
| [01 Zeek and Snort 3 on my own traffic](essentials/01-zeek-snort-own-traffic/) | Broke down a DNS volume spike, wrote and tested my own Snort rules, and found and closed an LLMNR exposure on a Windows host |
| [02 Packet triage with tshark](essentials/02-tshark-packet-triage/) | Found traffic the logs never show, identified devices from MAC vendors without sending a packet, and worked out why three tools disagreed about the same checksums |

## Foundations

Linux, networking, and password basics, done hands-on.

| Lab | What it shows |
|---|---|

## Lab environment

Isolated range behind a TP-Link ER605 with default-deny to the household network. Targets run as VMs on Proxmox. Logs go to a Splunk instance on the range. Attacks come from a dedicated Kali laptop. Detection work for these labs also lives in [soc-lab](https://github.com/RobertMyersCloud/soc-lab).

## Related

- [packet-analysis-lab](https://github.com/RobertMyersCloud/packet-analysis-lab)
- [pcap-pattern-detector](https://github.com/RobertMyersCloud/pcap-pattern-detector)
- [prove-it](https://github.com/RobertMyersCloud/prove-it)
