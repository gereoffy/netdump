# netdump
tcpdump alternative for quick pcap traffic visualisation

A minimal, libpcap-based tcpdump alternative for Linux and macOS.
It prints one line per packet in fixed-width columns, with no name resolution
(all addresses and ports are shown as numbers).

## What it's for

netdump is a triage tool for when users complain that "the network doesn't
work": take a quick look at the live traffic, even at several hundred packets
per second, and see whether the basics are fine:

- do SYNs get a SYN+ACK, do ARP requests get a reply?
- do DHCP requests get an OFFER/ACK (or are addresses exhausted, or does DHCP
  snooping on a switch drop them)?
- do DNS queries get answered, and without errors?
- are there suspiciously many ICMP port-unreachables, TCP resets or other
  unusual traffic?

So the output is strictly one line per packet, in aligned columns, showing
only what matters for spotting network faults: VLAN, MAC and IP addresses,
protocol, ports, and a short, greppable summary (`SYN`, `RST`, `NXDOMAIN`,
`DISCOVER`, `port-unr`, ...). The summary printed on exit then shows whether
requests got answers, without reading every line.

Why not tcpdump? Its one-line output doesn't show MAC addresses, the VLAN tag
gets lost in the details, and DHCP is only decoded with `-v -e`, spread over
half a page. For full protocol dissection, use Wireshark; netdump deliberately
leaves details out.

## Building

You need a C compiler and libpcap.

- **macOS:** libpcap ships with the system; the Xcode Command Line Tools are
  enough (`xcode-select --install`).
- **Debian/Ubuntu:** `sudo apt install build-essential libpcap-dev`
- **Fedora/RHEL:** `sudo dnf install gcc make libpcap-devel`

```bash
make
```

## Usage

```
netdump [-v] <interface> [bpf filter expression...]
netdump [-v] -r <file.pcap> [bpf filter expression...]
```

- The interface is required. Without it (or with `-h` / `--help`) the program
  lists the available interfaces with their IPv4 addresses and exits.
- Any arguments after the interface form an optional BPF filter, using the same
  syntax as tcpdump (`man pcap-filter`).
- `-r` reads packets from a pcap file (e.g. one saved with `tcpdump -w` or
  Wireshark) instead of capturing; `-r -` reads from stdin. No root needed.
- `-v` (verbose) adds extra details that are usually just noise: the answers
  in DNS responses and the UDP payload length.
- Capturing requires root (or `CAP_NET_RAW` + `CAP_NET_ADMIN` on Linux, read
  access to the `/dev/bpf*` devices on macOS).
- Ctrl-C stops the capture and prints the number of packets received and
  dropped by the kernel.

Examples:

```bash
sudo ./netdump en0
sudo ./netdump eth0 tcp port 443
sudo ./netdump eth0 vlan and host 10.0.0.1
sudo ./netdump en0 arp or icmp
./netdump -r capture.pcap udp port 67 or udp port 68
```

## Output

```
vlan src-mac           dst-mac            src-ip          dst-ip          proto  sport dport
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff  10.0.0.1        192.168.100.200 TCP    51234   443 SYN
100  11:22:33:44:55:66 aa:bb:cc:dd:ee:ff  1.2.3.4         8.8.8.8         UDP     5353    53
4094 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff  1.2.3.4         5.6.7.8         ICMP   echo-req
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff  1.2.3.4         5.6.7.8         47
     11:22:33:44:55:66 ff:ff:ff:ff:ff:ff  192.168.1.1     192.168.1.254   ARP                request
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff                                  IPv6
     11:22:33:44:55:66 01:80:c2:00:00:00                                  STP
```

| Column    | Content |
|-----------|---------|
| `vlan`    | 802.1Q VLAN ID; empty for untagged/native packets |
| `src-mac` | source MAC address |
| `dst-mac` | destination MAC address |
| `src-ip`  | source IPv4 address (sender IP for ARP) |
| `dst-ip`  | destination IPv4 address (target IP for ARP) |
| `proto`   | see below |
| `sport`   | source port (TCP/UDP only) |
| `dport`   | destination port (TCP/UDP only) |

After the ports, free-form protocol-specific info may follow (see below).
For ICMP the two port columns hold the ICMP type instead.

Values of the `proto` column:

| Value              | Meaning |
|--------------------|---------|
| `TCP`, `UDP`, `ICMP` | IPv4 with that protocol |
| number (e.g. `47`) | IPv4 with another protocol (IP protocol number) |
| `ARP`              | ARP |
| `DHCP`             | DHCP (UDP ports 67/68), see below |
| `DNS`              | DNS (UDP port 53), see below |
| `QUIC`             | QUIC / HTTP/3 (UDP port 443), see below |
| `IPv6`             | IPv6 (not decoded further) |
| `0x....`           | other ethertype, in hex |
| `STP`              | Spanning Tree BPDU (802.3/LLC, or Cisco PVST+ over SNAP) |
| `CDP`              | Cisco Discovery Protocol |
| `LLC:xx`           | other 802.3/LLC frame, `xx` is the DSAP in hex (e.g. `LLC:e0` = IPX) |
| `SNAP`             | SNAP frame with a vendor-specific OUI |
| `LLC`              | truncated 802.3/LLC frame |

802.3 frames carrying IPv4 or ARP in an RFC 1042 SNAP header are decoded the
same way as Ethernet II frames.

For TCP, the info after the ports is a readable summary of the flags:

| Info       | Meaning |
|------------|---------|
| `SYN`      | new connection attempt |
| `SYN+ACK`  | answer to a SYN |
| `FIN`      | connection close |
| `RST`      | connection reset |
| `(N)`      | segment carrying N bytes of payload |
| (nothing)  | plain ACK |

Several items can appear together, separated by spaces, e.g. `FIN (12)`.

With `-v`, the UDP payload length is shown the same way, e.g. `(48)`. (UDP
protocols that matter for troubleshooting, DHCP and DNS, are decoded anyway.)

For DHCP, the info is the message type (`DISCOVER`, `OFFER`, `REQUEST`,
`DECLINE`, `ACK`, `NAK`, `RELEASE`, `INFORM`), followed by the hostname the
client sent (option 12) for client messages, or the assigned address (yiaddr)
for `OFFER` and `ACK`:

```
     11:22:33:44:55:66 ff:ff:ff:ff:ff:ff  0.0.0.0         255.255.255.255 DHCP      68    67 REQUEST laptop
     aa:bb:cc:dd:ee:ff 11:22:33:44:55:66  192.168.1.1     192.168.1.50    DHCP      67    68 ACK 192.168.1.50
```

Plain BOOTP packets (without a DHCP message type) are shown as UDP.

For DNS, the info is the question (type and name). Responses also show the
error code if the lookup failed (`NXDOMAIN`, `SERVFAIL`, `REFUSED`, ...):

```
... DNS    40000    53 A example.com
... DNS       53 40000 A example.com
... DNS       53 40000 A nincs.example.com NXDOMAIN
```

With `-v`, successful responses also show the answer: the first IPv4/IPv6
address (following CNAME chains), otherwise the first record (CNAME, PTR, NS,
MX or SRV target), then `+N` for the remaining answer records; `NODATA` if the
name exists but has no record of the asked type:

```
... DNS       53 40000 A www.example.com -> 1.2.3.4 +3
... DNS       53 40000 PTR 34.216.184.93.in-addr.arpa -> host.example.com
... DNS       53 40000 AAAA example.com NODATA
```

Only DNS over UDP is decoded.

For QUIC (UDP port 443 with the QUIC fixed bit set), long header packets show
their type: `Initial` starts a connection (like a TCP SYN), then `Handshake`;
also `0-RTT`, `Retry` and `VersionNeg`. Data packets show nothing (with `-v`,
the payload length). Other traffic on UDP 443 (e.g. DTLS VPNs) stays `UDP`.

For ARP, the info is the kind of message:

| Info       | Meaning |
|------------|---------|
| `request`  | who has the target IP? |
| `reply`    | answer to a request |
| `announce` | gratuitous ARP: sender announces its own IP (sender IP = target IP) |
| `probe`    | address conflict check before using an IP (sender IP 0.0.0.0, RFC 5227) |
| `op-N`     | other opcode (e.g. RARP) |

ICMP types, shortened to fit the port columns:

| Type/code | Shown as | | Type/code | Shown as |
|-----------|----------|-|-----------|----------|
| 0         | `echo-reply`  | | 3/13 | `adm-prohib` |
| 8         | `echo-req`    | | 3/14 | `prec-viol` |
| 3/0       | `net-unr`     | | 3/15 | `prec-cutoff` |
| 3/1       | `host-unr`    | | 4    | `src-quench` |
| 3/2       | `proto-unr`   | | 5/0–3 | `redir-net`, `redir-host`, `redir-tnet`, `redir-thost` |
| 3/3       | `port-unr`    | | 9    | `rtr-advert` |
| 3/4       | `frag-needed` | | 10   | `rtr-solicit` |
| 3/5       | `srcrt-fail`  | | 11/0 | `ttl-exceed` |
| 3/6       | `net-unknown` | | 11/1 | `reasm-tmout` |
| 3/7       | `host-unkn`   | | 12   | `param-prob` |
| 3/8       | `isolated`    | | 13 / 14 | `tstamp-req` / `tstamp-rep` |
| 3/9       | `net-prohib`  | | 15 / 16 | `info-req` / `info-reply` |
| 3/10      | `host-prohib` | | 17 / 18 | `mask-req` / `mask-reply` |
| 3/11      | `net-tos-unr` | | other | `type/code`, e.g. `42/0` |
| 3/12      | `hst-tos-unr` | | | |

ICMP error messages (unreachable, time exceeded, redirect, source quench,
parameter problem) quote the header of the packet that caused them. After the
type, netdump shows that original packet's protocol and destination, plus the
next-hop MTU for `frag-needed` and the new gateway for redirects:

```
... ICMP   port-unr    UDP 172.18.11.251:161
... ICMP   frag-needed TCP 10.0.0.5:443 mtu=1400
... ICMP   ttl-exceed  UDP 8.8.8.8:33434
... ICMP   redir-host  ICMP 10.0.0.1 gw=172.18.11.1
```

## Summary on exit

When the capture stops (Ctrl-C, or the end of a `-r` file), netdump prints a
summary to stderr, so after a few minutes of traffic you can see at a glance
whether requests get answers:

```
--- 12345 packets (kernel: 12400 received, 0 dropped)
protocols: TCP 10000  IPv6 500  UDP 300  DNS 150  ARP 80  STP 60  ICMP 40  DHCP 8
TCP:       SYN 120  SYN+ACK 118  FIN 90  RST 5
ARP:       request 50  reply 25  announce 3
DHCP:      DISCOVER 2  OFFER 0  REQUEST 0  ACK 0
DNS:       query 150  response 148  NXDOMAIN 3  SERVFAIL 1
QUIC:      Initial 40  Handshake 38
ICMP:      echo-req 10  echo-reply 10  port-unr 12
```

A group appears only if it had any traffic. Request/answer counters (SYN and
SYN+ACK, ARP request and reply, DISCOVER/OFFER/REQUEST/ACK, DNS query and
response, QUIC Initial and Handshake, echo request and reply) are always shown within a group, because a
zero there is the telling part; everything else only when non-zero. The
counts only include packets that passed the BPF filter.

The header line goes to stdout, status messages go to stderr. Output is
line-buffered, so it shows up immediately in a pipe (`| grep`, `| tee`).

## Limitations

- Only Ethernet (`DLT_EN10MB`) interfaces are supported; e.g. macOS `lo0` or
  the Linux `any` pseudo-interface won't work.
- Only IPv4 is decoded. For IPv6 packets only the MAC addresses and `IPv6`
  are shown.
- Only a single 802.1Q tag is handled, no QinQ.
- For fragmented IP packets, ports are shown only in the first fragment.
