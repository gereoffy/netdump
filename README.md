# netdump
tcpdump alternative for quick pcap traffic visualisation

A minimal, libpcap-based tcpdump alternative for Linux and macOS.
It prints one line per packet in fixed-width columns, with no name resolution
(all addresses and ports are shown as numbers).

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
netdump <interface> [bpf filter expression...]
```

- The interface is required. Without it (or with `-h` / `--help`) the program
  lists the available interfaces with their IPv4 addresses and exits.
- Any arguments after the interface form an optional BPF filter, using the same
  syntax as tcpdump (`man pcap-filter`).
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
```

## Output

```
vlan src-mac           dst-mac           src-ip          dst-ip          proto  sport dport
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 10.0.0.1        192.168.100.200 TCP    51234   443
100  11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         8.8.8.8         UDP     5353    53
4094 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         5.6.7.8         ICMP   echo-req
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         5.6.7.8         47
     11:22:33:44:55:66 ff:ff:ff:ff:ff:ff 192.168.1.1     192.168.1.254   ARP
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff                                 IPv6
     11:22:33:44:55:66 01:80:c2:00:00:00                                 STP
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

For ICMP the two port columns hold the ICMP type instead (see below).

Values of the `proto` column:

| Value              | Meaning |
|--------------------|---------|
| `TCP`, `UDP`, `ICMP` | IPv4 with that protocol |
| number (e.g. `47`) | IPv4 with another protocol (IP protocol number) |
| `ARP`              | ARP |
| `IPv6`             | IPv6 (not decoded further) |
| `0x....`           | other ethertype, in hex |
| `STP`              | Spanning Tree BPDU (802.3/LLC, or Cisco PVST+ over SNAP) |
| `CDP`              | Cisco Discovery Protocol |
| `LLC:xx`           | other 802.3/LLC frame, `xx` is the DSAP in hex (e.g. `LLC:e0` = IPX) |
| `SNAP`             | SNAP frame with a vendor-specific OUI |
| `LLC`              | truncated 802.3/LLC frame |

802.3 frames carrying IPv4 or ARP in an RFC 1042 SNAP header are decoded the
same way as Ethernet II frames.

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

The header line goes to stdout, status messages go to stderr. Output is
line-buffered, so it shows up immediately in a pipe (`| grep`, `| tee`).

## Limitations

- Only Ethernet (`DLT_EN10MB`) interfaces are supported; e.g. macOS `lo0` or
  the Linux `any` pseudo-interface won't work.
- Only IPv4 is decoded. For IPv6 packets only the MAC addresses and `IPv6`
  are shown.
- Only a single 802.1Q tag is handled, no QinQ.
- For fragmented IP packets, ports are shown only in the first fragment.
