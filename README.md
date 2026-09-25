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
4094 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         5.6.7.8         ICMP
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         5.6.7.8         47
     11:22:33:44:55:66 ff:ff:ff:ff:ff:ff 192.168.1.1     192.168.1.254   ARP
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff                                 0x86dd
```

| Column    | Content |
|-----------|---------|
| `vlan`    | 802.1Q VLAN ID; empty for untagged/native packets |
| `src-mac` | source MAC address |
| `dst-mac` | destination MAC address |
| `src-ip`  | source IPv4 address (sender IP for ARP) |
| `dst-ip`  | destination IPv4 address (target IP for ARP) |
| `proto`   | `TCP`, `UDP`, `ICMP`, `ARP`; the protocol number for other IPv4 protocols, the ethertype in hex for non-IP packets |
| `sport`   | source port (TCP/UDP only) |
| `dport`   | destination port (TCP/UDP only) |

The header line goes to stdout, status messages go to stderr. Output is
line-buffered, so it shows up immediately in a pipe (`| grep`, `| tee`).

## Limitations

- Only Ethernet (`DLT_EN10MB`) interfaces are supported; e.g. macOS `lo0` or
  the Linux `any` pseudo-interface won't work.
- Only IPv4 is decoded. For IPv6 packets only the MAC addresses and the
  ethertype (`0x86dd`) are shown.
- Only a single 802.1Q tag is handled, no QinQ.
- For fragmented IP packets, ports are shown only in the first fragment.
