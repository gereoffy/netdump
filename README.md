# netdump
tcpdump alternative for quick pcap traffic visualisation

Minimalista, libpcap alapú tcpdump alternatíva Linuxra és macOS-re.
Csomagonként egy sort ír ki, fix szélességű oszlopokban, névfeloldás nélkül
(minden cím és port szám formában jelenik meg).

## Fordítás

Kell hozzá egy C fordító és a libpcap.

- **macOS:** a libpcap a rendszer része, elég az Xcode Command Line Tools
  (`xcode-select --install`).
- **Debian/Ubuntu:** `sudo apt install build-essential libpcap-dev`
- **Fedora/RHEL:** `sudo dnf install gcc make libpcap-devel`

```bash
make
```

## Használat

```
netdump <interface> [bpf filter kifejezés...]
```

- Az interfész megadása kötelező. Nélküle (vagy `-h` / `--help` esetén)
  a program kiírja az elérhető interfészeket az IPv4 címükkel, majd kilép.
- Az interfész utáni argumentumok opcionális BPF filterként működnek, ugyanazzal
  a szintaxissal, mint a tcpdump-nál (`man pcap-filter`).
- A capture-höz root jog (vagy Linuxon `CAP_NET_RAW` + `CAP_NET_ADMIN`,
  macOS-en olvasási jog a `/dev/bpf*` eszközökhöz) kell.
- Ctrl-C-re leáll, és kiírja a kapott, illetve a kernel által eldobott
  csomagok számát.

Példák:

```bash
sudo ./netdump en0
sudo ./netdump eth0 tcp port 443
sudo ./netdump eth0 vlan and host 10.0.0.1
sudo ./netdump en0 arp or icmp
```

## Kimenet

```
vlan src-mac           dst-mac           src-ip          dst-ip          proto  sport dport
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 10.0.0.1        192.168.100.200 TCP    51234   443
100  11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         8.8.8.8         UDP     5353    53
4094 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         5.6.7.8         ICMP
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 1.2.3.4         5.6.7.8         47
     11:22:33:44:55:66 ff:ff:ff:ff:ff:ff 192.168.1.1     192.168.1.254   ARP
     11:22:33:44:55:66 aa:bb:cc:dd:ee:ff                                 0x86dd
```

| Oszlop    | Tartalom |
|-----------|----------|
| `vlan`    | 802.1Q VLAN ID; untagged/native csomagnál üres |
| `src-mac` | forrás MAC cím |
| `dst-mac` | cél MAC cím |
| `src-ip`  | forrás IPv4 cím (ARP-nál a sender IP) |
| `dst-ip`  | cél IPv4 cím (ARP-nál a target IP) |
| `proto`   | `TCP`, `UDP`, `ICMP`, `ARP`; más IPv4 protokollnál a protokollszám, nem-IP csomagnál az ethertype hexben |
| `sport`   | forrás port (csak TCP/UDP) |
| `dport`   | cél port (csak TCP/UDP) |

A fejléc a stdout-ra kerül, a státuszüzenetek a stderr-re. A kimenet soronként
pufferelt, így pipe-ban (`| grep`, `| tee`) is azonnal megjelenik.

## Korlátok

- Csak Ethernet (`DLT_EN10MB`) interfészt támogat. Például a macOS `lo0` vagy
  a Linux `any` pszeudo-interfész nem működik.
- Csak IPv4-et dolgoz fel. IPv6 csomagnál csak a MAC címek és az ethertype
  (`0x86dd`) jelennek meg.
- Csak egyetlen 802.1Q taget kezel, QinQ-t nem.
- Fragmentált IP csomagnál a portok csak az első fragmentben jelennek meg.
