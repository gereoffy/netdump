/*
 * netdump - minimal tcpdump alternative (libpcap)
 *
 * Usage: netdump <interface> [bpf filter expression...]
 *        netdump -r <file.pcap> [bpf filter expression...]
 *
 * One line per packet, fixed-width columns:
 *   vlan src-mac dst-mac src-ip dst-ip proto sport dport [info]
 *
 * No name resolution: addresses and ports are always numeric.
 * Supports Linux and macOS, Ethernet interfaces, IPv4 (+ARP, DHCP).
 */

#include <pcap.h>

#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#define SNAPLEN 1600    /* whole DHCP packets; options start at byte 282 */

#define ETH_HDR_LEN   14
#define VLAN_TAG_LEN  4

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_8021Q 0x8100
#define ETHERTYPE_IPV6  0x86dd

/* type/length field values up to this are an 802.3 length, not an ethertype */
#define ETH_MAX_LEN     1500

#define LLC_SAP_STP     0x42
#define LLC_SAP_SNAP    0xaa
#define LLC_HDR_LEN     3
#define SNAP_HDR_LEN    5

#define OUI_ENCAP       0x000000    /* RFC 1042: PID is an ethertype */
#define OUI_BRIDGE_TUN  0x0000f8    /* 802.1H: PID is an ethertype */
#define OUI_CISCO       0x00000c
#define CISCO_PID_CDP   0x2000
#define CISCO_PID_PVST  0x010b

#define IPPROTO_NUM_ICMP 1
#define IPPROTO_NUM_TCP  6
#define IPPROTO_NUM_UDP  17

/* column widths */
#define W_VLAN  4
#define W_MAC   17
#define W_IP    15
#define W_PROTO 6
#define W_PORT  5

static pcap_t *handle;

static void on_signal(int sig)
{
    (void)sig;
    if (handle)
        pcap_breakloop(handle);
}

static uint16_t rd16(const u_char *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void fmt_mac(char *out, size_t n, const u_char *p)
{
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x",
             p[0], p[1], p[2], p[3], p[4], p[5]);
}

static void fmt_ip(char *out, size_t n, const u_char *p)
{
    snprintf(out, n, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

static void print_header(void)
{
    printf("%-*s %-*s %-*s  %-*s %-*s %-*s %*s %*s\n",
           W_VLAN, "vlan", W_MAC, "src-mac", W_MAC, "dst-mac",
           W_IP, "src-ip", W_IP, "dst-ip", W_PROTO, "proto",
           W_PORT, "sport", W_PORT, "dport");
}

static const char *icmp_unreach_names[] = {
    [0]  = "net-unr",
    [1]  = "host-unr",
    [2]  = "proto-unr",
    [3]  = "port-unr",
    [4]  = "frag-needed",
    [5]  = "srcrt-fail",
    [6]  = "net-unknown",
    [7]  = "host-unkn",
    [8]  = "isolated",
    [9]  = "net-prohib",
    [10] = "host-prohib",
    [11] = "net-tos-unr",
    [12] = "hst-tos-unr",
    [13] = "adm-prohib",
    [14] = "prec-viol",
    [15] = "prec-cutoff",
};

static const char *icmp_redirect_names[] = {
    [0] = "redir-net",
    [1] = "redir-host",
    [2] = "redir-tnet",
    [3] = "redir-thost",
};

static const char *icmp_type_names[] = {
    [0]  = "echo-reply",
    [4]  = "src-quench",
    [8]  = "echo-req",
    [9]  = "rtr-advert",
    [10] = "rtr-solicit",
    [12] = "param-prob",
    [13] = "tstamp-req",
    [14] = "tstamp-rep",
    [15] = "info-req",
    [16] = "info-reply",
    [17] = "mask-req",
    [18] = "mask-reply",
};

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

/*
 * Readable TCP summary: SYN, SYN+ACK, FIN, RST and the payload length
 * for segments carrying data. A plain ACK prints nothing.
 * TCP has no length field: payload = IP total length - IP hdr - TCP hdr.
 */
static void fmt_tcp_info(char *out, size_t n, uint8_t f, long datalen)
{
    size_t len = 0;

    out[0] = '\0';
    if (f & TCP_SYN)
        len += snprintf(out + len, n - len, "%s",
                        (f & TCP_ACK) ? "SYN+ACK" : "SYN");
    if ((f & TCP_FIN) && len < n)
        len += snprintf(out + len, n - len, "%sFIN", len ? " " : "");
    if ((f & TCP_RST) && len < n)
        len += snprintf(out + len, n - len, "%sRST", len ? " " : "");
    if (datalen > 0 && len < n)
        snprintf(out + len, n - len, "%s(%ld)", len ? " " : "", datalen);
}

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_FIXED_LEN   236     /* BOOTP header up to the magic cookie */
#define DHCP_OPT_PAD     0
#define DHCP_OPT_HOST    12
#define DHCP_OPT_MSGTYPE 53
#define DHCP_OPT_END     255

static const char *dhcp_msg_names[] = {
    [1] = "DISCOVER",
    [2] = "OFFER",
    [3] = "REQUEST",
    [4] = "DECLINE",
    [5] = "ACK",
    [6] = "NAK",
    [7] = "RELEASE",
    [8] = "INFORM",
};

/*
 * DHCP summary: message type, then the hostname for client messages or
 * the assigned address for OFFER/ACK. Returns 0 if it's not DHCP.
 */
static int fmt_dhcp(char *out, size_t n, const u_char *d, size_t len)
{
    static const u_char cookie[4] = { 0x63, 0x82, 0x53, 0x63 };
    char host[64] = "", addr[16];
    int type = 0;

    if (len < DHCP_FIXED_LEN + 4 || memcmp(d + DHCP_FIXED_LEN, cookie, 4))
        return 0;

    for (size_t i = DHCP_FIXED_LEN + 4; i < len; ) {
        uint8_t opt = d[i++];
        if (opt == DHCP_OPT_PAD)
            continue;
        if (opt == DHCP_OPT_END || i >= len)
            break;
        uint8_t olen = d[i++];
        if (i + olen > len)
            break;
        if (opt == DHCP_OPT_MSGTYPE && olen >= 1) {
            type = d[i];
        } else if (opt == DHCP_OPT_HOST) {
            size_t k;
            for (k = 0; k < olen && k < sizeof host - 1; k++)
                host[k] = (d[i + k] >= 0x20 && d[i + k] < 0x7f) ? d[i + k] : '?';
            host[k] = '\0';
        }
        i += olen;
    }
    if (!type)
        return 0;   /* plain BOOTP */

    size_t w;
    if (type < (int)NELEM(dhcp_msg_names) && dhcp_msg_names[type])
        w = snprintf(out, n, "%s", dhcp_msg_names[type]);
    else
        w = snprintf(out, n, "type-%d", type);

    if (w < n && (type == 2 || type == 5)) {
        fmt_ip(addr, sizeof addr, d + 16);  /* yiaddr */
        snprintf(out + w, n - w, " %s", addr);
    } else if (w < n && d[0] == 1 && host[0]) {
        snprintf(out + w, n - w, " %s", host);
    }
    return 1;
}

/* ICMP type/code as short text (fits the port columns); unknown ones as "type/code" */
static void fmt_icmp(char *out, size_t n, uint8_t type, uint8_t code)
{
    const char *name = NULL;

    switch (type) {
    case 3:
        if (code < NELEM(icmp_unreach_names))
            name = icmp_unreach_names[code];
        break;
    case 5:
        if (code < NELEM(icmp_redirect_names))
            name = icmp_redirect_names[code];
        break;
    case 11:
        name = code == 0 ? "ttl-exceed" :
               code == 1 ? "reasm-tmout" : NULL;
        break;
    default:
        if (type < NELEM(icmp_type_names))
            name = icmp_type_names[type];
        break;
    }

    if (name)
        snprintf(out, n, "%s", name);
    else
        snprintf(out, n, "%u/%u", type, code);
}

static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
                          const u_char *pkt)
{
    (void)user;

    char vlan[8] = "", smac[18] = "", dmac[18] = "";
    char sip[16] = "", dip[16] = "", proto[16] = "";
    char sport[8] = "", dport[8] = "";
    char icmp[32] = "", info[96] = "";

    size_t caplen = h->caplen;
    if (caplen < ETH_HDR_LEN)
        return;

    fmt_mac(dmac, sizeof dmac, pkt);
    fmt_mac(smac, sizeof smac, pkt + 6);

    size_t off = 12;
    uint16_t etype = rd16(pkt + off);
    off += 2;

    if (etype == ETHERTYPE_8021Q) {
        if (caplen < off + VLAN_TAG_LEN)
            goto out;
        snprintf(vlan, sizeof vlan, "%u", rd16(pkt + off) & 0x0fff);
        etype = rd16(pkt + off + 2);
        off += VLAN_TAG_LEN;
    }

    if (etype <= ETH_MAX_LEN) {
        /* IEEE 802.3 frame: length field, followed by an LLC header */
        const u_char *llc = pkt + off;
        if (caplen < off + LLC_HDR_LEN) {
            strcpy(proto, "LLC");
            goto out;
        }
        if (llc[0] == LLC_SAP_STP) {
            strcpy(proto, "STP");
            goto out;
        }
        if (llc[0] != LLC_SAP_SNAP ||
            caplen < off + LLC_HDR_LEN + SNAP_HDR_LEN) {
            snprintf(proto, sizeof proto, "LLC:%02x", llc[0]);
            goto out;
        }

        const u_char *snap = llc + LLC_HDR_LEN;
        uint32_t oui = ((uint32_t)snap[0] << 16) | (snap[1] << 8) | snap[2];
        uint16_t pid = rd16(snap + 3);
        off += LLC_HDR_LEN + SNAP_HDR_LEN;

        if (oui == OUI_CISCO && pid == CISCO_PID_CDP) {
            strcpy(proto, "CDP");
            goto out;
        }
        if (oui == OUI_CISCO && pid == CISCO_PID_PVST) {
            strcpy(proto, "STP");
            goto out;
        }
        if (oui != OUI_ENCAP && oui != OUI_BRIDGE_TUN) {
            strcpy(proto, "SNAP");
            goto out;
        }
        etype = pid;    /* decode the encapsulated ethertype below */
    }

    if (etype == ETHERTYPE_IPV4) {
        const u_char *ip = pkt + off;
        if (caplen < off + 20 || (ip[0] >> 4) != 4) {
            snprintf(proto, sizeof proto, "0x%04x", etype);
            goto out;
        }
        size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
        uint8_t p = ip[9];
        int frag_off = rd16(ip + 6) & 0x1fff;

        fmt_ip(sip, sizeof sip, ip + 12);
        fmt_ip(dip, sizeof dip, ip + 16);

        switch (p) {
        case IPPROTO_NUM_ICMP: strcpy(proto, "ICMP"); break;
        case IPPROTO_NUM_TCP:  strcpy(proto, "TCP");  break;
        case IPPROTO_NUM_UDP:  strcpy(proto, "UDP");  break;
        default: snprintf(proto, sizeof proto, "%u", p); break;
        }

        /* ports only in the first fragment */
        if ((p == IPPROTO_NUM_TCP || p == IPPROTO_NUM_UDP) &&
            frag_off == 0 && ihl >= 20 && caplen >= off + ihl + 4) {
            const u_char *l4 = ip + ihl;
            snprintf(sport, sizeof sport, "%u", rd16(l4));
            snprintf(dport, sizeof dport, "%u", rd16(l4 + 2));
            if (p == IPPROTO_NUM_TCP && caplen >= off + ihl + 14) {
                long doff = (l4[12] >> 4) * 4;
                long datalen = (long)rd16(ip + 2) - (long)ihl - doff;
                fmt_tcp_info(info, sizeof info, l4[13], datalen);
            }
            /* UDP length field covers the 8-byte header plus payload */
            if (p == IPPROTO_NUM_UDP && caplen >= off + ihl + 6 &&
                rd16(l4 + 4) > 8)
                snprintf(info, sizeof info, "(%u)", rd16(l4 + 4) - 8);

            if (p == IPPROTO_NUM_UDP && caplen >= off + ihl + 8) {
                uint16_t sp = rd16(l4), dp = rd16(l4 + 2);
                size_t avail = caplen - (off + ihl + 8);
                size_t ulen = rd16(l4 + 4) > 8 ? rd16(l4 + 4) - 8u : 0;
                if (ulen < avail)
                    avail = ulen;
                if ((sp == DHCP_SERVER_PORT || sp == DHCP_CLIENT_PORT) &&
                    (dp == DHCP_SERVER_PORT || dp == DHCP_CLIENT_PORT) &&
                    fmt_dhcp(info, sizeof info, l4 + 8, avail))
                    strcpy(proto, "DHCP");
            }
        }
        if (p == IPPROTO_NUM_ICMP && frag_off == 0 && ihl >= 20 &&
            caplen >= off + ihl + 2) {
            const u_char *l4 = ip + ihl;
            fmt_icmp(icmp, sizeof icmp, l4[0], l4[1]);
        }
    } else if (etype == ETHERTYPE_ARP) {
        const u_char *arp = pkt + off;
        strcpy(proto, "ARP");
        /* Ethernet/IPv4 ARP: htype 1, ptype 0x0800, hlen 6, plen 4 */
        if (caplen >= off + 28 && rd16(arp) == 1 &&
            rd16(arp + 2) == ETHERTYPE_IPV4 && arp[4] == 6 && arp[5] == 4) {
            fmt_ip(sip, sizeof sip, arp + 14);
            fmt_ip(dip, sizeof dip, arp + 24);
        }
    } else if (etype == ETHERTYPE_IPV6) {
        strcpy(proto, "IPv6");
    } else {
        snprintf(proto, sizeof proto, "0x%04x", etype);
    }

out:
    printf("%-*s %-*s %-*s  %-*s %-*s %-*s ",
           W_VLAN, vlan, W_MAC, smac, W_MAC, dmac,
           W_IP, sip, W_IP, dip, W_PROTO, proto);
    /* ICMP type replaces the two port columns */
    if (icmp[0])
        printf("%s\n", icmp);
    else if (info[0])
        printf("%*s %*s %s\n", W_PORT, sport, W_PORT, dport, info);
    else
        printf("%*s %*s\n", W_PORT, sport, W_PORT, dport);
}

/*
 * Tell whether an interface is Ethernet without opening it (which would
 * need root), by asking the OS for its hardware type.
 */
#if defined(__linux__)
static int is_ethernet(const char *name)
{
    char path[128];
    int type = -1;

    if (strchr(name, '/'))
        return 0;
    snprintf(path, sizeof path, "/sys/class/net/%s/type", name);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;   /* pseudo devices: any, nflog, dbus-*, ... */
    if (fscanf(f, "%d", &type) != 1)
        type = -1;
    fclose(f);
    return type == 1;   /* ARPHRD_ETHER */
}
#elif defined(__APPLE__)
static int is_ethernet(const char *name)
{
    struct ifaddrs *ifa, *i;
    int ret = 0;

    if (getifaddrs(&ifa) == -1)
        return 1;   /* can't tell, don't hide it */
    for (i = ifa; i; i = i->ifa_next) {
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_LINK &&
            !strcmp(i->ifa_name, name)) {
            uint8_t t = ((struct sockaddr_dl *)i->ifa_addr)->sdl_type;
            ret = (t == IFT_ETHER || t == IFT_BRIDGE);
            break;
        }
    }
    freeifaddrs(ifa);
    return ret;
}
#else
static int is_ethernet(const char *name)
{
    (void)name;
    return 1;
}
#endif

static int list_interfaces(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs, *d;

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    fprintf(stderr, "Available Ethernet interfaces:\n");
    for (d = devs; d; d = d->next) {
        if (!is_ethernet(d->name))
            continue;
        fprintf(stderr, "  %-16s", d->name);
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                char buf[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf);
                fprintf(stderr, " %s", buf);
            }
        }
        if (d->description)
            fprintf(stderr, "  (%s)", d->description);
        fprintf(stderr, "\n");
    }
    pcap_freealldevs(devs);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <interface> [bpf filter expression...]\n"
            "       %s -r <file.pcap> [bpf filter expression...]\n\n",
            prog, prog);
}

/* join argv[from..argc-1] with spaces into a malloc'd string */
static char *join_args(int argc, char **argv, int from)
{
    size_t len = 1;
    for (int i = from; i < argc; i++)
        len += strlen(argv[i]) + 1;

    char *s = malloc(len);
    if (!s)
        return NULL;
    s[0] = '\0';
    for (int i = from; i < argc; i++) {
        if (i > from)
            strcat(s, " ");
        strcat(s, argv[i]);
    }
    return s;
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argv[0]);
        list_interfaces();
        return 1;
    }

    int offline = !strcmp(argv[1], "-r");
    int filter_from = offline ? 3 : 2;
    int rc;

    if (offline && argc < 3) {
        usage(argv[0]);
        return 1;
    }
    const char *dev = offline ? argv[2] : argv[1];

    if (offline) {
        handle = pcap_open_offline(dev, errbuf);   /* "-" reads stdin */
        if (!handle) {
            fprintf(stderr, "%s\n", errbuf);
            return 1;
        }
    } else {
        handle = pcap_create(dev, errbuf);
        if (!handle) {
            fprintf(stderr, "%s: %s\n", dev, errbuf);
            return 1;
        }
        pcap_set_snaplen(handle, SNAPLEN);
        pcap_set_promisc(handle, 1);
        pcap_set_immediate_mode(handle, 1);
        pcap_set_timeout(handle, 100);

        rc = pcap_activate(handle);
        if (rc < 0) {
            fprintf(stderr, "%s: %s\n", dev, pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        } else if (rc > 0) {
            fprintf(stderr, "%s: warning: %s\n", dev, pcap_geterr(handle));
        }
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s: not Ethernet (link type %s)\n",
                dev, pcap_datalink_val_to_name(pcap_datalink(handle)));
        pcap_close(handle);
        return 1;
    }

    if (argc > filter_from) {
        char *expr = join_args(argc, argv, filter_from);
        struct bpf_program fp;
        if (!expr) {
            perror("malloc");
            pcap_close(handle);
            return 1;
        }
        if (pcap_compile(handle, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "filter '%s': %s\n", expr, pcap_geterr(handle));
            free(expr);
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&fp);
        free(expr);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    setvbuf(stdout, NULL, _IOLBF, 0);
    fprintf(stderr, "%s %s\n", offline ? "reading from" : "listening on", dev);
    print_header();

    rc = pcap_loop(handle, -1, handle_packet, NULL);
    if (rc == -1)
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));

    struct pcap_stat st;
    if (!offline && pcap_stats(handle, &st) == 0)
        fprintf(stderr, "\n%u packets received, %u dropped by kernel\n",
                st.ps_recv, st.ps_drop);

    pcap_close(handle);
    return rc == -1 ? 1 : 0;
}
