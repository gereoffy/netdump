/*
 * netdump - minimal tcpdump alternative (libpcap)
 *
 * Usage: netdump [-v] [-s snaplen] [-w out.pcap] <interface> [bpf filter...]
 *        netdump [-v] [-w out.pcap] -r <file.pcap> [bpf filter...]
 *
 * One line per packet, fixed-width columns:
 *   vlan src-mac dst-mac src-ip dst-ip proto sport dport [info]
 *
 * No name resolution: addresses and ports are always numeric.
 * Supports Linux and macOS, Ethernet interfaces, IPv4/IPv6
 * (+ARP, ICMPv6, DHCP, DNS, mDNS, QUIC, RADIUS).
 */

#include <pcap.h>

#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#define SNAPLEN     1600    /* default: whole DHCP packets (options at byte 282) */
#define SNAPLEN_MAX 262144  /* -s 0, like tcpdump */

#define ETH_HDR_LEN   14
#define VLAN_TAG_LEN  4

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_8021Q 0x8100
#define ETHERTYPE_IPV6  0x86dd

#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2

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
static int verbose;     /* -v: extra details (DNS answers, UDP length, ...) */

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

/* copy a protocol string field, replacing non-printable bytes with '?' */
static void copy_printable(char *dst, size_t n, const u_char *src, size_t len)
{
    size_t k;
    for (k = 0; k < len && k < n - 1; k++)
        dst[k] = (src[k] >= 0x20 && src[k] < 0x7f) ? src[k] : '?';
    dst[k] = '\0';
}

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
            copy_printable(host, sizeof host, d + i, olen);
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

/* append printf-style to a string, never overflowing it */
static void append(char *out, size_t n, const char *fmt, ...)
{
    size_t len = strlen(out);
    va_list ap;

    if (len + 1 >= n)
        return;
    va_start(ap, fmt);
    vsnprintf(out + len, n - len, fmt, ap);
    va_end(ap);
}

#define DNS_PORT     53
#define DNS_HDR_LEN  12
#define DNS_MAX_NAME 128    /* longer names are cut, marked with "..." */

#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_SRV   33

static const char *dns_type_name(uint16_t t, char *buf, size_t n)
{
    switch (t) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 64:  return "SVCB";
    case 65:  return "HTTPS";
    case 255: return "ANY";
    }
    snprintf(buf, n, "TYPE%u", t);
    return buf;
}

static const char *dns_rcode_names[] = {
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
};

static const char *dns_opcode_names[] = {
    [1] = "IQUERY", [2] = "STATUS", [4] = "NOTIFY", [5] = "UPDATE",
};

/*
 * Decode a (possibly compressed) domain name at *pos into out. On success
 * *pos is moved past the name at its original position and 1 is returned.
 */
static int dns_name(const u_char *msg, size_t len, size_t *pos,
                    char *out, size_t n)
{
    size_t p = *pos, w = 0, end = 0;
    int jumps = 0, cut = 0;

    for (;;) {
        if (p >= len)
            return 0;
        uint8_t l = msg[p];
        if ((l & 0xc0) == 0xc0) {           /* compression pointer */
            if (p + 1 >= len || ++jumps > 16)
                return 0;
            if (!end)
                end = p + 2;
            p = ((size_t)(l & 0x3f) << 8) | msg[p + 1];
            continue;
        }
        if (l & 0xc0)
            return 0;                       /* reserved label types */
        if (l == 0) {
            p++;
            break;
        }
        if (p + 1 + l > len)
            return 0;
        for (size_t i = 0; i <= l; i++) {
            char c = i == 0 ? '.' : (char)msg[p + i];
            if (i == 0 && w == 0)
                continue;                   /* no leading dot */
            if (c < 0x21 || c > 0x7e)
                c = '?';
            if (w + 4 < n && w < DNS_MAX_NAME)
                out[w++] = c;
            else
                cut = 1;
        }
        p += 1 + l;
    }
    if (w == 0)
        out[w++] = '.';                     /* root */
    out[w] = '\0';
    if (cut)
        snprintf(out + w, n - w, "...");
    *pos = end ? end : p;
    return 1;
}

/*
 * DNS summary: "<qtype> <qname>", plus the rcode for error responses.
 * With -v, successful responses also get "-> <answer>" (first A/AAAA if
 * any, else the first record) and "+N" for the other answer records, or
 * NODATA if there are none.
 * Sets *resp (query/response) and *rc (rcode) for the statistics.
 * Returns 0 if it doesn't look like DNS.
 */
static int fmt_dns(char *out, size_t n, const u_char *d, size_t len,
                   int *resp, unsigned *rc)
{
    char name[DNS_MAX_NAME + 8], val[DNS_MAX_NAME + 8], tbuf[12];

    if (len < DNS_HDR_LEN)
        return 0;
    uint16_t flags = rd16(d + 2);
    uint16_t qd = rd16(d + 4), an = rd16(d + 6);
    int is_resp = flags >> 15;
    unsigned opcode = (flags >> 11) & 0x0f, rcode = flags & 0x0f;
    size_t pos = DNS_HDR_LEN;

    *resp = is_resp;
    *rc = rcode;
    out[0] = '\0';
    if (opcode) {
        if (opcode < NELEM(dns_opcode_names) && dns_opcode_names[opcode])
            append(out, n, "%s ", dns_opcode_names[opcode]);
        else
            append(out, n, "OPCODE%u ", opcode);
    }
    if (qd >= 1) {
        if (!dns_name(d, len, &pos, name, sizeof name) || pos + 4 > len)
            return 0;
        uint16_t qtype = rd16(d + pos);
        pos += 4;
        append(out, n, "%s %s", dns_type_name(qtype, tbuf, sizeof tbuf), name);
        /* skip any further questions (practically never present) */
        for (unsigned i = 1; i < qd; i++) {
            if (!dns_name(d, len, &pos, name, sizeof name) || pos + 4 > len)
                return 1;
            pos += 4;
        }
    }
    if (!is_resp)
        return qd >= 1 || opcode;

    if (rcode) {
        if (rcode < NELEM(dns_rcode_names))
            append(out, n, " %s", dns_rcode_names[rcode]);
        else
            append(out, n, " RCODE%u", rcode);
        return 1;
    }
    if (!verbose)
        return 1;
    if (an == 0) {
        append(out, n, " NODATA");
        return 1;
    }

    /* prefer the first address record (skipping CNAME chains), else the first record */
    size_t first = 0, addr = 0;
    uint16_t ftype = 0, frdlen = 0, atype = 0, ardlen = 0;
    for (unsigned i = 0; i < an; i++) {
        if (!dns_name(d, len, &pos, name, sizeof name) || pos + 10 > len)
            break;
        uint16_t t = rd16(d + pos), rl = rd16(d + pos + 8);
        pos += 10;
        if (pos + rl > len)
            break;
        if (!first) {
            first = pos; ftype = t; frdlen = rl;
        }
        if ((t == DNS_TYPE_A && rl == 4) || (t == DNS_TYPE_AAAA && rl == 16)) {
            addr = pos; atype = t; ardlen = rl;
            break;
        }
        pos += rl;
    }
    if (addr) {
        first = addr; ftype = atype; frdlen = ardlen;
    }
    if (!first)
        return 1;

    if (ftype == DNS_TYPE_A && frdlen == 4) {
        fmt_ip(val, sizeof val, d + first);
        append(out, n, " -> %s", val);
    } else if (ftype == DNS_TYPE_AAAA && frdlen == 16) {
        inet_ntop(AF_INET6, d + first, val, sizeof val);
        append(out, n, " -> %s", val);
    } else if (ftype == DNS_TYPE_CNAME || ftype == DNS_TYPE_PTR ||
               ftype == DNS_TYPE_NS) {
        size_t p2 = first;
        if (!dns_name(d, len, &p2, val, sizeof val))
            return 1;
        append(out, n, " -> %s%s", ftype == DNS_TYPE_CNAME ? "CNAME " : "", val);
    } else if (ftype == DNS_TYPE_MX && frdlen > 2) {
        size_t p2 = first + 2;
        if (!dns_name(d, len, &p2, val, sizeof val))
            return 1;
        append(out, n, " -> %s", val);
    } else if (ftype == DNS_TYPE_SRV && frdlen > 6) {
        size_t p2 = first + 6;
        if (!dns_name(d, len, &p2, val, sizeof val))
            return 1;
        append(out, n, " -> %s:%u", val, rd16(d + first + 4));
    } else {
        append(out, n, " -> %s", dns_type_name(ftype, tbuf, sizeof tbuf));
    }
    if (an > 1)
        append(out, n, " +%u", an - 1);
    return 1;
}

#define MDNS_PORT 5353

/*
 * mDNS: "<qtype> <qname>" (+N more questions) for queries; responses are
 * mostly unsolicited announcements without questions, so show the first
 * answer record: "answer <type> <name>" (+N more). Returns 0 if it doesn't
 * look like DNS; *resp tells query/response for the statistics.
 */
static int fmt_mdns(char *out, size_t n, const u_char *d, size_t len,
                    int *resp)
{
    char name[DNS_MAX_NAME + 8], tbuf[12];
    size_t pos = DNS_HDR_LEN;

    if (len < DNS_HDR_LEN)
        return 0;
    uint16_t qd = rd16(d + 4), an = rd16(d + 6);
    *resp = rd16(d + 2) >> 15;
    out[0] = '\0';

    if (!*resp) {
        if (qd == 0 || !dns_name(d, len, &pos, name, sizeof name) ||
            pos + 4 > len)
            return 0;
        append(out, n, "%s %s", dns_type_name(rd16(d + pos), tbuf, sizeof tbuf),
               name);
        if (qd > 1)
            append(out, n, " +%u", qd - 1);
        return 1;
    }

    for (unsigned i = 0; i < qd; i++) {     /* skip questions, if any */
        if (!dns_name(d, len, &pos, name, sizeof name) || pos + 4 > len)
            return 0;
        pos += 4;
    }
    if (an == 0 || !dns_name(d, len, &pos, name, sizeof name) ||
        pos + 10 > len)
        return 0;
    append(out, n, "answer %s %s", dns_type_name(rd16(d + pos), tbuf, sizeof tbuf),
           name);
    if (an > 1)
        append(out, n, " +%u", an - 1);
    return 1;
}

#define RADIUS_PORT     1812
#define RADIUS_HDR_LEN  20
#define RADIUS_ATTR_USER_NAME 1

static const char *radius_code_names[] = {
    [1]  = "Request",
    [2]  = "Accept",
    [3]  = "Reject",
    [11] = "Challenge",
    [12] = "Status-Server",     /* NAS health check, answered with Accept */
};

/*
 * RADIUS (UDP 1812): packet type and the user name, if the packet has one
 * (requests always, Accept often, depending on the server). Returns 0 if it doesn't look like
 * RADIUS.
 */
static int fmt_radius(char *out, size_t n, const u_char *d, size_t len)
{
    char user[64] = "";

    if (len < RADIUS_HDR_LEN)
        return 0;
    uint8_t code = d[0];
    size_t rlen = rd16(d + 2);
    if (rlen < RADIUS_HDR_LEN || code >= NELEM(radius_code_names) ||
        !radius_code_names[code])
        return 0;
    if (rlen < len)
        len = rlen;

    for (size_t i = RADIUS_HDR_LEN; i + 2 <= len; ) {
        uint8_t type = d[i], alen = d[i + 1];
        if (alen < 2 || i + alen > len)
            break;
        if (type == RADIUS_ATTR_USER_NAME)
            copy_printable(user, sizeof user, d + i + 2, alen - 2);
        i += alen;
    }

    snprintf(out, n, "%s%s%s", radius_code_names[code], user[0] ? " " : "", user);
    return 1;
}

#define QUIC_PORT       443
#define QUIC_FIXED_BIT  0x40
#define QUIC_LONG_HDR   0x80
#define QUIC_V2         0x6b3343cfu

/*
 * QUIC (UDP 443): returns 0 if the fixed bit is not set (then it's
 * something else on port 443). For long header packets out gets the
 * packet type (Initial = connection start, like a TCP SYN); short header
 * (data) packets leave out untouched. The caller shows their UDP payload
 * length: the real QUIC payload is encrypted and its header length can't
 * be known from outside, so that's the best available size.
 */
static int fmt_quic(char *out, size_t n, const u_char *d, size_t len)
{
    static const char *v1_types[] = { "Initial", "0-RTT", "Handshake", "Retry" };
    static const char *v2_types[] = { "Retry", "Initial", "0-RTT", "Handshake" };

    if (len < 1)
        return 0;
    if (!(d[0] & QUIC_LONG_HDR))
        return (d[0] & QUIC_FIXED_BIT) != 0;
    if (len < 5)
        return 0;

    uint32_t ver = ((uint32_t)d[1] << 24) | (d[2] << 16) | (d[3] << 8) | d[4];
    unsigned t = (d[0] >> 4) & 3;
    if (ver == 0) {
        snprintf(out, n, "VersionNeg");     /* fixed bit is unused here */
        return 1;
    }
    if (!(d[0] & QUIC_FIXED_BIT))
        return 0;
    snprintf(out, n, "%s", ver == QUIC_V2 ? v2_types[t] : v1_types[t]);
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

static void fmt_ip_proto(char *out, size_t n, uint8_t p)
{
    switch (p) {
    case IPPROTO_NUM_ICMP: snprintf(out, n, "ICMP"); break;
    case IPPROTO_NUM_TCP:  snprintf(out, n, "TCP");  break;
    case IPPROTO_NUM_UDP:  snprintf(out, n, "UDP");  break;
    default:               snprintf(out, n, "%u", p); break;
    }
}

/*
 * ICMP error details from the quoted original datagram: its protocol and
 * destination (ip[:port]), plus the next-hop MTU for frag-needed and the
 * new gateway for redirects. icmp points to the ICMP header, len is the
 * number of captured bytes from there.
 */
static void fmt_icmp_error(char *out, size_t n, const u_char *icmp, size_t len)
{
    uint8_t type = icmp[0], code = icmp[1];
    char pname[8], addr[16];

    out[0] = '\0';
    if (type != 3 && type != 4 && type != 5 && type != 11 && type != 12)
        return;
    if (len < 8 + 20)
        return;

    const u_char *in = icmp + 8;
    size_t ihl = (size_t)(in[0] & 0x0f) * 4;
    if ((in[0] >> 4) != 4 || ihl < 20)
        return;

    fmt_ip_proto(pname, sizeof pname, in[9]);
    fmt_ip(addr, sizeof addr, in + 16);
    int w = snprintf(out, n, "%s %s", pname, addr);

    int first_frag = (rd16(in + 6) & 0x1fff) == 0;
    if ((in[9] == IPPROTO_NUM_TCP || in[9] == IPPROTO_NUM_UDP) &&
        first_frag && len >= 8 + ihl + 4)
        w += snprintf(out + w, n - w, ":%u", rd16(in + ihl + 2));

    if (type == 3 && code == 4 && rd16(icmp + 6))
        snprintf(out + w, n - w, " mtu=%u", rd16(icmp + 6));
    else if (type == 5) {
        fmt_ip(addr, sizeof addr, icmp + 4);
        snprintf(out + w, n - w, " gw=%s", addr);
    }
}

/*
 * Summary statistics printed on exit. Core counters are always shown for a
 * group with any traffic (a zero there, e.g. no SYN+ACK or no OFFER, is the
 * interesting part); other counters only when non-zero.
 */
#define MAX_COUNTERS 32

struct counter {
    char name[16];
    unsigned long n;
};

struct group {
    const char *title;
    int ncore, used;
    struct counter c[MAX_COUNTERS];
};

static unsigned long st_total;
/* IP-level bytes (from the IP headers, so snaplen doesn't matter) */
static unsigned long long st_bytes_ip, st_bytes_tcp, st_bytes_quic;
/* measurement period: wall clock when live, packet timestamps with -r */
static int st_offline;
static struct timeval st_run_start, st_run_stop, st_first_ts, st_last_ts;
static struct group st_proto = { "protocols", 0, 0, {{"", 0}} };
static struct group st_tcp = { "TCP", 4, 4,
    { {"SYN", 0}, {"SYN+ACK", 0}, {"FIN", 0}, {"RST", 0} } };
static struct group st_arp = { "ARP", 2, 2, { {"request", 0}, {"reply", 0} } };
static struct group st_dhcp = { "DHCP", 4, 4,
    { {"DISCOVER", 0}, {"OFFER", 0}, {"REQUEST", 0}, {"ACK", 0} } };
static struct group st_dns = { "DNS", 2, 2, { {"query", 0}, {"response", 0} } };
static struct group st_mdns = { "mDNS", 2, 2, { {"query", 0}, {"response", 0} } };
static struct group st_radius = { "RADIUS", 3, 3,
    { {"Request", 0}, {"Accept", 0}, {"Reject", 0} } };
static struct group st_quic = { "QUIC", 3, 3,
    { {"client-Initial", 0}, {"server-Initial", 0}, {"Handshake", 0} } };
static struct group st_icmp = { "ICMP", 2, 2,
    { {"echo-req", 0}, {"echo-reply", 0} } };
static struct group st_icmp6 = { "ICMP6", 2, 2, { {"NS", 0}, {"NA", 0} } };

/* count one occurrence of name (up to the first space) in g */
static void count(struct group *g, const char *name)
{
    char key[sizeof g->c[0].name];
    size_t k;

    for (k = 0; name[k] && name[k] != ' ' && k < sizeof key - 1; k++)
        key[k] = name[k];
    key[k] = '\0';

    for (int i = 0; i < g->used; i++) {
        if (!strcmp(g->c[i].name, key)) {
            g->c[i].n++;
            return;
        }
    }
    if (g->used < MAX_COUNTERS) {
        strcpy(g->c[g->used].name, key);
        g->c[g->used++].n = 1;
    }
}

static int cmp_counter_desc(const void *a, const void *b)
{
    unsigned long x = ((const struct counter *)a)->n;
    unsigned long y = ((const struct counter *)b)->n;
    return (x < y) - (x > y);
}

static void print_group(struct group *g, int sort)
{
    unsigned long sum = 0;
    char title[16];

    for (int i = 0; i < g->used; i++)
        sum += g->c[i].n;
    if (!sum)
        return;
    if (sort)
        qsort(g->c, g->used, sizeof g->c[0], cmp_counter_desc);

    snprintf(title, sizeof title, "%s:", g->title);
    fprintf(stderr, "%-11s", title);
    for (int i = 0; i < g->used; i++)
        if (i < g->ncore || g->c[i].n)
            fprintf(stderr, "%s%s %lu", i ? "  " : "", g->c[i].name, g->c[i].n);
    fprintf(stderr, "\n");
}

static double tv_diff(struct timeval a, struct timeval b)
{
    return (a.tv_sec - b.tv_sec) + (a.tv_usec - b.tv_usec) / 1e6;
}

/* 1000-based, e.g. 1.8 GB */
static void fmt_bytes(char *out, size_t n, double b)
{
    static const char *unit[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    size_t u = 0;
    while (b >= 1000 && u < NELEM(unit) - 1) {
        b /= 1000;
        u++;
    }
    snprintf(out, n, u ? "%.1f %s" : "%.0f %s", b, unit[u]);
}

static void print_stats(void)
{
    struct pcap_stat ps;
    struct timeval t0 = st_offline ? st_first_ts : st_run_start;
    struct timeval t1 = st_offline ? st_last_ts : st_run_stop;
    double secs = tv_diff(t1, t0);

    fprintf(stderr, "\n--- %lu packets", st_total);
    if (t0.tv_sec && (st_total || !st_offline)) {
        char a[32], b[32];
        time_t s0 = t0.tv_sec, s1 = t1.tv_sec;
        struct tm tm0, tm1;
        localtime_r(&s0, &tm0);
        localtime_r(&s1, &tm1);
        strftime(a, sizeof a, "%Y-%m-%d %H:%M:%S", &tm0);
        strftime(b, sizeof b, tm0.tm_yday == tm1.tm_yday && tm0.tm_year == tm1.tm_year
                 ? "%H:%M:%S" : "%Y-%m-%d %H:%M:%S", &tm1);
        fprintf(stderr, ", %s - %s (%.1f s)", a, b, secs);
        if (secs > 0)
            fprintf(stderr, ", %.0f pkt/s", st_total / secs);
    }
    if (pcap_stats(handle, &ps) == 0)
        fprintf(stderr, " (kernel: %u received, %u dropped)",
                ps.ps_recv, ps.ps_drop);
    fprintf(stderr, "\n");
    if (st_bytes_ip) {
        char ip[16], tcp[16], quic[16];
        fmt_bytes(ip, sizeof ip, st_bytes_ip);
        fmt_bytes(tcp, sizeof tcp, st_bytes_tcp);
        fmt_bytes(quic, sizeof quic, st_bytes_quic);
        fprintf(stderr, "%-11s" "IP %s", "bytes:", ip);
        if (secs > 0)
            fprintf(stderr, " (%.1f Mbit/s)", st_bytes_ip * 8 / secs / 1e6);
        fprintf(stderr, "  TCP %s (%.0f%%)  QUIC %s (%.0f%%)\n",
                tcp, 100.0 * st_bytes_tcp / st_bytes_ip,
                quic, 100.0 * st_bytes_quic / st_bytes_ip);
    }
    print_group(&st_proto, 1);
    print_group(&st_tcp, 0);
    print_group(&st_arp, 0);
    print_group(&st_dhcp, 0);
    print_group(&st_dns, 0);
    print_group(&st_mdns, 0);
    print_group(&st_radius, 0);
    print_group(&st_quic, 0);
    print_group(&st_icmp, 0);
    print_group(&st_icmp6, 0);
}

/* per-packet output fields and values for the statistics */
struct pkt {
    char vlan[8], smac[18], dmac[18], sip[16], dip[16], proto[16];
    char sport[8], dport[8], info[320], addr6[96];
    char type[32];      /* ICMP/ARP type, shown in place of the ports */
    int v6, tcp_flags, dns_resp, mdns_resp;
    unsigned long iplen;    /* IP packet length from the IP header */
    unsigned dns_rcode;
};

/*
 * TCP/UDP, shared by IPv4 and IPv6. l4 points to the transport header,
 * caplen is the number of captured bytes from there, l4len the transport
 * length according to the IP header.
 */
static void decode_tcp_udp(struct pkt *pk, uint8_t p, const u_char *l4,
                           size_t caplen, long l4len)
{
    if (caplen < 4)
        return;
    snprintf(pk->sport, sizeof pk->sport, "%u", rd16(l4));
    snprintf(pk->dport, sizeof pk->dport, "%u", rd16(l4 + 2));

    if (p == IPPROTO_NUM_TCP) {
        if (caplen >= 14) {
            long datalen = l4len - (l4[12] >> 4) * 4;
            fmt_tcp_info(pk->info, sizeof pk->info, l4[13], datalen);
            pk->tcp_flags = l4[13];
        }
        return;
    }

    /* UDP length field covers the 8-byte header plus payload;
     * mostly noise, so only with -v */
    if (verbose && caplen >= 6 && rd16(l4 + 4) > 8)
        snprintf(pk->info, sizeof pk->info, "(%u)", rd16(l4 + 4) - 8);
    if (caplen < 8)
        return;

    uint16_t sp = rd16(l4), dp = rd16(l4 + 2);
    size_t avail = caplen - 8;
    size_t ulen = rd16(l4 + 4) > 8 ? rd16(l4 + 4) - 8u : 0;
    if (ulen < avail)
        avail = ulen;

    /* decoders may leave partial output when they give up */
    char tmp[sizeof pk->info];
    if ((sp == DHCP_SERVER_PORT || sp == DHCP_CLIENT_PORT) &&
        (dp == DHCP_SERVER_PORT || dp == DHCP_CLIENT_PORT) &&
        fmt_dhcp(tmp, sizeof tmp, l4 + 8, avail)) {
        strcpy(pk->proto, "DHCP");
        strcpy(pk->info, tmp);
    } else if ((sp == DNS_PORT || dp == DNS_PORT) &&
               fmt_dns(tmp, sizeof tmp, l4 + 8, avail,
                       &pk->dns_resp, &pk->dns_rcode)) {
        strcpy(pk->proto, "DNS");
        strcpy(pk->info, tmp);
    } else if ((sp == MDNS_PORT || dp == MDNS_PORT) &&
               fmt_mdns(tmp, sizeof tmp, l4 + 8, avail, &pk->mdns_resp)) {
        strcpy(pk->proto, "mDNS");
        strcpy(pk->info, tmp);
    } else if ((sp == RADIUS_PORT || dp == RADIUS_PORT) &&
               fmt_radius(tmp, sizeof tmp, l4 + 8, avail)) {
        strcpy(pk->proto, "RADIUS");
        strcpy(pk->info, tmp);
    } else if (sp == QUIC_PORT || dp == QUIC_PORT) {
        tmp[0] = '\0';
        if (fmt_quic(tmp, sizeof tmp, l4 + 8, avail)) {
            strcpy(pk->proto, "QUIC");
            if (tmp[0])
                strcpy(pk->info, tmp);
            else if (ulen)  /* data: size shown even without -v */
                snprintf(pk->info, sizeof pk->info, "(%zu)", ulen);
        }
    }
}

static void fmt_ip6(char *out, size_t n, const u_char *p)
{
    if (!inet_ntop(AF_INET6, p, out, n))
        snprintf(out, n, "?");
}

/*
 * IPv6 address shortened to fit the IP column: as is if it fits, else the
 * first two groups, "..", and as many whole groups from the end as fit,
 * e.g. 2001:738:4403:58::1 -> 2001:738..58::1, so both the network and
 * the host part stay recognizable.
 */
static void fmt_ip6_short(char *out, size_t n, const u_char *p)
{
    char s[INET6_ADDRSTRLEN];
    size_t len, head, budget, best;

    fmt_ip6(s, sizeof s, p);
    len = strlen(s);
    if (len <= W_IP) {
        snprintf(out, n, "%s", s);
        return;
    }

    /* embedded IPv4 (e.g. ::ffff:a.b.c.d): the IPv4 part is what matters */
    if (strchr(s, '.')) {
        snprintf(out, n, "%s", strrchr(s, ':') + 1);
        return;
    }

    /* head: up to the second ':' or the "::", whichever comes first */
    const char *dc = strstr(s, "::");
    const char *c1 = strchr(s, ':');
    const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
    head = c2 ? (size_t)(c2 - s) : len;
    if (dc && (size_t)(dc - s) < head)
        head = dc - s;
    budget = W_IP - head - 2;

    /* tail: earliest group boundary (or "::") after head that fits */
    best = len;
    for (size_t i = head + 1; i < len; i++) {
        int boundary = (s[i - 1] == ':' && s[i] != ':') ||
                       (s[i] == ':' && s[i + 1] == ':');
        if (boundary && len - i <= budget) {
            best = i;
            break;
        }
    }
    if (best == len)                /* no tail fits: just cut it */
        snprintf(out, n, "%.*s..", W_IP - 2, s);
    else
        snprintf(out, n, "%.*s..%s", (int)head, s, s + best);
}

#define IPPROTO_NUM_ICMP6    58
#define IP6_HDR_LEN          40
#define IP6_NH_HOPOPTS       0
#define IP6_NH_ROUTING       43
#define IP6_NH_FRAGMENT      44
#define IP6_NH_DSTOPTS       60

/* ICMPv6 type/code as short text, same style (and max 11 chars) as ICMP */
static void fmt_icmp6(char *out, size_t n, uint8_t type, uint8_t code)
{
    static const char *unreach[] = {
        "net-unr", "adm-prohib", "scope-unr", "host-unr", "port-unr",
        "policy-fail", "rej-route",
    };
    const char *name = NULL;

    switch (type) {
    case 1:   name = code < NELEM(unreach) ? unreach[code] : NULL; break;
    case 2:   name = "pkt-too-big"; break;
    case 3:   name = code == 0 ? "ttl-exceed" : code == 1 ? "reasm-tmout" : NULL;
              break;
    case 4:   name = "param-prob"; break;
    case 128: name = "echo-req"; break;
    case 129: name = "echo-reply"; break;
    case 130: name = "mld-query"; break;
    case 131: name = "mld-report"; break;
    case 132: name = "mld-done"; break;
    case 133: name = "RS"; break;
    case 134: name = "RA"; break;
    case 135: name = "NS"; break;
    case 136: name = "NA"; break;
    case 137: name = "redirect"; break;
    case 143: name = "mld2-report"; break;
    }
    if (name)
        snprintf(out, n, "%s", name);
    else
        snprintf(out, n, "%u/%u", type, code);
}

/*
 * ICMPv6 details: the target address for neighbor solicitation and
 * advertisement; for errors the quoted packet's protocol and destination
 * ([ip]:port), plus the MTU for pkt-too-big; the new gateway for redirects.
 */
static void fmt_icmp6_info(char *out, size_t n, const u_char *icmp, size_t len)
{
    uint8_t type = icmp[0];
    char addr[INET6_ADDRSTRLEN], pname[8];

    out[0] = '\0';
    if ((type == 135 || type == 136) && len >= 24) {
        fmt_ip6(addr, sizeof addr, icmp + 8);
        snprintf(out, n, "%s", addr);
    } else if (type == 137 && len >= 24) {
        fmt_ip6(addr, sizeof addr, icmp + 8);
        snprintf(out, n, "gw=%s", addr);
    } else if (type >= 1 && type <= 4 && len >= 8 + IP6_HDR_LEN) {
        const u_char *in = icmp + 8;
        if ((in[0] >> 4) != 6)
            return;
        fmt_ip_proto(pname, sizeof pname, in[6]);
        fmt_ip6(addr, sizeof addr, in + 24);
        if ((in[6] == IPPROTO_NUM_TCP || in[6] == IPPROTO_NUM_UDP) &&
            len >= 8 + IP6_HDR_LEN + 4)
            append(out, n, "%s [%s]:%u", pname, addr,
                   rd16(in + IP6_HDR_LEN + 2));
        else
            append(out, n, "%s %s", pname, addr);
        if (type == 2)
            append(out, n, " mtu=%u", (unsigned)(((uint32_t)icmp[4] << 24) |
                   (icmp[5] << 16) | (icmp[6] << 8) | icmp[7]));
    }
}

static void decode_ipv6(struct pkt *pk, const u_char *ip6, size_t caplen)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

    if (caplen < IP6_HDR_LEN || (ip6[0] >> 4) != 6) {
        strcpy(pk->proto, "IPv6");
        return;
    }
    pk->v6 = 1;
    pk->iplen = rd16(ip6 + 4) + IP6_HDR_LEN;
    strcpy(pk->proto, "IPv6");      /* until a known transport is found */
    fmt_ip6_short(pk->sip, sizeof pk->sip, ip6 + 8);
    fmt_ip6_short(pk->dip, sizeof pk->dip, ip6 + 24);
    if (verbose) {                  /* full addresses at the end of the line */
        fmt_ip6(src, sizeof src, ip6 + 8);
        fmt_ip6(dst, sizeof dst, ip6 + 24);
        snprintf(pk->addr6, sizeof pk->addr6, "[%s > %s]", src, dst);
    }

    /* walk the extension headers that may precede the transport header */
    uint8_t nh = ip6[6];
    size_t pos = IP6_HDR_LEN;
    int first_frag = 1;
    for (int i = 0; i < 8; i++) {
        if (nh == IP6_NH_HOPOPTS || nh == IP6_NH_ROUTING ||
            nh == IP6_NH_DSTOPTS) {
            if (caplen < pos + 2)
                return;
            nh = ip6[pos];
            pos += (ip6[pos + 1] + 1) * 8;
        } else if (nh == IP6_NH_FRAGMENT) {
            if (caplen < pos + 8)
                return;
            first_frag = (rd16(ip6 + pos + 2) & 0xfff8) == 0;
            nh = ip6[pos];
            pos += 8;
        } else {
            break;
        }
    }
    long l4len = (long)rd16(ip6 + 4) - (long)(pos - IP6_HDR_LEN);

    if (nh == IPPROTO_NUM_ICMP6) {
        strcpy(pk->proto, "ICMP");
        if (first_frag && caplen >= pos + 2) {
            fmt_icmp6(pk->type, sizeof pk->type, ip6[pos], ip6[pos + 1]);
            fmt_icmp6_info(pk->info, sizeof pk->info, ip6 + pos, caplen - pos);
        }
    } else if (nh == IPPROTO_NUM_TCP || nh == IPPROTO_NUM_UDP) {
        fmt_ip_proto(pk->proto, sizeof pk->proto, nh);
        if (first_frag && caplen > pos)
            decode_tcp_udp(pk, nh, ip6 + pos, caplen - pos, l4len);
    } else {
        snprintf(pk->info, sizeof pk->info, "next=%u", nh);
    }
}

static void count_stats(const struct pkt *pk, const char *label,
                        struct timeval ts)
{
    if (!st_total)
        st_first_ts = ts;
    st_last_ts = ts;
    st_total++;
    st_bytes_ip += pk->iplen;
    if (!strcmp(pk->proto, "TCP"))
        st_bytes_tcp += pk->iplen;
    else if (!strcmp(pk->proto, "QUIC"))
        st_bytes_quic += pk->iplen;
    count(&st_proto, label[0] ? label : "truncated");
    if (pk->tcp_flags >= 0) {
        if ((pk->tcp_flags & TCP_SYN) && (pk->tcp_flags & TCP_ACK))
            count(&st_tcp, "SYN+ACK");
        else if (pk->tcp_flags & TCP_SYN)
            count(&st_tcp, "SYN");
        if (pk->tcp_flags & TCP_FIN)
            count(&st_tcp, "FIN");
        if (pk->tcp_flags & TCP_RST)
            count(&st_tcp, "RST");
    }
    if (!strcmp(pk->proto, "ARP") && pk->type[0])
        count(&st_arp, pk->type);
    if (!strcmp(pk->proto, "DHCP"))
        count(&st_dhcp, pk->info);
    if (!strcmp(pk->proto, "DNS")) {
        count(&st_dns, pk->dns_resp ? "response" : "query");
        if (pk->dns_resp && pk->dns_rcode) {
            if (pk->dns_rcode < NELEM(dns_rcode_names))
                count(&st_dns, dns_rcode_names[pk->dns_rcode]);
            else
                count(&st_dns, "RCODE?");
        }
    }
    if (!strcmp(pk->proto, "RADIUS"))
        count(&st_radius, pk->info);
    if (!strcmp(pk->proto, "mDNS"))
        count(&st_mdns, pk->mdns_resp ? "response" : "query");
    if (!strcmp(pk->proto, "QUIC") && pk->info[0] && pk->info[0] != '(') {
        /* client -> server:443 Initial vs. the server's answer */
        if (!strcmp(pk->info, "Initial"))
            count(&st_quic, strcmp(pk->dport, "443") ? "server-Initial"
                                                     : "client-Initial");
        else
            count(&st_quic, pk->info);
    }
    if (!strcmp(pk->proto, "ICMP") && pk->type[0])
        count(pk->v6 ? &st_icmp6 : &st_icmp, pk->type);
}

static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
                          const u_char *pkt)
{
    /* -w: save the packet as captured, besides printing it */
    if (user)
        pcap_dump(user, h, pkt);

    struct pkt pk;
    memset(&pk, 0, sizeof pk);
    pk.tcp_flags = -1;
    pk.dns_resp = -1;

    size_t caplen = h->caplen;
    if (caplen < ETH_HDR_LEN)
        return;

    fmt_mac(pk.dmac, sizeof pk.dmac, pkt);
    fmt_mac(pk.smac, sizeof pk.smac, pkt + 6);

    size_t off = 12;
    uint16_t etype = rd16(pkt + off);
    off += 2;

    if (etype == ETHERTYPE_8021Q) {
        if (caplen < off + VLAN_TAG_LEN)
            goto out;
        snprintf(pk.vlan, sizeof pk.vlan, "%u", rd16(pkt + off) & 0x0fff);
        etype = rd16(pkt + off + 2);
        off += VLAN_TAG_LEN;
    }

    if (etype <= ETH_MAX_LEN) {
        /* IEEE 802.3 frame: length field, followed by an LLC header */
        const u_char *llc = pkt + off;
        if (caplen < off + LLC_HDR_LEN) {
            strcpy(pk.proto, "LLC");
            goto out;
        }
        if (llc[0] == LLC_SAP_STP) {
            strcpy(pk.proto, "STP");
            goto out;
        }
        if (llc[0] != LLC_SAP_SNAP ||
            caplen < off + LLC_HDR_LEN + SNAP_HDR_LEN) {
            snprintf(pk.proto, sizeof pk.proto, "LLC:%02x", llc[0]);
            goto out;
        }

        const u_char *snap = llc + LLC_HDR_LEN;
        uint32_t oui = ((uint32_t)snap[0] << 16) | (snap[1] << 8) | snap[2];
        uint16_t pid = rd16(snap + 3);
        off += LLC_HDR_LEN + SNAP_HDR_LEN;

        if (oui == OUI_CISCO && pid == CISCO_PID_CDP) {
            strcpy(pk.proto, "CDP");
            goto out;
        }
        if (oui == OUI_CISCO && pid == CISCO_PID_PVST) {
            strcpy(pk.proto, "STP");
            goto out;
        }
        if (oui != OUI_ENCAP && oui != OUI_BRIDGE_TUN) {
            strcpy(pk.proto, "SNAP");
            goto out;
        }
        etype = pid;    /* decode the encapsulated ethertype below */
    }

    if (etype == ETHERTYPE_IPV4) {
        const u_char *ip = pkt + off;
        if (caplen < off + 20 || (ip[0] >> 4) != 4) {
            snprintf(pk.proto, sizeof pk.proto, "0x%04x", etype);
            goto out;
        }
        size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
        uint8_t p = ip[9];
        int frag_off = rd16(ip + 6) & 0x1fff;

        pk.iplen = rd16(ip + 2);
        fmt_ip(pk.sip, sizeof pk.sip, ip + 12);
        fmt_ip(pk.dip, sizeof pk.dip, ip + 16);
        fmt_ip_proto(pk.proto, sizeof pk.proto, p);

        /* transport details only in the first fragment */
        if (frag_off == 0 && ihl >= 20 && caplen > off + ihl) {
            const u_char *l4 = ip + ihl;
            size_t l4cap = caplen - (off + ihl);
            if (p == IPPROTO_NUM_TCP || p == IPPROTO_NUM_UDP)
                decode_tcp_udp(&pk, p, l4, l4cap,
                               (long)rd16(ip + 2) - (long)ihl);
            if (p == IPPROTO_NUM_ICMP && l4cap >= 2) {
                fmt_icmp(pk.type, sizeof pk.type, l4[0], l4[1]);
                fmt_icmp_error(pk.info, sizeof pk.info, l4, l4cap);
            }
        }
    } else if (etype == ETHERTYPE_ARP) {
        const u_char *arp = pkt + off;
        strcpy(pk.proto, "ARP");
        /* Ethernet/IPv4 ARP: htype 1, ptype 0x0800, hlen 6, plen 4 */
        if (caplen >= off + 28 && rd16(arp) == 1 &&
            rd16(arp + 2) == ETHERTYPE_IPV4 && arp[4] == 6 && arp[5] == 4) {
            const u_char *spa = arp + 14, *tpa = arp + 24;
            uint16_t op = rd16(arp + 6);
            fmt_ip(pk.sip, sizeof pk.sip, spa);
            fmt_ip(pk.dip, sizeof pk.dip, tpa);
            if (op == ARP_OP_REQUEST && !(spa[0] | spa[1] | spa[2] | spa[3]))
                strcpy(pk.type, "probe");      /* RFC 5227 address check */
            else if (!memcmp(spa, tpa, 4))
                strcpy(pk.type, "announce");   /* gratuitous ARP */
            else if (op == ARP_OP_REQUEST)
                strcpy(pk.type, "request");
            else if (op == ARP_OP_REPLY)
                strcpy(pk.type, "reply");
            else
                snprintf(pk.type, sizeof pk.type, "op-%u", op);
        }
    } else if (etype == ETHERTYPE_IPV6) {
        decode_ipv6(&pk, pkt + off, caplen - off);
    } else {
        snprintf(pk.proto, sizeof pk.proto, "0x%04x", etype);
    }

out:;
    /* IPv6 variants get a "6" suffix: TCP6, DNS6, ICMP6, ... */
    char label[sizeof pk.proto + 1];
    snprintf(label, sizeof label, "%s%s", pk.proto,
             pk.v6 && strcmp(pk.proto, "IPv6") ? "6" : "");
    count_stats(&pk, label, h->ts);

    printf("%-*s %-*s %-*s  %-*s %-*s %-*s ",
           W_VLAN, pk.vlan, W_MAC, pk.smac, W_MAC, pk.dmac,
           W_IP, pk.sip, W_IP, pk.dip, W_PROTO, label);
    /* ICMP/ARP type replaces the two port columns */
    if (pk.type[0])
        printf(pk.info[0] || pk.addr6[0] ? "%-*s" : "%.*s%s",
               2 * W_PORT + 1, pk.type, "");
    else
        printf("%*s %*s", W_PORT, pk.sport, W_PORT, pk.dport);
    if (pk.info[0])
        printf(" %s", pk.info);
    if (pk.addr6[0])
        printf(" %s", pk.addr6);
    printf("\n");
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
            "Usage: %s [-v] [-s snaplen] [-w out.pcap] <interface> [bpf filter...]\n"
            "       %s [-v] [-w out.pcap] -r <file.pcap> [bpf filter...]\n"
            "\n"
            "  -r file  read packets from a pcap file ('-' for stdin)\n"
            "  -w file  also save the packets to a pcap file (output continues)\n"
            "  -s len   capture length in bytes (default %d, 0 = whole packet)\n"
            "  -v       verbose: extra details (DNS answers, UDP payload length,\n"
            "           full IPv6 addresses)\n\n",
            prog, prog, SNAPLEN);
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

    const char *dev = NULL, *wfile = NULL;
    int offline = 0, snaplen = SNAPLEN, rc, i;
    pcap_dumper_t *dumper = NULL;

    /* options first, then the interface (unless -r), then the filter */
    for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        if (!strcmp(argv[i], "--")) {
            i++;
            break;
        } else if (!strcmp(argv[i], "-v")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            offline = 1;
            dev = argv[++i];
        } else if (!strcmp(argv[i], "-w") && i + 1 < argc) {
            wfile = argv[++i];
            if (!strcmp(wfile, "-")) {
                fprintf(stderr, "-w -: writing to stdout would mix with the output\n");
                return 1;
            }
        } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
            char *end;
            long v = strtol(argv[++i], &end, 10);
            if (*end || v < 0 || v > SNAPLEN_MAX) {
                fprintf(stderr, "-s: invalid capture length '%s'\n", argv[i]);
                return 1;
            }
            snaplen = v ? (int)v : SNAPLEN_MAX;
        } else {
            usage(argv[0]);
            if (strcmp(argv[i], "-h") && strcmp(argv[i], "--help"))
                return 1;
            list_interfaces();
            return 1;
        }
    }
    if (!offline) {
        if (i >= argc) {
            usage(argv[0]);
            list_interfaces();
            return 1;
        }
        dev = argv[i++];
    }
    int filter_from = i;

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
        pcap_set_snaplen(handle, snaplen);
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

    if (wfile) {
        dumper = pcap_dump_open(handle, wfile);
        if (!dumper) {
            fprintf(stderr, "%s\n", pcap_geterr(handle));  /* names the file */
            pcap_close(handle);
            return 1;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    setvbuf(stdout, NULL, _IOLBF, 0);
    fprintf(stderr, "%s %s", offline ? "reading from" : "listening on", dev);
    if (wfile)
        fprintf(stderr, ", saving to %s", wfile);
    fprintf(stderr, "\n");
    print_header();
    st_offline = offline;
    gettimeofday(&st_run_start, NULL);

    rc = pcap_loop(handle, -1, handle_packet, (u_char *)dumper);
    if (rc == -1)
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));

    gettimeofday(&st_run_stop, NULL);
    print_stats();

    if (dumper)
        pcap_dump_close(dumper);
    pcap_close(handle);
    return rc == -1 ? 1 : 0;
}
