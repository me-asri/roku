#define _DEFAULT_SOURCE

#include "icmp.h"

#include <stddef.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "checksum.h"
#include "trans.h"
#include "log.h"
#include "addr.h"

/* Maximum ICMP error data length so total packet size doesn't exceed min IPv4 MTU */
#define ICMP_ERROR_LENGTH_MAX 548
/* Maximum ICMPv6 error data length so total packet size doesn't exceed min IPv6 MTU */
#define ICMP6_ERROR_LENGTH_MAX 1232

static ssize_t icmp_error_4to6(int tunfd, int tun_mtu, const struct iphdr* iphdr,
    const struct icmphdr* icmphdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);
static ssize_t icmp_echo_4to6(int tunfd, const struct iphdr* iphdr,
    const struct icmphdr* icmphdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);
static ssize_t icmp_error_6to4(int tunfd, int tun_mtu, const struct ip6_hdr* ip6hdr,
    const struct icmp6_hdr* icmp6hdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);
static ssize_t icmp_echo_6to4(int tunfd, const struct ip6_hdr* ip6hdr,
    const struct icmp6_hdr* icmp6hdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);

/* Estimate path MTU using algorithm from RFC1191 */
static int pmtu_estimate(size_t packet_len);

ssize_t icmp_send_error(int tunfd, int type, int code, in_addr_t src, in_addr_t dst,
    char* payload, size_t payload_len, int data)
{
    struct iovec iov[2];
    struct
    {
        struct iphdr ip;
        struct icmphdr icmp;
    } header;

    ssize_t written;

    if (payload_len < sizeof(struct iphdr)) {
        log_e("%s - Invalid payload length for ICMP error", addr_str_v4(dst));
        return -1;
    }

    if (payload_len > ICMP_ERROR_LENGTH_MAX) {
        payload_len = ICMP_ERROR_LENGTH_MAX;
    }

    header.ip.version = 4;
    header.ip.ihl = 5;
    header.ip.saddr = src;
    header.ip.daddr = dst;
    header.ip.frag_off = 0;
    header.ip.id = 0;
    header.ip.protocol = IPPROTO_ICMP;
    header.ip.tos = 0;
    header.ip.ttl = 64;
    header.ip.tot_len = htons(sizeof(header) + payload_len);
    header.ip.check = 0;
    header.ip.check = ip_checksum(&header.ip, sizeof(struct iphdr));

    header.icmp.type = type;
    header.icmp.code = code;
    header.icmp.un.gateway = htonl(data);
    header.icmp.checksum = 0;
    header.icmp.checksum = ip_checksum_add(
        ip_checksum(&header.icmp, sizeof(struct icmphdr)),
        ip_checksum(payload, payload_len));

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = payload;
    iov[1].iov_len = payload_len;

    written = writev(tunfd, iov, sizeof(iov) / sizeof(iov[0]));
    if (written < 0) {
        elog_e("%s - Failed to write packet to TUN interface", addr_str_v4(dst));
    } else {
        log_d("%s - ICMP error - Len: %zd", addr_str_v4(dst), written);
    }
    return written;
}

ssize_t icmp6_send_error(int tunfd, int type, int code, struct in6_addr* src, struct in6_addr* dst,
    char* payload, size_t payload_len, int data)
{
    struct iovec iov[2];
    struct
    {
        struct ip6_hdr ip6;
        struct icmp6_hdr icmp6;
    } header;

    ssize_t written;

    if (payload_len < sizeof(struct ip6_hdr)) {
        log_e("%s - Invalid payload length for ICMPv6 error", addr_str_v6(dst));
        return -1;
    }

    if (payload_len > ICMP6_ERROR_LENGTH_MAX) {
        payload_len = ICMP6_ERROR_LENGTH_MAX;
    }

    header.ip6.ip6_vfc = htonl(0x6 << 28);
    header.ip6.ip6_plen = htons(sizeof(header.icmp6) + payload_len);
    header.ip6.ip6_nxt = IPPROTO_ICMPV6;
    header.ip6.ip6_hops = 64;
    header.ip6.ip6_src = *src;
    header.ip6.ip6_dst = *dst;

    header.icmp6.icmp6_type = type;
    header.icmp6.icmp6_code = code;
    header.icmp6.icmp6_dataun.icmp6_un_data32[0] = htonl(data);
    header.icmp6.icmp6_cksum = 0;
    header.icmp6.icmp6_cksum = ip_checksum_add(
        ip6_ph_checksum(&header.ip6, sizeof(header.icmp6) + payload_len, IPPROTO_ICMPV6),
        ip_checksum(&header.icmp6, sizeof(header.icmp6)));
    header.icmp6.icmp6_cksum = ip_checksum_add(
        header.icmp6.icmp6_cksum,
        ip_checksum(payload, payload_len));

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = payload;
    iov[1].iov_len = payload_len;

    written = writev(tunfd, iov, sizeof(iov) / sizeof(iov[0]));
    if (written < 0) {
        elog_e("%s - Failed to write packet to TUN interface", addr_str_v6(dst));
    } else {
        log_d("%s - ICMPv6 error - Len: %zd", addr_str_v6(dst), written);
    }
    return written;
}

ssize_t icmp_write_4to6(int tunfd, int tun_mtu, const struct iphdr* iphdr,
    char* payload, size_t payload_len,
    struct in6_addr* src_prefix, struct in6_addr* dst_prefix)
{
    struct icmphdr* icmphdr = (struct icmphdr*)payload;
    char* data = payload + sizeof(struct icmphdr);
    size_t data_len = payload_len - sizeof(struct icmphdr);

    if (icmphdr->type == ICMP_ECHOREPLY || icmphdr->type == ICMP_ECHO) {
        return icmp_echo_4to6(tunfd, iphdr, icmphdr, data, data_len, src_prefix, dst_prefix);
    } else {
        return icmp_error_4to6(tunfd, tun_mtu, iphdr, icmphdr, data, data_len, src_prefix, dst_prefix);
    }
}

ssize_t icmp_write_6to4(int tunfd, int tun_mtu, const struct ip6_hdr* ip6hdr,
    char* payload, size_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct icmp6_hdr* icmp6hdr = (struct icmp6_hdr*)payload;
    char* data = payload + sizeof(struct icmp6_hdr);
    size_t data_len = payload_len - sizeof(struct icmp6_hdr);

    if (icmp6hdr->icmp6_type == ICMP6_ECHO_REQUEST || icmp6hdr->icmp6_type == ICMP6_ECHO_REPLY) {
        return icmp_echo_6to4(tunfd, ip6hdr, icmp6hdr, data, data_len,
            src_prefix, dst_prefix);
    } else {
        return icmp_error_6to4(tunfd, tun_mtu, ip6hdr, icmp6hdr, data, data_len,
            src_prefix, dst_prefix);
    }
}

ssize_t icmp_error_4to6(int tunfd, int tun_mtu, const struct iphdr* iphdr,
    const struct icmphdr* icmphdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct iovec iov[2];
    struct
    {
        struct ip6_hdr ip6;
        struct
        {
            struct icmp6_hdr hdr;
            struct ip6_hdr inner_ip6;
        } icmp6;
    } header;

    struct iphdr* inner_iphdr;
    size_t inner_iphdr_len;
    char* inner_payload;
    size_t inner_payload_len;

    ssize_t written;

    if (data_len < sizeof(struct iphdr)) {
        log_w("%s - Invalid data length for ICMP error", addr_str_v4(iphdr->saddr));
        return 0;
    }

    switch (icmphdr->type) {
    case ICMP_DEST_UNREACH:
        header.icmp6.hdr.icmp6_type = ICMP6_DST_UNREACH;
        header.icmp6.hdr.icmp6_dataun.icmp6_un_data32[0] = 0;

        switch (icmphdr->code) {
        case ICMP_UNREACH_NET:
        case ICMP_HOST_UNREACH:
        case ICMP_UNREACH_SRCFAIL:
        case ICMP_NET_UNKNOWN:
        case ICMP_HOST_UNKNOWN:
        case ICMP_HOST_ISOLATED:
        case ICMP_NET_UNR_TOS:
        case ICMP_HOST_UNR_TOS:
            header.icmp6.hdr.icmp6_code = 0;
            break;
        case ICMP_PROT_UNREACH:
            header.icmp6.hdr.icmp6_type = ICMP6_PARAM_PROB;
            header.icmp6.hdr.icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;
            header.icmp6.hdr.icmp6_pptr = htons(IP6_POINTER_NXT);

            break;
        case ICMP_PORT_UNREACH:
            header.icmp6.hdr.icmp6_code = ICMP6_DST_UNREACH_NOPORT;
            break;
        case ICMP_FRAG_NEEDED: {
            int mtu = htons(icmphdr->un.frag.mtu);
            header.icmp6.hdr.icmp6_type = ICMP6_PACKET_TOO_BIG;
            header.icmp6.hdr.icmp6_code = 0;
            if (mtu < IF_MIN_MTU) {
                mtu = pmtu_estimate(ntohs(iphdr->tot_len));
            }
            if (mtu < IF_MIN_MTU_V6) {
                mtu = IF_MIN_MTU_V6;
            }
            mtu += MTU_DIFF;
            header.icmp6.hdr.icmp6_mtu = htonl(mtu);

            break;
        }
        case ICMP_UNREACH_NET_PROHIB:
        case ICMP_UNREACH_HOST_PROHIB:
        case ICMP_UNREACH_FILTER_PROHIB:
        case ICMP_UNREACH_PRECEDENCE_CUTOFF:
            header.icmp6.hdr.icmp6_code = ICMP6_DST_UNREACH_ADMIN;
            break;
        default:
            return 0;
        }

        break;
    case ICMP_TIME_EXCEEDED:
        header.icmp6.hdr.icmp6_type = ICMP6_TIME_EXCEEDED;
        header.icmp6.hdr.icmp6_code = icmphdr->code;
        header.icmp6.hdr.icmp6_dataun.icmp6_un_data32[0] = 0;

        break;
    case ICMP_PARAMPROB:
        header.icmp6.hdr.icmp6_type = ICMP6_PARAM_PROB;
        switch (icmphdr->code) {
        case ICMP_PARAMPROB_OPTABSENT:
            return 0;
        case ICMP_PARAMPROB_PTRERR:
        case ICMP_PARAMPROB_BADLEN: /* TODO */
            log_w("%s - ICMP_PARAMPROB not implemented yet", addr_str_v4(iphdr->saddr));
            return 0;
        default:
            return 0;
        }

        break;
    default:
        return 0;
    }

    inner_iphdr = (struct iphdr*)data;
    inner_iphdr_len = inner_iphdr->ihl * 4;
    if (inner_iphdr_len > data_len) {
        log_w("%s - Invalid ICMP error inner IP header length", addr_str_v4(iphdr->saddr));
        return 0;
    }

    inner_payload = data + inner_iphdr_len;
    inner_payload_len = data_len - inner_iphdr_len;
    if (inner_payload_len > ICMP6_ERROR_LENGTH_MAX - sizeof(struct ip6_hdr)) {
        inner_payload_len = ICMP6_ERROR_LENGTH_MAX - sizeof(struct ip6_hdr);
    }

    /* Translate IP header of the ICMP packet itself */
    trans_header_4to6(iphdr, &header.ip6, sizeof(header.icmp6) + inner_payload_len,
        src_prefix, dst_prefix, true);

    /* Translate IP header of the embedded packet */
    trans_header_4to6(inner_iphdr, &header.icmp6.inner_ip6,
        ntohs(inner_iphdr->tot_len) - inner_iphdr_len, src_prefix, dst_prefix, false);
    if (trans_payload_4to6(inner_iphdr, &header.icmp6.inner_ip6, inner_payload, inner_payload_len) != 0) {
        log_d("%s - Failed to translate ICMP error inner IP payload, dropping packet",
            addr_str_v4(iphdr->saddr));
        return 0;
    }

    header.icmp6.hdr.icmp6_cksum = 0;
    header.icmp6.hdr.icmp6_cksum = ip_checksum_add(
        ip6_ph_checksum(&header.ip6, sizeof(header.icmp6) + inner_payload_len, IPPROTO_ICMPV6),
        ip_checksum(&header.icmp6, sizeof(header.icmp6)));
    header.icmp6.hdr.icmp6_cksum = ip_checksum_add(
        header.icmp6.hdr.icmp6_cksum,
        ip_checksum(inner_payload, inner_payload_len));

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = inner_payload;
    iov[1].iov_len = inner_payload_len;

    written = writev(tunfd, iov, sizeof(iov) / sizeof(iov[0]));
    if (written < 0) {
        elog_e("%s - Failed to write packet to TUN interface", addr_str_v4(iphdr->saddr));
    } else {
        log_d("%s - IPv4->IPv6 (ICMP error) - Len: %zd", addr_str_v4(iphdr->saddr), written);
    }
    return written;
}

ssize_t icmp_echo_4to6(int tunfd, const struct iphdr* iphdr, const struct icmphdr* icmphdr,
    char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct iovec iov[2];
    struct
    {
        struct ip6_hdr ip6;
        struct icmp6_hdr icmp6;
    } header;

    ssize_t written;

    switch (icmphdr->type) {
    case ICMP_ECHOREPLY:
        header.icmp6.icmp6_type = ICMP6_ECHO_REPLY;
        header.icmp6.icmp6_code = 0;
        header.icmp6.icmp6_id = icmphdr->un.echo.id;
        header.icmp6.icmp6_seq = icmphdr->un.echo.sequence;

        break;
    case ICMP_ECHO:
        header.icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
        header.icmp6.icmp6_code = 0;
        header.icmp6.icmp6_id = icmphdr->un.echo.id;
        header.icmp6.icmp6_seq = icmphdr->un.echo.sequence;

        break;
    default:
        return 0;
    }

    /* Translate IP header */
    trans_header_4to6(iphdr, &header.ip6, data_len + sizeof(struct icmp6_hdr),
        src_prefix, dst_prefix, true);

    header.icmp6.icmp6_cksum = 0;
    header.icmp6.icmp6_cksum = ip_checksum_add(
        ip6_ph_checksum(&header.ip6, sizeof(header.icmp6) + data_len, IPPROTO_ICMPV6),
        ip_checksum(&header.icmp6, sizeof(header.icmp6)));
    header.icmp6.icmp6_cksum = ip_checksum_add(
        header.icmp6.icmp6_cksum,
        ip_checksum(data, data_len));

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = data;
    iov[1].iov_len = data_len;

    written = writev(tunfd, iov, sizeof(iov) / sizeof(iov[0]));
    if (written < 0) {
        elog_e("%s - Failed to write packet to TUN interface", addr_str_v4(iphdr->saddr));
    } else {
        log_d("%s - IPv4->IPv6 (ICMP echo) - Len: %zd", addr_str_v4(iphdr->saddr), written);
    }
    return written;
}

ssize_t icmp_error_6to4(int tunfd, int tun_mtu, const struct ip6_hdr* ip6hdr,
    const struct icmp6_hdr* icmp6hdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct iovec iov[2];
    struct
    {
        struct iphdr ip;
        struct
        {
            struct icmphdr hdr;
            struct iphdr inner_ip;
        } icmp;
    } header;

    struct ip6_hdr* inner_ip6hdr;
    char* inner_payload;
    size_t inner_payload_len;
    uint16_t inner_ip6hdr_plen;
    struct ip6_frag* inner_frag;

    ssize_t written;

    int mtu;

    if (data_len < sizeof(struct ip6_hdr)) {
        return 0; /* Invalid length */
    }

    switch (icmp6hdr->icmp6_type) {
    case ICMP6_DST_UNREACH:
        header.icmp.hdr.type = ICMP_DEST_UNREACH;
        header.icmp.hdr.un.gateway = 0; /* Set unused to 0 */
        switch (icmp6hdr->icmp6_code) {
        case ICMP6_DST_UNREACH_NOROUTE:
        case ICMP6_DST_UNREACH_BEYONDSCOPE:
            header.icmp.hdr.code = ICMP_DEST_UNREACH;
            break;
        case ICMP6_DST_UNREACH_ADMIN:
            header.icmp.hdr.code = ICMP_UNREACH_HOST_PROHIB;
            break;
        case ICMP6_DST_UNREACH_NOPORT:
            header.icmp.hdr.code = ICMP_PORT_UNREACH;
            break;
        default:
            return 0;
        }

        break;
    case ICMP6_PACKET_TOO_BIG: {
        mtu = ntohl(icmp6hdr->icmp6_mtu);
        header.icmp.hdr.type = ICMP_DEST_UNREACH;
        header.icmp.hdr.code = ICMP_FRAG_NEEDED;
        if (mtu > tun_mtu) {
            mtu = tun_mtu;
        }
        mtu -= MTU_DIFF;
        header.icmp.hdr.un.frag.mtu = htons(mtu);

        break;
    }
    case ICMP6_TIME_EXCEEDED:
        header.icmp.hdr.type = ICMP_TIME_EXCEEDED;
        header.icmp.hdr.code = icmp6hdr->icmp6_code;
        header.icmp.hdr.un.gateway = 0;

        break;
    case ICMP6_PARAM_PROB:
        switch (icmp6hdr->icmp6_code) {
        case ICMP6_PARAMPROB_NEXTHEADER:
            header.icmp.hdr.type = ICMP_DEST_UNREACH;
            header.icmp.hdr.code = ICMP_PROT_UNREACH;
            header.icmp.hdr.un.gateway = 0;

            break;
        case ICMP6_PARAMPROB_OPTION:
            return 0;
        case ICMP6_PARAMPROB_HEADER: /* TODO */
            log_w("%s - ICMP6_PARAMPROB not implemented yet", addr_str_v6(&ip6hdr->ip6_src));
            return 0;
        default:
            return 0;
        }

        break;
    default:
        return 0;
    }

    inner_ip6hdr = (struct ip6_hdr*)data;
    inner_payload = data + sizeof(struct ip6_hdr);
    inner_payload_len = data_len - sizeof(struct ip6_hdr);
    if (inner_payload_len > ICMP_ERROR_LENGTH_MAX - sizeof(struct iphdr)) {
        inner_payload_len = ICMP_ERROR_LENGTH_MAX - sizeof(struct iphdr);
    }
    inner_ip6hdr_plen = htons(inner_ip6hdr->ip6_plen);

    if (inner_ip6hdr->ip6_nxt == IPPROTO_FRAGMENT) {
        if (inner_payload_len < sizeof(struct ip6_frag)) {
            log_w("%s - Dropping ICMPv6 error packet with invalid inner packet size",
                addr_str_v6(&ip6hdr->ip6_src));
            return 0;
        }

        inner_frag = (struct ip6_frag*)inner_payload;

        inner_payload_len -= sizeof(struct ip6_frag);
        inner_payload += sizeof(struct ip6_frag);

        inner_ip6hdr_plen -= sizeof(struct ip6_frag);
    } else {
        inner_frag = NULL;
    }

    /* Translate IP header of ICMP packet */
    if (trans_header_6to4(ip6hdr, NULL, &header.ip, sizeof(header.icmp) + inner_payload_len,
            src_prefix, dst_prefix, true)
        != 0) {
        log_w("%s - Failed to translate ICMPv6 error header, dropping packet",
            addr_str_v6(&ip6hdr->ip6_src));
        return 0;
    }

    /* Translate inner packet */
    if (trans_header_6to4(inner_ip6hdr, inner_frag,
            &header.icmp.inner_ip, inner_ip6hdr_plen, src_prefix, dst_prefix, false)
        != 0) {
        log_w("%s - Failed to translate ICMPv6 error inner IP packet, dropping packet",
            addr_str_v6(&ip6hdr->ip6_src));
        return 0;
    }
    if (trans_payload_6to4(&header.icmp.inner_ip, inner_ip6hdr, inner_payload, inner_payload_len) != 0) {
        log_w("%s - Failed to translate ICMPv6 error inner IP packet, dropping packet",
            addr_str_v6(&ip6hdr->ip6_src));
        return 0;
    }

    header.icmp.hdr.checksum = 0;
    header.icmp.hdr.checksum = ip_checksum_add(
        ip_checksum(&header.icmp, sizeof(header.icmp)),
        ip_checksum(inner_payload, inner_payload_len));

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = inner_payload;
    iov[1].iov_len = inner_payload_len;

    written = writev(tunfd, iov, sizeof(iov) / sizeof(iov[0]));
    if (written < 0) {
        elog_e("%s - Failed to write packet to TUN interface", addr_str_v6(&ip6hdr->ip6_src));
    } else {
        log_d("%s - IPv6->IPv4 (ICMP error) - Len: %zd", addr_str_v6(&ip6hdr->ip6_src), written);
    }
    return written;
}

ssize_t icmp_echo_6to4(int tunfd, const struct ip6_hdr* ip6hdr,
    const struct icmp6_hdr* icmp6hdr, char* data, size_t data_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct iovec iov[2];
    struct
    {
        struct iphdr ip;
        struct icmphdr icmp;
    } header;

    ssize_t written;

    switch (icmp6hdr->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
        header.icmp.code = ICMP_ECHO;
        header.icmp.type = 0;
        header.icmp.un.echo.id = icmp6hdr->icmp6_id;
        header.icmp.un.echo.sequence = icmp6hdr->icmp6_seq;

        break;
    case ICMP6_ECHO_REPLY:
        header.icmp.code = ICMP_ECHOREPLY;
        header.icmp.type = 0;
        header.icmp.un.echo.id = icmp6hdr->icmp6_id;
        header.icmp.un.echo.sequence = icmp6hdr->icmp6_seq;

        break;
    default:
        return 0;
    }

    if (trans_header_6to4(ip6hdr, NULL, &header.ip, sizeof(struct icmphdr) + data_len,
            src_prefix, dst_prefix, true)
        != 0) {
        log_w("%s - Failed to translate ICMP echo header, dropping packet",
            addr_str_v6(&ip6hdr->ip6_src));
        return 0;
    }

    header.icmp.checksum = 0;
    header.icmp.checksum = ip_checksum_add(
        ip_checksum(&header.icmp, sizeof(header.icmp)),
        ip_checksum(data, data_len));

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = data;
    iov[1].iov_len = data_len;

    written = writev(tunfd, iov, sizeof(iov) / sizeof(iov[0]));
    if (written < 0) {
        elog_e("%s - Failed to write packet to TUN interface", addr_str_v6(&ip6hdr->ip6_src));
    } else {
        log_d("%s - IPv6->IPv4 (ICMP echo) - Len: %zd", addr_str_v6(&ip6hdr->ip6_src), written);
    }
    return written;
}

int pmtu_estimate(size_t packet_len)
{
    static const int mtu_table[] = { 65535, 32000, 17914, 8166, 4352, 2002,
        1492, 1006, 508, 296, 0 };
    int i = 0;

    for (i = 0; mtu_table[i] != 0; i++) {
        if (packet_len > mtu_table[i]) {
            return mtu_table[i];
        }
    }
    return IF_MIN_MTU;
}
