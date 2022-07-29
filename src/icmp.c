#include "icmp.h"

#include <sys/uio.h>

#include "roku.h"
#include "checksum.h"
#include "xlat.h"
#include "log.h"

// Estimate MTU using the algorithm from RFC 1191.
static int estimate_mtu(int packet_length)
{
    static const int table[] = {65535, 32000, 17914, 8166, 4352,
                                2002, 1492, 1006, 508, 296, 0};

    for (int i = 0; table[i] != 0; i++)
    {
        if (packet_length > table[i])
        {
            return table[i];
        }
    }
    return MTU_MIN;
}

int icmp_send_error(int type, int code, in_addr_t src, in_addr_t dst, char *payload, int payload_length, int data)
{
    if (payload_length < sizeof(struct iphdr))
    {
        return 0;
    }

    if (payload_length > ICMP_ERROR_LENGTH_MAX)
    {
        payload_length = ICMP_ERROR_LENGTH_MAX;
    }

    struct
    {
        struct iphdr ip;
        struct icmphdr icmp;
    } header;

    header.ip.version = 4;
    header.ip.ihl = 5;
    header.ip.saddr = src;
    header.ip.daddr = dst;
    header.ip.frag_off = 0;
    header.ip.id = 0;
    header.ip.protocol = IPPROTO_ICMP;
    header.ip.tos = 0;
    header.ip.ttl = 64;
    header.ip.tot_len = htons(sizeof(header) + payload_length);
    header.ip.check = 0;
    header.ip.check = checksum(&header.ip, sizeof(struct iphdr));

    header.icmp.type = type;
    header.icmp.code = code;
    header.icmp.un.gateway = htonl(data);
    header.icmp.checksum = 0;
    header.icmp.checksum = checksum_sum(checksum(&header.icmp, sizeof(struct icmphdr)), checksum(payload, payload_length));

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = payload;
    iov[1].iov_len = payload_length;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        log_error("Failed to write packet");
        return -1;
    }
    return 1;
}

int icmp6_send_error(int type, int code, struct in6_addr *src, struct in6_addr *dst, char *payload, int payload_length, int data)
{
    if (payload_length < sizeof(struct ip6_hdr))
    {
        return 0;
    }

    if (payload_length > ICMP6_ERROR_LENGTH_MAX)
    {
        payload_length = ICMP6_ERROR_LENGTH_MAX;
    }

    struct
    {
        struct ip6_hdr ip6;
        struct icmp6_hdr icmp6;
    } header;

    header.ip6.ip6_vfc = htonl(0x6 << 28);
    header.ip6.ip6_plen = htons(sizeof(header.icmp6) + payload_length);
    header.ip6.ip6_nxt = IPPROTO_ICMPV6;
    header.ip6.ip6_hops = 64;
    header.ip6.ip6_src = *src;
    header.ip6.ip6_dst = *dst;

    header.icmp6.icmp6_type = type;
    header.icmp6.icmp6_code = code;
    header.icmp6.icmp6_dataun.icmp6_un_data32[0] = htonl(data);
    header.icmp6.icmp6_cksum = 0;
    header.icmp6.icmp6_cksum = checksum_sum(checksum_pseudo6(&header.ip6, sizeof(header.icmp6) + payload_length, IPPROTO_ICMPV6),
                                            checksum(&header.icmp6, sizeof(header.icmp6)));
    header.icmp6.icmp6_cksum = checksum_sum(header.icmp6.icmp6_cksum, checksum(payload, payload_length));

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = payload;
    iov[1].iov_len = payload_length;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        log_error("Failed to write packet");
        return -1;
    }
    return 1;
}

static int icmp_error_4to6(struct iphdr *ip_header, struct icmphdr *icmp_header, char *data, int data_length)
{
    if (data_length < sizeof(struct iphdr))
    {
        return 0;
    }

    struct
    {
        struct ip6_hdr ip6;
        struct
        {
            struct icmp6_hdr hdr;
            struct ip6_hdr ip6;
        } icmp6;
    } header;

    switch (icmp_header->type)
    {
    case ICMP_DEST_UNREACH:
        header.icmp6.hdr.icmp6_type = ICMP6_DST_UNREACH;
        header.icmp6.hdr.icmp6_dataun.icmp6_un_data32[0] = 0;
        switch (icmp_header->code)
        {
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
        case ICMP_FRAG_NEEDED:
        {
            int mtu = htons(icmp_header->un.frag.mtu);
            header.icmp6.hdr.icmp6_type = ICMP6_PACKET_TOO_BIG;
            header.icmp6.hdr.icmp6_code = 0;
            if (mtu < MTU_MIN)
            {
                mtu = estimate_mtu(ntohs(ip_header->tot_len));
            }
            mtu += MTU_DIFF;
            if (mtu > roku_cfg.mtu)
            {
                mtu = roku_cfg.mtu;
            }
            if (mtu < IPV6_MIN_MTU)
            {
                mtu = IPV6_MIN_MTU;
            }
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
    case ICMP_TIME_EXCEEDED:
        header.icmp6.hdr.icmp6_type = ICMP6_TIME_EXCEEDED;
        header.icmp6.hdr.icmp6_code = icmp_header->code;
        header.icmp6.hdr.icmp6_dataun.icmp6_un_data32[0] = 0;
    case ICMP_PARAMPROB:
        header.icmp6.hdr.icmp6_type = ICMP6_PARAM_PROB;
        switch (icmp_header->code)
        {
        case ICMP_PARAMPROB_OPTABSENT:
            return 0;
        case ICMP_PARAMPROB_PTRERR:
        case ICMP_PARAMPROB_BADLEN:
            log_warn("ICMP type not implemented");
            // TODO
        default:
            return 0;
        }
    default:
        return 0;
    }

    struct iphdr *em_ip = (struct iphdr *)data;
    int em_iplen = em_ip->ihl * 4;
    if (em_iplen > data_length)
    {
        return 0;
    }

    char *em_payload = data + em_iplen;
    int em_plen = data_length - em_iplen;
    if (em_plen > ICMP6_ERROR_LENGTH_MAX - sizeof(struct ip6_hdr))
    {
        em_plen = ICMP6_ERROR_LENGTH_MAX - sizeof(struct ip6_hdr);
    }

    xlat_header_4to6(ip_header, &header.ip6, sizeof(header.icmp6) + em_plen);

    xlat_header_4to6(em_ip, &header.icmp6.ip6, ntohs(em_ip->tot_len) - em_iplen);
    if (xlat_payload_4to6(em_ip, &header.icmp6.ip6, em_payload, em_plen) < 0)
    {
        return 0;
    }

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = em_payload;
    iov[1].iov_len = em_plen;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        log_error("Failed to write packet");
        return -1;
    }
    return 0;
}

static int icmp_info_4to6(struct iphdr *ip_header, struct icmphdr *icmp_header, char *data, int data_length)
{
    struct
    {
        struct ip6_hdr ip6;
        struct icmp6_hdr icmp6;
    } header;

    switch (icmp_header->type)
    {
    case ICMP_ECHOREPLY:
        header.icmp6.icmp6_type = ICMP6_ECHO_REPLY;
        header.icmp6.icmp6_code = 0;
        header.icmp6.icmp6_id = icmp_header->un.echo.id;
        header.icmp6.icmp6_seq = icmp_header->un.echo.sequence;
        break;
    case ICMP_ECHO:
        header.icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
        header.icmp6.icmp6_code = 0;
        header.icmp6.icmp6_id = icmp_header->un.echo.id;
        header.icmp6.icmp6_seq = icmp_header->un.echo.sequence;
        break;
    default:
        return 0;
    }

    xlat_header_4to6(ip_header, &header.ip6, data_length + sizeof(struct icmp6_hdr));

    header.icmp6.icmp6_cksum = 0;
    header.icmp6.icmp6_cksum = checksum_sum(checksum_pseudo6(&header.ip6, sizeof(struct icmp6_hdr) + data_length, IPPROTO_ICMPV6),
                                            checksum(&header.icmp6, sizeof(struct icmp6_hdr)));
    header.icmp6.icmp6_cksum = checksum_sum(header.icmp6.icmp6_cksum, checksum(data, data_length));

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = data;
    iov[1].iov_len = data_length;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        return -1;
    }
    return 1;
}

int icmp_4to6(struct iphdr *ip_header, char *payload, int payload_length)
{
    struct icmphdr *icmp_header = (struct icmphdr *)payload;
    char *data = payload + sizeof(struct icmphdr);
    int data_length = payload_length - sizeof(struct icmphdr);

    ip_header->ttl--;

    if (icmp_header->type == ICMP_ECHOREPLY || icmp_header->type == ICMP_ECHO)
    {
        return icmp_info_4to6(ip_header, icmp_header, data, data_length);
    }
    else
    {
        return icmp_error_4to6(ip_header, icmp_header, data, data_length);
    }
}

static int icmp_error_6to4(struct ip6_hdr *ip6_header, struct icmp6_hdr *icmp6_header, char *data, int data_length)
{
    if (data_length < sizeof(struct ip6_hdr))
    {
        return 0;
    }

    struct
    {
        struct iphdr ip;
        struct
        {
            struct icmphdr hdr;
            struct iphdr ip;
        } icmp;
    } header;

    switch (icmp6_header->icmp6_type)
    {
    case ICMP6_DST_UNREACH:
        header.icmp.hdr.type = ICMP_DEST_UNREACH;
        header.icmp.hdr.un.gateway = 0; // Set unused to 0
        switch (icmp6_header->icmp6_type)
        {
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
    case ICMP6_PACKET_TOO_BIG:
    {
        int mtu = ntohl(icmp6_header->icmp6_mtu);
        header.icmp.hdr.type = ICMP_DEST_UNREACH;
        header.icmp.hdr.code = ICMP_FRAG_NEEDED;
        if (mtu > roku_cfg.mtu)
        {
            mtu = roku_cfg.mtu;
        }
        mtu -= MTU_DIFF;
        header.icmp.hdr.un.frag.mtu = htons(mtu);
        break;
    }
    case ICMP6_TIME_EXCEEDED:
        header.icmp.hdr.type = ICMP_TIME_EXCEEDED;
        header.icmp.hdr.code = icmp6_header->icmp6_code;
        header.icmp.hdr.un.gateway = 0;
        break;
    case ICMP6_PARAM_PROB:
        switch (icmp6_header->icmp6_code)
        {
        case ICMP6_PARAMPROB_NEXTHEADER:
            header.icmp.hdr.type = ICMP_DEST_UNREACH;
            header.icmp.hdr.code = ICMP_PROT_UNREACH;
            header.icmp.hdr.un.gateway = 0;
            break;
        case ICMP6_PARAMPROB_OPTION:
            return 0;
        case ICMP6_PARAMPROB_HEADER:
            log_warn("ICMPv6 type not implemented");
            // TODO
        default:
            return 0;
        }
    default:
        return 0;
    }

    struct ip6_hdr *em_ip6 = (struct ip6_hdr *)data;
    char *em_payload = data + sizeof(struct ip6_hdr);
    int em_plen = data_length - sizeof(struct ip6_hdr);
    if (em_plen > ICMP_ERROR_LENGTH_MAX - sizeof(struct iphdr))
    {
        em_plen = ICMP_ERROR_LENGTH_MAX - sizeof(struct iphdr);
    }

    int em_plen_orig = htons(em_ip6->ip6_plen);
    struct ip6_frag *em_frag = NULL;
    if (em_ip6->ip6_nxt == IPPROTO_FRAGMENT)
    {
        em_frag = (struct ip6_frag *)em_payload;
        em_plen -= sizeof(struct ip6_frag);
        em_plen_orig -= sizeof(struct ip6_frag);
        em_payload += sizeof(struct ip6_frag);
    }

    xlat_header_6to4(ip6_header, NULL, &header.ip, sizeof(header.icmp) + em_plen);

    xlat_header_6to4(em_ip6, em_frag, &header.icmp.ip, em_plen_orig);
    if (xlat_payload_6to4(&header.icmp.ip, em_ip6, em_payload, em_plen) < 0)
    {
        return 0;
    }

    header.icmp.hdr.checksum = 0;
    header.icmp.hdr.checksum = checksum_sum(checksum(&header.icmp, sizeof(header.icmp)),
                                            checksum(em_payload, em_plen));

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = em_payload;
    iov[1].iov_len = em_plen;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        log_error("Failed to write packet");
        return -1;
    }
    return 1;
}

static int icmp_info_6to4(struct ip6_hdr *ip6_header, struct icmp6_hdr *icmp6_header, char *data, int data_length)
{
    struct
    {
        struct iphdr ip;
        struct icmphdr icmp;
    } header;

    switch (icmp6_header->icmp6_type)
    {
    case ICMP6_ECHO_REQUEST:
        header.icmp.code = ICMP_ECHO;
        header.icmp.type = 0;
        header.icmp.un.echo.id = icmp6_header->icmp6_id;
        header.icmp.un.echo.sequence = icmp6_header->icmp6_seq;
        break;
    case ICMP6_ECHO_REPLY:
        header.icmp.code = ICMP_ECHOREPLY;
        header.icmp.type = 0;
        header.icmp.un.echo.id = icmp6_header->icmp6_id;
        header.icmp.un.echo.sequence = icmp6_header->icmp6_seq;
        break;
    default:
        return 0;
    }

    xlat_header_6to4(ip6_header, NULL, &header.ip, sizeof(struct icmphdr) + data_length);

    header.icmp.checksum = 0;
    header.icmp.checksum = checksum_sum(checksum(&header.icmp, sizeof(header.icmp)),
                                        checksum(data, data_length));

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = data;
    iov[1].iov_len = data_length;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        log_error("Failed to write packet");
        return -1;
    }
    return 1;
}

int icmp_6to4(struct ip6_hdr *ip6_header, char *payload, int payload_length)
{
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)payload;
    char *data = payload + sizeof(struct icmp6_hdr);
    int data_length = payload_length - sizeof(struct icmp6_hdr);

    ip6_header->ip6_hops--;

    if (icmp6_header->icmp6_type == ICMP6_ECHO_REQUEST || icmp6_header->icmp6_type == ICMP6_ECHO_REPLY)
    {
        return icmp_info_6to4(ip6_header, icmp6_header, data, data_length);
    }
    else
    {
        return icmp_error_6to4(ip6_header, icmp6_header, data, data_length);
    }
}
