#include "clat.h"

#include <stdbool.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <sys/uio.h>

#include "roku.h"
#include "xlat.h"
#include "icmp.h"
#include "checksum.h"
#include "addr.h"
#include "log.h"

static int clat_packet_4to6(struct iphdr *ip_header, char *payload, int payload_length)
{
    ip_header->ttl--;
    struct ip6_hdr ip6_header;
    xlat_header_4to6(ip_header, &ip6_header, payload_length);

    int offset = ntohs(ip_header->frag_off);
    int flags = offset & ~IP_OFFMASK;
    offset = (offset & IP_OFFMASK) << 3;

    if (offset == 0)
    {
        if (xlat_payload_4to6(ip_header, &ip6_header, payload, payload_length) < 0)
        {
            return 0;
        }
    }

    struct iovec iov[3];
    iov[0].iov_base = &ip6_header;
    iov[0].iov_len = sizeof(struct ip6_hdr);

    bool fragment;
    if ((flags & IP_MF) || offset > 0)
    {
        fragment = true;
    }
    else
    {
        fragment = (flags & IP_DF) ? false : ((sizeof(struct ip6_hdr) + payload_length) > IPV6_MIN_MTU);
    }

    if (fragment)
    {
        struct ip6_frag ip6_fragment;
        ip6_fragment.ip6f_nxt = ip6_header.ip6_nxt;
        ip6_header.ip6_nxt = IPPROTO_FRAGMENT;
        ip6_fragment.ip6f_ident = htonl(ntohs(ip_header->id));
        ip6_fragment.ip6f_reserved = 0;

        iov[1].iov_base = &ip6_fragment;
        iov[1].iov_len = sizeof(struct ip6_frag);

        int frag_offset = 0;
        while (frag_offset < payload_length)
        {
            int frag_payload_len = IPV6_MIN_MTU - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag));
            int mf_flag = IP_MF;

            if (frag_offset + frag_payload_len > payload_length)
            {
                frag_payload_len = payload_length - frag_offset;
                if (!(flags & IP_MF))
                {
                    mf_flag = 0;
                }
            }

            ip6_header.ip6_plen = htons(frag_payload_len + sizeof(struct ip6_frag));
            ip6_fragment.ip6f_offlg = htons((offset + frag_offset) | mf_flag >> 13);

            iov[2].iov_base = payload + frag_offset;
            iov[2].iov_len = frag_payload_len;

            if (writev(roku_cfg.tunfd, iov, 3) < 0)
            {
                log_error("Failed to write packet");
                return -1;
            }

            frag_offset += frag_payload_len;
        }
    }
    else
    {
        iov[1].iov_base = payload;
        iov[1].iov_len = payload_length;

        if (writev(roku_cfg.tunfd, iov, 2) < 0)
        {
            log_error("Failed to write packet");
            return -1;
        }
    }

    return 1;
}

int clat_4to6(char *ip_packet, int packet_length)
{
    if (packet_length < sizeof(struct iphdr))
    {
        return 0;
    }

    struct iphdr *ip_header = (struct iphdr *)ip_packet;
    int ip_header_len = ip_header->ihl * 4;

    if (ip_header->version != 4 || ip_header_len < sizeof(struct iphdr) || ip_header_len > packet_length || ip_header->ttl == 0 || checksum(ip_header, ip_header_len) != 0)
    {
        return 0;
    }

    if (!addr_validate(ip_header->daddr))
    {
        if (ip_header->protocol != IPPROTO_ICMP)
        {
            icmp_send_error(ICMP_DEST_UNREACH, ICMP_UNREACH_FILTER_PROHIB, roku_cfg.gateway, ip_header->saddr, ip_packet, packet_length, 0);
        }
        return 0;
    }
    if (ip_header->ttl - 1 == 0)
    {
        icmp_send_error(ICMP_TIME_EXCEEDED, ICMP_TIMXCEED_INTRANS, roku_cfg.gateway, ip_header->saddr, ip_packet, packet_length, 0);
        return 0;
    }

    char *payload = ip_packet + ip_header_len;
    int payload_length = packet_length - ip_header_len;

    bool fragmented = ip_header->frag_off & htons(IP_OFFMASK | IP_MF);

    if (ip_header->protocol == IPPROTO_ICMP)
    {
        if (fragmented)
        {
            return 0; // Fragmented ICMP is not supported
        }
        else
        {
            return icmp_4to6(ip_header, payload, payload_length);
        }
    }
    else
    {
        if (!fragmented && (ip_header->frag_off & htons(IP_DF)))
        {
            int adjusted_mtu = roku_cfg.mtu - MTU_DIFF;
            if (packet_length > adjusted_mtu)
            {
                icmp_send_error(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, roku_cfg.gateway, roku_cfg.ip, ip_packet, packet_length, adjusted_mtu);
                return 0;
            }
        }

        return clat_packet_4to6(ip_header, payload, payload_length);
    }
}

static int clat_packet_6to4(struct ip6_hdr *ip6_header, struct ip6_frag *ip6_fragment, char *payload, int payload_length)
{
    ip6_header->ip6_hops--;

    struct iphdr ip_header;
    if (!xlat_header_6to4(ip6_header, ip6_fragment, &ip_header, payload_length))
    {
        return 0;
    }

    int offset = (ip6_fragment) ? ntohs(ip6_fragment->ip6f_offlg & IP6F_OFF_MASK) : 0;
    if (offset == 0)
    {
        if (xlat_payload_6to4(&ip_header, ip6_header, payload, payload_length) < 0)
        {
            return 0;
        }
    }

    struct iovec iov[2];
    iov[0].iov_base = &ip_header;
    iov[0].iov_len = sizeof(struct iphdr);
    iov[1].iov_base = payload;
    iov[1].iov_len = payload_length;

    if (writev(roku_cfg.tunfd, iov, 2) < 0)
    {
        log_error("Failed to write packet");
        return -1;
    }

    return 1;
}

int clat_6to4(char *ip6_packet, int packet_length)
{
    if (packet_length < sizeof(struct ip6_hdr))
    {
        return 0;
    }

    struct ip6_hdr *ip6_header = (struct ip6_hdr *)ip6_packet;

    if ((ip6_header->ip6_vfc >> 4) != 6 || ip6_header->ip6_hops == 0)
    {
        return 0;
    }

    if (!ADDR_MATCH_PREFIX(ip6_header->ip6_dst, roku_cfg.dst_prefix) && !ADDR_MATCH_PREFIX(ip6_header->ip6_dst, roku_cfg.src_prefix))
    {
        if (ip6_header->ip6_nxt != IPPROTO_ICMPV6)
        {
            icmp6_send_error(ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN, &roku_cfg.gateway6, &ip6_header->ip6_src, ip6_packet, packet_length, 0);
        }
        return 0;
    }
    if (ip6_header->ip6_hops - 1 == 0)
    {
        icmp6_send_error(ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, &roku_cfg.gateway6, &ip6_header->ip6_src, ip6_packet, packet_length, 0);
        return 0;
    }
    if (packet_length > roku_cfg.mtu)
    {
        icmp6_send_error(ICMP6_PACKET_TOO_BIG, 0, &roku_cfg.gateway6, &ip6_header->ip6_src, ip6_packet, packet_length, roku_cfg.mtu);
        return 0;
    }

    char *payload = ip6_packet + sizeof(struct ip6_hdr);
    int payload_length = packet_length - sizeof(struct ip6_hdr);

    if (ip6_header->ip6_nxt == IPPROTO_ICMPV6)
    {
        return icmp_6to4(ip6_header, payload, payload_length);
    }
    else
    {
        struct ip6_frag *ip6_fragment = NULL;

        if (ip6_header->ip6_nxt == IPPROTO_FRAGMENT)
        {
            if (payload_length < sizeof(struct ip6_frag))
            {
                return 0;
            }

            ip6_fragment = (struct ip6_frag *)payload;
            if (ip6_fragment->ip6f_nxt == IPPROTO_ICMPV6)
            {
                return 0; // Fragmented ICMP is not supported
            }

            payload += sizeof(struct ip6_frag);
            payload_length -= sizeof(struct ip6_frag);
        }

        return clat_packet_6to4(ip6_header, ip6_fragment, payload, payload_length);
    }
}