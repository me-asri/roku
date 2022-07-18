#include "xlat.h"

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "roku.h"
#include "addr.h"
#include "checksum.h"

void xlat_header_4to6(struct iphdr *ip_header, struct ip6_hdr *ip6_header, int payload_length)
{
    ip6_header->ip6_vfc = htonl((0x6 << 28) | (ip_header->tos << 20));
    ip6_header->ip6_plen = htons(payload_length);
    ip6_header->ip6_nxt = (ip_header->protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : ip_header->protocol;
    ip6_header->ip6_hops = ip_header->ttl;
    addr_4to6(ip_header->saddr, &ip6_header->ip6_src, &roku_cfg.src_prefix);
    addr_4to6(ip_header->daddr, &ip6_header->ip6_dst, &roku_cfg.dst_prefix);
}

int xlat_payload_4to6(struct iphdr *ip_header, struct ip6_hdr *ip6_header, char *payload, int payload_length)
{
    switch (ip_header->protocol)
    {
    case IPPROTO_TCP:
    {
        if (payload_length < sizeof(struct tcphdr))
        {
            return -1;
        }

        struct tcphdr *tcp_header = (struct tcphdr *)payload;
        tcp_header->check = checksum_4to6(tcp_header->check, ip_header, ip6_header);
        break;
    }
    case IPPROTO_UDP:
    {
        if (payload_length < sizeof(struct udphdr))
        {
            return -1;
        }

        struct udphdr *udp_header = (struct udphdr *)payload;
        if (udp_header->check == 0)
        {
            return -1; // Drop UDP packets with no checksum
        }
        udp_header->check = checksum_4to6(udp_header->check, ip_header, ip6_header);
        break;
    }
    case IPPROTO_ICMP:
    {
        if (payload_length < sizeof(struct icmphdr))
        {
            return -1;
        }

        struct icmphdr *icmp_header = (struct icmphdr *)payload;

        uint16_t cksum = ~checksum_pseudo6(ip6_header, htons(ip6_header->ip6_plen) - sizeof(struct icmp6_hdr), IPPROTO_ICMPV6);
        cksum = checksum_sum(icmp_header->checksum, cksum);

        switch (icmp_header->type)
        {
        case ICMP_ECHOREPLY:
            icmp_header->type = ICMP6_ECHO_REPLY;
            icmp_header->checksum = checksum_sum(cksum, ~(ICMP6_ECHO_REPLY - ICMP_ECHOREPLY));
            break;
        case ICMP_ECHO:
            icmp_header->type = ICMP6_ECHO_REQUEST;
            icmp_header->checksum = checksum_sum(cksum, ~(ICMP6_ECHO_REQUEST - ICMP_ECHO));
            break;
        default:
            return -1;
        }
        break;
    }
    default:
        return 0;
    }
    return 1;
}

bool xlat_header_6to4(struct ip6_hdr *ip6_header, struct ip6_frag *ip6_fragment, struct iphdr *ip_header, int payload_length)
{
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = (ntohl(ip6_header->ip6_vfc) >> 20) & 0xff;
    ip_header->tot_len = htons(payload_length + sizeof(struct iphdr));
    if (ip6_fragment)
    {
        ip_header->id = htons(ntohl(ip6_fragment->ip6f_ident) & 0xffff);
        ip_header->frag_off = htons(ntohs(ip6_fragment->ip6f_offlg) >> 3);
        if (ip6_fragment->ip6f_offlg & IP6F_MORE_FRAG)
        {
            ip_header->frag_off |= htons(IP_MF);
        }
        ip_header->protocol = (ip6_fragment->ip6f_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6_fragment->ip6f_nxt;
    }
    else
    {
        ip_header->id = 0;
        ip_header->frag_off = htons(IP_DF);
        ip_header->protocol = (ip6_header->ip6_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6_header->ip6_nxt;
    }
    ip_header->ttl = ip6_header->ip6_hops;
    ip_header->check = 0;
    if (!addr_6to4(&ip6_header->ip6_dst, &ip_header->daddr, false) || !addr_6to4(&ip6_header->ip6_src, &ip_header->saddr, true))
    {
        return false;
    }
    ip_header->check = checksum(ip_header, sizeof(struct iphdr));
    return true;
}

int xlat_payload_6to4(struct iphdr *ip_header, struct ip6_hdr *ip6_header, char *payload, int payload_length)
{
    switch (ip_header->protocol)
    {
    case IPPROTO_TCP:
    {
        if (payload_length < sizeof(struct tcphdr))
        {
            return -1;
        }

        struct tcphdr *tcp_header = (struct tcphdr *)payload;
        tcp_header->check = checksum_6to4(tcp_header->check, ip_header, ip6_header);
        break;
    }
    case IPPROTO_UDP:
    {
        if (payload_length < sizeof(struct udphdr))
        {
            return -1;
        }

        struct udphdr *udp_header = (struct udphdr *)payload;
        udp_header->check = checksum_6to4(udp_header->check, ip_header, ip6_header);
        break;
    }
    case IPPROTO_ICMP:
    {
        if (payload_length < sizeof(struct icmp6_hdr))
        {
            return -1;
        }

        struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)payload;

        uint16_t cksum = ~checksum_pseudo6(ip6_header, htons(ip6_header->ip6_plen) - sizeof(struct icmp6_hdr), IPPROTO_ICMPV6);
        cksum = checksum_sum(cksum, icmp6_header->icmp6_cksum);

        switch (icmp6_header->icmp6_type)
        {
        case ICMP6_ECHO_REQUEST:
            icmp6_header->icmp6_type = ICMP_ECHO;
            icmp6_header->icmp6_cksum = checksum_sum(cksum, ICMP6_ECHO_REQUEST - ICMP_ECHO);
            break;
        case ICMP6_ECHO_REPLY:
            icmp6_header->icmp6_type = ICMP_ECHOREPLY;
            icmp6_header->icmp6_cksum = checksum_sum(cksum, ICMP6_ECHO_REPLY - ICMP_ECHOREPLY);
            break;
        default:
            return -1;
        }
        break;
    }
    default:
        return 0;
    }
    return 1;
}