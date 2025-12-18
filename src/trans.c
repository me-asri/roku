#define _DEFAULT_SOURCE

#include "trans.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "addr.h"
#include "checksum.h"

void trans_header_4to6(const struct iphdr* iphdr, struct ip6_hdr* ip6hdr, uint16_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix, bool dec_ttl)
{
    ip6hdr->ip6_vfc = htonl((0x6 << 28) | (iphdr->tos << 20));
    ip6hdr->ip6_plen = htons(payload_len);
    ip6hdr->ip6_nxt = (iphdr->protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : iphdr->protocol;
    ip6hdr->ip6_hops = dec_ttl ? iphdr->ttl - 1 : iphdr->ttl;

    addr_map_4to6(iphdr->saddr, &ip6hdr->ip6_src, src_prefix);
    addr_map_4to6(iphdr->daddr, &ip6hdr->ip6_dst, dst_prefix);
}

int trans_payload_4to6(const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr,
    char* payload, size_t payload_len)
{
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    struct icmphdr* icmphdr;

    uint16_t cksum;

    switch (iphdr->protocol) {
    case IPPROTO_TCP: {
        if (payload_len < sizeof(struct tcphdr)) {
            return 1; /* Invalid packet size */
        }

        tcphdr = (struct tcphdr*)payload;
        tcphdr->check = ip_checksum_4to6(tcphdr->check, iphdr, ip6hdr);
        return 0;
    }
    case IPPROTO_UDP: {
        if (payload_len < sizeof(struct udphdr)) {
            return 1; /* Invalid packet size */
        }

        udphdr = (struct udphdr*)payload;
        if (udphdr->check == 0) {
            return 1; /* UDP packets with no checksum are dropped */
        }
        udphdr->check = ip_checksum_4to6(udphdr->check, iphdr, ip6hdr);
        return 0;
    }
    case IPPROTO_ICMP: {
        if (payload_len < sizeof(struct icmphdr)) {
            return 1; /* Invalid packet size */
        }

        icmphdr = (struct icmphdr*)payload;

        /* TODO: need to test this */
        cksum = ip_checksum_add(icmphdr->checksum,
            ip6_ph_checksum(ip6hdr, ntohs(ip6hdr->ip6_plen), IPPROTO_ICMPV6));

        switch (icmphdr->type) {
        case ICMP_ECHOREPLY:
            icmphdr->type = ICMP6_ECHO_REPLY;
            icmphdr->checksum = ip_checksum_add(cksum, ~(ICMP6_ECHO_REPLY - ICMP_ECHOREPLY));
            break;
        case ICMP_ECHO:
            icmphdr->type = ICMP6_ECHO_REQUEST;
            icmphdr->checksum = ip_checksum_add(cksum, ~(ICMP6_ECHO_REQUEST - ICMP_ECHO));
            break;
        default:
            return 1; /* Unsupported ICMP packet type */
        }
        return 0;
    }
    default:
        return 1; /* Unsupported payload type */
    }
}

int trans_header_6to4(const struct ip6_hdr* ip6hdr, const struct ip6_frag* ip6frag,
    struct iphdr* iphdr, uint16_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix, bool dec_ttl)
{
    iphdr->version = 4;
    iphdr->ihl = 5;
    iphdr->tos = (ntohl(ip6hdr->ip6_vfc) >> 20) & 0xff;
    iphdr->tot_len = htons(payload_len + sizeof(struct iphdr));
    if (ip6frag) {
        iphdr->id = htons(ntohl(ip6frag->ip6f_ident) & 0xffff);
        iphdr->frag_off = htons(ntohs(ip6frag->ip6f_offlg) >> 3);
        if (ip6frag->ip6f_offlg & IP6F_MORE_FRAG) {
            iphdr->frag_off |= htons(IP_MF);
        }
        iphdr->protocol = (ip6frag->ip6f_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6frag->ip6f_nxt;
    } else {
        iphdr->id = 0;
        iphdr->frag_off = htons(IP_DF);
        iphdr->protocol = (ip6hdr->ip6_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6hdr->ip6_nxt;
    }
    iphdr->ttl = dec_ttl ? ip6hdr->ip6_hops - 1 : ip6hdr->ip6_hops;
    iphdr->check = 0;
    if (addr_map_6to4(&ip6hdr->ip6_dst, &iphdr->daddr, src_prefix, dst_prefix) != 0
        || addr_map_6to4(&ip6hdr->ip6_src, &iphdr->saddr, src_prefix, dst_prefix) != 0) {
        return 1; /* Untranslatable address */
    }
    iphdr->check = ip_checksum(iphdr, sizeof(struct iphdr));
    return 0;
}

int trans_payload_6to4(const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr,
    char* payload, size_t payload_len)
{
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    struct icmp6_hdr* icmp6hdr;
    uint16_t cksum;

    switch (iphdr->protocol) {
    case IPPROTO_TCP: {
        if (payload_len < sizeof(struct tcphdr)) {
            return 1; /* Invalid payload size */
        }

        tcphdr = (struct tcphdr*)payload;
        tcphdr->check = ip_checksum_6to4(tcphdr->check, iphdr, ip6hdr);
        return 0;
    }
    case IPPROTO_UDP: {
        if (payload_len < sizeof(struct udphdr)) {
            return 1; /* Invalid payload size */
        }

        udphdr = (struct udphdr*)payload;
        udphdr->check = ip_checksum_6to4(udphdr->check, iphdr, ip6hdr);
        return 0;
    }
    case IPPROTO_ICMP: {
        if (payload_len < sizeof(struct icmp6_hdr)) {
            return 1; /* Invalid payload size */
        }

        icmp6hdr = (struct icmp6_hdr*)payload;

        cksum = ip_checksum_add(icmp6hdr->icmp6_cksum,
            ~ip6_ph_checksum(ip6hdr, ntohs(ip6hdr->ip6_plen), IPPROTO_ICMPV6));

        switch (icmp6hdr->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
            icmp6hdr->icmp6_type = ICMP_ECHO;
            icmp6hdr->icmp6_cksum = ip_checksum_add(cksum, ICMP6_ECHO_REQUEST - ICMP_ECHO);
            break;
        case ICMP6_ECHO_REPLY:
            icmp6hdr->icmp6_type = ICMP_ECHOREPLY;
            icmp6hdr->icmp6_cksum = ip_checksum_add(cksum, ICMP6_ECHO_REPLY - ICMP_ECHOREPLY);
            break;
        default:
            return 1; /* Unsupported ICMPv6 type */
        }
        return 0;
    }
    default:
        return 1; /* Unsupported protocol */
    }
}