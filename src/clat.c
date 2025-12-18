#define _DEFAULT_SOURCE

#include "clat.h"

#include <stddef.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <sys/types.h>
#include <sys/uio.h>

#include "trans.h"
#include "icmp.h"
#include "checksum.h"
#include "addr.h"
#include "log.h"

static ssize_t clat_write_6to4(int tunfd, const struct ip6_hdr* ip6hdr,
    const struct ip6_frag* ip6frag, char* payload, size_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);
static ssize_t clat_write_4to6(int tunfd, const struct iphdr* ip_header,
    char* payload, size_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);

ssize_t clat_packet_4to6(clat_params_t* params, char* packet, size_t len)
{
    struct iphdr* iphdr;
    int iphdr_len;
    int fragmented;

    char* payload;
    size_t payload_len;

    iphdr = (struct iphdr*)packet;
    if (len < sizeof(struct iphdr) || (iphdr_len = iphdr->ihl * 4) < sizeof(struct iphdr)
        || iphdr_len > len) {
        return 0; /* Invalid length */
    }
    if (iphdr->ttl == 0) {
        log_w("%s - Dropping packet with expired TTL", addr_str_v4(iphdr->saddr));
        return 0; /* TTL already exceeded */
    }
    if (ip_checksum(iphdr, iphdr_len) != 0) {
        log_w("%s - Dropping packet with invalid checksum", addr_str_v4(iphdr->saddr));
        return 0;
    }

    if (addr_is_private(iphdr->daddr)) {
        /* Reject private IP destinations */
        if (iphdr->protocol != IPPROTO_ICMP) {
            return icmp_send_error(params->tunfd, ICMP_DEST_UNREACH, ICMP_UNREACH_FILTER_PROHIB,
                params->if_gw, iphdr->saddr, packet, len, 0);
        }
        return 0;
    }
    if (iphdr->ttl - 1 == 0) {
        /* TTL exceeded just now */
        return icmp_send_error(params->tunfd, ICMP_TIME_EXCEEDED, ICMP_TIMXCEED_INTRANS,
            params->if_gw, iphdr->saddr, packet, len, 0);
    }

    fragmented = iphdr->frag_off & htons(IP_OFFMASK | IP_MF);

    payload = packet + iphdr_len;
    payload_len = len - iphdr_len;

    if (iphdr->protocol == IPPROTO_ICMP) {
        if (fragmented) {
            log_w("%s - Fragmented ICMPv4 is not supported", addr_str_v4(iphdr->saddr));
            return 0;
        }
        return icmp_write_4to6(params->tunfd, params->if_mtu, iphdr, payload, payload_len,
            &params->src_prefix, &params->dst_prefix);
    } else {
        if (!fragmented && (iphdr->frag_off & htons(IP_DF))) {
            int adjusted_mtu = params->if_mtu - MTU_DIFF;
            if (len > adjusted_mtu) {
                /* Packet too large for our interface, fragmentation needed */
                return icmp_send_error(params->tunfd, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
                    params->if_gw, params->if_ip, packet, len, adjusted_mtu);
            }
        }

        return clat_write_4to6(params->tunfd, iphdr, payload, payload_len,
            &params->src_prefix, &params->dst_prefix);
    }
}

ssize_t clat_packet_6to4(clat_params_t* params, char* packet, size_t len)
{
    struct ip6_hdr* ip6hdr;

    char* payload;
    size_t payload_len;
    struct ip6_frag* ip6frag;

    if (len < sizeof(struct ip6_hdr)) {
        return 0; /* Invalid length */
    }

    ip6hdr = (struct ip6_hdr*)packet;
    if (ip6hdr->ip6_hops == 0) {
        return 0; /* TTL exceeded */
    }

    if (len > params->if_mtu) {
        /* Packet too large for our interface */
        return icmp6_send_error(params->tunfd, ICMP6_PACKET_TOO_BIG, 0,
            &params->if_gw6, &ip6hdr->ip6_src, packet, len, params->if_mtu);
    }
    if (!addr_prefix_match(&ip6hdr->ip6_dst, &params->dst_prefix)
        && !addr_prefix_match(&ip6hdr->ip6_dst, &params->src_prefix)) {
        /* A packet has reached us that's not from the NAT64 prefix */
        if (ip6hdr->ip6_nxt != IPPROTO_ICMPV6) {
            return icmp6_send_error(params->tunfd, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN,
                &params->if_gw6, &ip6hdr->ip6_src, packet, len, 0);
        }
        return 0;
    }
    if (ip6hdr->ip6_hops - 1 == 0) {
        /* TTL exceeded just now */
        return icmp6_send_error(params->tunfd, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT,
            &params->if_gw6, &ip6hdr->ip6_src, packet, len, 0);
    }

    payload = packet + sizeof(struct ip6_hdr);
    payload_len = len - sizeof(struct ip6_hdr);

    if (ip6hdr->ip6_nxt == IPPROTO_ICMPV6) {
        return icmp_write_6to4(params->tunfd, params->if_mtu, ip6hdr, payload, payload_len,
            &params->src_prefix, &params->dst_prefix);
    } else {
        if (ip6hdr->ip6_nxt == IPPROTO_FRAGMENT) {
            if (payload_len < sizeof(struct ip6_frag)) {
                log_w("%s - Dropping packet with invalid fragment length", addr_str_v6(&ip6hdr->ip6_src));
                return 0;
            }
            ip6frag = (struct ip6_frag*)payload;
            if (ip6frag->ip6f_nxt == IPPROTO_ICMPV6) {
                log_w("%s - Fragmented ICMPv6 is not supported", addr_str_v6(&ip6hdr->ip6_src));
                return 0;
            }
            payload += sizeof(struct ip6_frag);
            payload_len -= sizeof(struct ip6_frag);
        } else {
            ip6frag = NULL;
        }
        return clat_write_6to4(params->tunfd, ip6hdr, ip6frag, payload, payload_len,
            &params->src_prefix, &params->dst_prefix);
    }
}

ssize_t clat_write_6to4(int tunfd, const struct ip6_hdr* ip6hdr,
    const struct ip6_frag* ip6frag, char* payload, size_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct iphdr iphdr;
    struct iovec iov[2];
    uint16_t offset;

    ssize_t written;

    if (trans_header_6to4(ip6hdr, ip6frag, &iphdr, payload_len, src_prefix, dst_prefix, true) != 0) {
        log_w("%s - Failed to translate packet header, dropping packet",
            addr_str_v6(&ip6hdr->ip6_src));
        return 0;
    }

    offset = ip6frag ? ntohs(ip6frag->ip6f_offlg & IP6F_OFF_MASK) : 0;
    if (offset == 0) {
        /* When it comes to payloads we translate the first fragment's which contains the payload header */
        if (trans_payload_6to4(&iphdr, ip6hdr, payload, payload_len) != 0) {
            log_w("%s - Failed to translate packet payload, dropping packet",
                addr_str_v6(&ip6hdr->ip6_src));
            return 0;
        }
    }

    iov[0].iov_base = &iphdr;
    iov[0].iov_len = sizeof(struct iphdr);
    iov[1].iov_base = payload;
    iov[1].iov_len = payload_len;

    written = writev(tunfd, iov, 2);
    if (written < 0) {
        elog_e("%s - Failed to write packet", addr_str_v6(&ip6hdr->ip6_src));
    } else {
        log_d("%s - IPv6->IPv4 - Len: %zd", addr_str_v6(&ip6hdr->ip6_src), written);
    }
    return written;
}

ssize_t clat_write_4to6(int tunfd, const struct iphdr* iphdr,
    char* payload, size_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    struct ip6_hdr ip6hdr;
    struct iovec iov[3];
    int offset;
    int flags;

    int fragmented;
    struct ip6_frag ip6frag;
    size_t frag_payload_len;
    size_t frag_offset;
    int mf_flag;

    ssize_t total_written;
    ssize_t written;

    trans_header_4to6(iphdr, &ip6hdr, payload_len, src_prefix, dst_prefix, true);

    offset = ntohs(iphdr->frag_off);
    flags = offset & ~IP_OFFMASK;
    offset = (offset & IP_OFFMASK) << 3;

    if (offset == 0) {
        /* We only care about the first fragment packet (that contains the payload header) to translate */
        if (trans_payload_4to6(iphdr, &ip6hdr, payload, payload_len) != 0) {
            log_w("%s - Failed to translate IPv4 packet payload, dropping packet",
                addr_str_v4(iphdr->saddr));
            return 0;
        }
    }

    iov[0].iov_base = &ip6hdr;
    iov[0].iov_len = sizeof(struct ip6_hdr);

    if ((flags & IP_MF) || offset > 0) {
        fragmented = 1; /* More fragments or offset is set */
    } else {
        /* If IP_DF is not set check if when translated to v6 it would be larger than the minimum MTU */
        fragmented = (flags & IP_DF)
            ? 0
            : ((sizeof(struct ip6_hdr) + payload_len) > IF_MIN_MTU_V6);
    }

    if (fragmented) {
        ip6frag.ip6f_nxt = ip6hdr.ip6_nxt;
        ip6hdr.ip6_nxt = IPPROTO_FRAGMENT;
        ip6frag.ip6f_ident = htonl(ntohs(iphdr->id));
        ip6frag.ip6f_reserved = 0;

        iov[1].iov_base = &ip6frag;
        iov[1].iov_len = sizeof(struct ip6_frag);

        /* Break IPv4 packet into fragmented IPv6 packets */
        frag_offset = 0;
        total_written = 0;
        while (frag_offset < payload_len) {
            frag_payload_len = IF_MIN_MTU_V6 - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag));
            mf_flag = IP_MF;

            if (frag_offset + frag_payload_len > payload_len) {
                frag_payload_len = payload_len - frag_offset;
                if (!(flags & IP_MF)) {
                    mf_flag = 0;
                }
            }

            ip6hdr.ip6_plen = htons(frag_payload_len + sizeof(struct ip6_frag));
            ip6frag.ip6f_offlg = htons((offset + frag_offset) | mf_flag >> 13);

            iov[2].iov_base = payload + frag_offset;
            iov[2].iov_len = frag_payload_len;

            written = writev(tunfd, iov, 3);
            if (written < 0) {
                elog_e("%s - Failed to write packet to TUN interface", addr_str_v4(iphdr->saddr));
                return written;
            } else {
                log_d("%s - IPv4->IPv6 (frag) - Len: %zd", addr_str_v4(iphdr->saddr), written);
            }
            total_written += written;

            frag_offset += frag_payload_len;
        }
        return total_written;
    } else {
        iov[1].iov_base = payload;
        iov[1].iov_len = payload_len;

        written = writev(tunfd, iov, 2);
        if (written < 0) {
            elog_e("%s - Failed to write packet to TUN interface", addr_str_v4(iphdr->saddr));
        } else {
            log_d("%s - IPv4->IPv6 - Len: %zd", addr_str_v4(iphdr->saddr), written);
        }
        return written;
    }
}
