#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/* Minimum possible MTU */
#define IF_MIN_MTU 68
/* Minimum MTU for IPv6 */
#define IF_MIN_MTU_V6 1280
/* MTU difference between IPv4 and IPv6.
   There is a 20 byte difference between IPv6 and IPv4 header sizes.
   This does not account for IPv6 fragmentation header. */
#define MTU_DIFF 20

/* Translate IPv4 header to IPv6 */
void trans_header_4to6(const struct iphdr* iphdr, struct ip6_hdr* ip6hdr, uint16_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix, bool dec_ttl);
/* Translate IPv4 payload to IPv6 */
int trans_payload_4to6(const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr,
    char* payload, size_t payload_len);
/* Translate IPv6 header to IPv4 */
int trans_header_6to4(const struct ip6_hdr* ip6hdr, const struct ip6_frag* ip6frag,
    struct iphdr* iphdr, uint16_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix, bool dec_ttl);
/* Translate IPv6 payload to IPv4 */
int trans_payload_6to4(const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr,
    char* payload, size_t payload_len);
