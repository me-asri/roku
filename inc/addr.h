#pragma once

#include <stdbool.h>

#include <netinet/in.h>

/* Whether NAT64 prefix (/96) of two IPv6 addresses match */
bool addr_prefix_match(const struct in6_addr* a, const struct in6_addr* b);
/* Whether address is a valid NAT64 prefix */
bool addr_prefix_valid(const struct in6_addr* addr);
/* Map IPv6 address to IPv4 (if it's from a NAT64 prefix) */
int addr_map_6to4(const struct in6_addr* ip6, in_addr_t* ip,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);
/* Map IPv4 to IPv6 using the specified NAT64 prefix */
void addr_map_4to6(in_addr_t ip, struct in6_addr* ip6, const struct in6_addr* prefix);
/* Is an IP address private? */
bool addr_is_private(in_addr_t ip);
/* Get string representation of IPv4 address */
const char* addr_str_v4(in_addr_t ip);
/* Get string representation of IPv6 address */
const char* addr_str_v6(const struct in6_addr* ip6);
