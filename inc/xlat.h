#ifndef XLAT_H
#define XLAT_H

#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

// Minimum MTU
#define MTU_MIN 68
// Minimum MTU for IPv6
#define IPV6_MIN_MTU 1280
/* MTU difference between IPv4 and IPv6.
   There is a 20 byte difference between IPv6 and IPv4 header sizes.
   This does not account for IPv6 fragmentation header. */
#define MTU_DIFF 20

void xlat_header_4to6(struct iphdr *ip_header, struct ip6_hdr *ip6_header, int payload_length);
int xlat_payload_4to6(struct iphdr *ip_header, struct ip6_hdr *ip6_header, char *payload, int payload_length);
bool xlat_header_6to4(struct ip6_hdr *ip6_header, struct ip6_frag *ip6_fragment, struct iphdr *ip_header, int payload_length);
int xlat_payload_6to4(struct iphdr *ip_header, struct ip6_hdr *ip6_header, char *payload, int payload_length);

#endif