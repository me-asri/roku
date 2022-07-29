#ifndef ROKU_ICMP_H
#define ROKU_ICMP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

// Maximum ICMP error data length so total packet size doesn't exceed 576 (Min IPv4 MTU)
#define ICMP_ERROR_LENGTH_MAX 548
// Maximum ICMPv6 error data length so total packet size doesn't exceed 1280 (Min IPv6 MTU)
#define ICMP6_ERROR_LENGTH_MAX 1232

// Additional PARAMPROB codes
#define ICMP_PARAMPROB_PTRERR 0
#define ICMP_PARAMPROB_BADLEN 2

enum
{
    IP_POINTER_VER = 0,
    IP_POINTER_TOS = 1,
    IP_POINTER_TLEN_A = 2,
    IP_POINTER_TLEN_B = 3,
    IP_POINTER_IDENT_A = 4,
    IP_POINTER_IDENT_B = 5,
    IP_POINTER_FLAGS = 6,
    IP_POINTER_FRAG = 7,
    IP_POINTER_TTL = 8,
    IP_POINTER_PROTO = 9,
    IP_POINTER_CKSUM_A = 10,
    IP_POINTER_CKSUM_B = 11,
    IP_POINTER_SRC_A = 12,
    IP_POINTER_SRC_B = 15,
    IP_POINTER_DST_A = 16,
    IP_POINTER_DST_B = 19
};

enum
{
    IP6_POINTER_VER = 0,
    IP6_POINTER_FLOW = 1,
    IP6_POINTER_PLEN = 4,
    IP6_POINTER_NXT = 6,
    IP6_POINTER_HLIM = 7,
    IP6_POINTER_SRC = 8,
    IP6_POINTER_DST = 24
};

int icmp_send_error(int type, int code, in_addr_t src, in_addr_t dst, char *payload, int payload_length, int data);
int icmp6_send_error(int type, int code, struct in6_addr *src, struct in6_addr *dst, char *payload, int payload_length, int data);
int icmp_4to6(struct iphdr *ip_header, char *payload, int payload_length);
int icmp_6to4(struct ip6_hdr *ip6_header, char *payload, int payload_length);

#endif