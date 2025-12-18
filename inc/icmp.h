#pragma once

#include <stddef.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/* Additional PARAMPROB codes */
#define ICMP_PARAMPROB_PTRERR 0
#define ICMP_PARAMPROB_BADLEN 2

enum {
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

enum {
    IP6_POINTER_VER = 0,
    IP6_POINTER_FLOW = 1,
    IP6_POINTER_PLEN = 4,
    IP6_POINTER_NXT = 6,
    IP6_POINTER_HLIM = 7,
    IP6_POINTER_SRC = 8,
    IP6_POINTER_DST = 24
};

/* Send an ICMP error */
ssize_t icmp_send_error(int tunfd, int type, int code, in_addr_t src, in_addr_t dst,
    char* payload, size_t payload_len, int data);
/* Send an ICMPv6 error */
ssize_t icmp6_send_error(int tunfd, int type, int code, struct in6_addr* src, struct in6_addr* dst,
    char* payload, size_t payload_len, int data);
/* Translate ICMPv4 packet to ICMPv6 */
ssize_t icmp_write_4to6(int tunfd, int tun_mtu, const struct iphdr* iphdr,
    char* payload, size_t payload_len,
    struct in6_addr* src_prefix, struct in6_addr* dst_prefix);
/* Translate ICMPv6 packet to ICMPv4*/
ssize_t icmp_write_6to4(int tunfd, int tun_mtu, const struct ip6_hdr* ip6hdr,
    char* payload, size_t payload_len,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix);
