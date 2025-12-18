#define _DEFAULT_SOURCE

#include "addr.h"

#include <stdbool.h>
#include <threads.h>

#include <netinet/in.h>

#include <arpa/inet.h>

bool addr_prefix_match(const struct in6_addr* a, const struct in6_addr* b)
{
    return (a->s6_addr32[0] == b->s6_addr32[0] && a->s6_addr32[1] == b->s6_addr32[1]
        && a->s6_addr32[2] == b->s6_addr32[2]);
}

bool addr_prefix_valid(const struct in6_addr* addr)
{
    return (addr->s6_addr32[3] == 0);
}

int addr_map_6to4(const struct in6_addr* ip6, in_addr_t* ip,
    const struct in6_addr* src_prefix, const struct in6_addr* dst_prefix)
{
    /* TODO: support dynamic mapping for directly untranslatable IPv6 addresses */

    if (addr_prefix_match(ip6, src_prefix) || addr_prefix_match(ip6, dst_prefix)) {
        *ip = ip6->s6_addr32[3];
        return 0;
    }
    return 1;
}

void addr_map_4to6(in_addr_t ip, struct in6_addr* ip6, const struct in6_addr* prefix)
{

    *ip6 = *prefix;
    ip6->s6_addr32[3] = ip;
}

bool addr_is_private(in_addr_t ip)
{
    // 0.0.0.0/8 | Private
    if ((ip & htonl(0xff000000)) == 0) {
        return true;
    }
    // 10.0.0.0/8 | Private
    if ((ip & htonl(0xff000000)) == htonl(0x0a000000)) {
        return true;
    }
    // 100.64.0.0/10 | Shared
    if ((ip & htonl(0xffc00000)) == htonl(0x64400000)) {
        return true;
    }
    //  127.0.0.0/8 | Host
    if ((ip & htonl(0xff000000)) == htonl(0x7f000000)) {
        return true;
    }
    // 169.254.0.0/16 | Link-local
    if ((ip & htonl(0xffff0000)) == htonl(0xa9fe0000)) {
        return true;
    }
    // 172.16.0.0/12 | Private
    if ((ip & htonl(0xfff00000)) == htonl(0xac100000)) {
        return true;
    }
    // 192.0.0.0/24 | Private
    if ((ip & htonl(0xffffff00)) == htonl(0xc0000000)) {
        return true;
    }
    // 192.0.2.0/24 | TEST-NET-1
    if ((ip & htonl(0xffffff00)) == htonl(0xc0000200)) {
        return true;
    }
    // 192.88.99.0/24 | Reserved (6to4)
    if ((ip & htonl(0xffffff00)) == htonl(0xc0586300)) {
        return true;
    }
    // 192.168.0.0/16 | Private
    if ((ip & htonl(0xffff0000)) == htonl(0xc0a80000)) {
        return true;
    }
    // 198.18.0.0/15 | Private
    if ((ip & htonl(0xfffe0000)) == htonl(0xc6120000)) {
        return true;
    }
    // 198.51.100.0/24 | TEST-NET-2
    if ((ip & htonl(0xffffff00)) == htonl(0xc6336400)) {
        return true;
    }
    // 203.0.113.0/24 | TEST-NET-3
    if ((ip & htonl(0xffffff00)) == htonl(0xcb007100)) {
        return true;
    }
    // 224.0.0.0/4 | Multicast
    if ((ip & htonl(0xf0000000)) == htonl(0xe0000000)) {
        return true;
    }
    // 240.0.0.0 | Reserved (Class D)
    if ((ip & htonl(0xf0000000)) == htonl(0xf0000000)) {
        return true;
    }
    // 255.255.255.255 | Broadcast
    if (ip == 0xffffffff) {
        return true;
    }
    return false;
}

const char* addr_str_v4(in_addr_t ip)
{
    thread_local static char str[INET_ADDRSTRLEN];

    return inet_ntop(AF_INET, &ip, str, sizeof(str));
}

const char* addr_str_v6(const struct in6_addr* ip6)
{
    thread_local static char str[INET6_ADDRSTRLEN];

    return inet_ntop(AF_INET6, ip6, str, sizeof(str));
}