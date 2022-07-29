#ifndef ROKU_H
#define ROKU_H

#include <stdbool.h>
#include <netinet/in.h>
#include <net/route.h>

#define IF_MIN_MTU 1280
#define IF_MAX_MTU 65535
#define BUF_SIZE 65535

// IP addresses from the range defined in RFC 7335
#define DEFAULT_GW "192.0.0.1"
#define DEFAULT_IP "192.0.0.2"

#define DEFAULT_IP6_PREFIX "fd64:64:64::"

#define DEFAULT_IFNAME "roku"
#define DEFAULT_MTU 1500

#define ROUTE_METRIC 2000
#define ROUTE_MTU (roku_cfg.mtu - 20) // MTU - MTU_DIFF

struct roku_config
{
    char ifname[16];
    int tunfd;
    int mtu;
    in_addr_t ip, gateway;
    struct in6_addr src_prefix, dst_prefix, gateway6;
    bool add_route;
    struct rtentry route;
};

extern struct roku_config roku_cfg;

#endif