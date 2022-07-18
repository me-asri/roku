#ifndef ISEKAI_H
#define ISEKAI_H

#include <stdbool.h>
#include <netinet/in.h>
#include <net/route.h>

#define IF_MIN_MTU 1280
#define IF_MAX_MTU 65535
#define BUF_SIZE 65535

#define DEFAULT_MTU 1500
#define DEFAULT_GW "10.6.4.1"
#define DEFAULT_IP "10.6.4.2"
#define DEFAULT_IP6_PREFIX "fd64:64:64::"
#define DEFAULT_IFNAME "roku"

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