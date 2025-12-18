#pragma once

#include <stddef.h>

#include <sys/types.h>

#include <netinet/in.h>

typedef struct clat_params {
    int tunfd;
    int if_mtu;
    in_addr_t if_ip;
    in_addr_t if_gw;
    struct in6_addr if_gw6;
    struct in6_addr src_prefix;
    struct in6_addr dst_prefix;
} clat_params_t;

/* Translate IPv4 packet to IPv6 and send on TUN */
ssize_t clat_packet_4to6(clat_params_t* params, char* packet, size_t len);
/* Translate IPv6 packet to IPv4 and send on TUN */
ssize_t clat_packet_6to4(clat_params_t* params, char* packet, size_t len);
