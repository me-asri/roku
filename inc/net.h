#pragma once

#include <netinet/in.h>

#include <net/route.h>

/* Set interface IP address */
int net_if_set_ip(const char* ifname, in_addr_t ip, in_addr_t gateway);
/* Set interface IPv6 address */
int net_if_set_ip6(const char* ifname, struct in6_addr* ip6, unsigned int prefix);
/* Set IPv4 destination address for P2P interface */
int net_if_set_dest_ip(const char* ifname, in_addr_t ip);

/* Get interface MTU */
int net_if_get_mtu(const char* ifname);
/* Set interface MTU */
int net_if_set_mtu(const char* ifname, int mtu);

/* Populate rtentry for IPv4 route */
void net_if_set_route(char* ifname, in_addr_t ip, int metric, int mtu, struct rtentry* route);
/* Add new route */
int net_if_add_route(struct rtentry* route);
/* Delete route */
int net_if_del_route(struct rtentry* route);

/* Set IPv6 forwarding state */
int net_set_ipv6_fwd(int state, int* prev_state);
