#ifndef ROKU_TUN_H
#define ROKU_TUN_H

#include <stdbool.h>
#include <netinet/in.h>
#include <net/route.h>

int tun_new(char *name);
bool tun_set_ip(int sockfd, const char *ifname, in_addr_t ip, in_addr_t gateway);
bool tun_set_dest_ip(int sockfd, const char *ifname, in_addr_t ip);
bool tun_set_ip6(int sockfd, const char *ifname, struct in6_addr *ip6, int prefix);
bool tun_up(int sockfd, const char *ifname);
int tun_get_mtu(int sockfd, const char *ifname);
bool tun_set_mtu(int sockfd, const char *ifname, int mtu);
void tun_set_route(char *ifname, in_addr_t ip, int metric, int mtu, struct rtentry *route);
bool tun_add_route(int sockfd, struct rtentry *route);
bool tun_del_route(int sockfd, struct rtentry *route);

#endif