#include "tun.h"

#include <stdbool.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/route.h>

#include <linux/if_tun.h>
#include <linux/ipv6.h>

#define IFNAMSIZ_NULL (IFNAMSIZ - 1)

static const char TUN_DEV[] = "/dev/net/tun";

int tun_new(char *name)
{
    int tunfd = open(TUN_DEV, O_RDWR);
    if (tunfd < 0)
    {
        return tunfd;
    }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ_NULL);

    if (ioctl(tunfd, TUNSETIFF, &ifr) < 0)
    {
        close(tunfd);
        return -1;
    }

    strncpy(name, ifr.ifr_name, IFNAMSIZ);
    return tunfd;
}

bool tun_set_ip(int sockfd, const char *ifname, in_addr_t ip, in_addr_t gateway)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ_NULL);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;

    addr->sin_addr.s_addr = ip;
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0)
    {
        return false;
    }

    addr->sin_addr.s_addr = gateway;
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0)
    {
        return false;
    }

    return true;
}

bool tun_set_dest_ip(int sockfd, const char *ifname, in_addr_t ip)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ_NULL);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;

    return (ioctl(sockfd, SIOCSIFDSTADDR, &ifr) == 0);
}

bool tun_set_ip6(int sockfd, const char *ifname, struct in6_addr *ip6, int prefix)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ_NULL);

    if (ioctl(sockfd, SIOGIFINDEX, &ifr) < 0)
    {
        return false;
    }

    struct in6_ifreq in6_ifr = {0};
    in6_ifr.ifr6_ifindex = ifr.ifr_ifindex;
    in6_ifr.ifr6_prefixlen = prefix;
    in6_ifr.ifr6_addr = *ip6;

    if (ioctl(sockfd, SIOCSIFADDR, &in6_ifr) < 0)
    {
        return false;
    }

    return true;
}

bool tun_up(int sockfd, const char *ifname)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ_NULL);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        return false;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
    {
        return false;
    }

    return true;
}

int tun_get_mtu(int sockfd, const char *ifname)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ_NULL);

    if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0)
    {
        return -1;
    }

    return ifr.ifr_mtu;
}

bool tun_set_mtu(int sockfd, const char *ifname, int mtu)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ_NULL);
    ifr.ifr_mtu = mtu;

    return (ioctl(sockfd, SIOCSIFMTU, &ifr) == 0);
}

void tun_set_route(char *ifname, in_addr_t ip, int metric, int mtu, struct rtentry *route)
{
    memset(route, 0, sizeof(struct rtentry));

    struct sockaddr_in *addr = (struct sockaddr_in *)&route->rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;

    addr = (struct sockaddr_in *)&route->rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in *)&route->rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route->rt_dev = ifname;
    route->rt_flags = RTF_UP | RTF_GATEWAY | RTF_MTU;
    route->rt_metric = metric + 1;
    route->rt_mtu = mtu;
}

bool tun_add_route(int sockfd, struct rtentry *route)
{
    return (ioctl(sockfd, SIOCADDRT, route) >= 0);
}

bool tun_del_route(int sockfd, struct rtentry *route)
{
    return (ioctl(sockfd, SIOCDELRT, route) >= 0);
}