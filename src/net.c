#define _DEFAULT_SOURCE

#include "net.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if_tun.h>
#include <linux/ipv6.h>

#include "log.h"
#include "utils.h"

static const char SYSCTL_IPV6_FORWARDING[] = "/proc/sys/net/ipv6/conf/all/forwarding";

int net_if_set_ip(const char* ifname, in_addr_t ip, in_addr_t gateway)
{
    int sockfd;

    struct ifreq ifr = { 0 };
    struct sockaddr_in* addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return 1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        elog_e("ioctl(SIOCSIFADDR) failed");
        goto err_close_sock;
    }

    addr->sin_addr.s_addr = gateway;
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        elog_e("ioctl(SIOCSIFNETMASK) failed");
        goto err_close_sock;
    }

    close(sockfd);
    return 0;

err_close_sock:
    close(sockfd);

    return 1;
}

int net_if_set_ip6(const char* ifname, struct in6_addr* ip6, unsigned int prefix)
{
    int sockfd;

    struct ifreq ifr = { 0 };
    struct in6_ifreq in6_ifr = { 0 };

    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return 1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(sockfd, SIOGIFINDEX, &ifr) < 0) {
        elog_e("ioctl(SIOGIFINDEX) failed");
        goto err_close_sock;
    }

    in6_ifr.ifr6_ifindex = ifr.ifr_ifindex;
    in6_ifr.ifr6_prefixlen = prefix;
    in6_ifr.ifr6_addr = *ip6;

    if (ioctl(sockfd, SIOCSIFADDR, &in6_ifr) < 0) {
        elog_e("ioctl(SIOCSIFADDR) failed");
        goto err_close_sock;
    }

    close(sockfd);
    return 0;

err_close_sock:
    close(sockfd);

    return 1;
}

int net_if_set_dest_ip(const char* ifname, in_addr_t ip)
{
    int sockfd;

    struct ifreq ifr = { 0 };
    struct sockaddr_in* addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return 1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    addr = (struct sockaddr_in*)&ifr.ifr_dstaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;

    if (ioctl(sockfd, SIOCSIFDSTADDR, &ifr) < 0) {
        elog_e("ioctl(SIOCSIFDSTADDR) failed");

        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

int net_if_get_mtu(const char* ifname)
{
    int sockfd;
    struct ifreq ifr = { 0 };

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
        elog_e("ioctl(SIOCGIFMTU) failed");

        close(sockfd);
        return -1;
    }

    close(sockfd);
    return ifr.ifr_mtu;
}

int net_if_set_mtu(const char* ifname, int mtu)
{
    int sockfd;
    struct ifreq ifr = { 0 };

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return 1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    ifr.ifr_mtu = mtu;

    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        elog_e("ioctl(SIOCSIFMTU) failed");

        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

void net_if_set_route(char* ifname, in_addr_t ip, int metric, int mtu, struct rtentry* route)
{
    struct sockaddr_in* addr;

    memset(route, 0, sizeof(struct rtentry));

    addr = (struct sockaddr_in*)&route->rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;

    addr = (struct sockaddr_in*)&route->rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in*)&route->rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route->rt_dev = ifname;
    route->rt_flags = RTF_UP | RTF_GATEWAY | RTF_MTU;
    route->rt_metric = metric + 1;
    route->rt_mtu = mtu;
}

int net_if_add_route(struct rtentry* route)
{
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return 1;
    }

    if (ioctl(sockfd, SIOCADDRT, route) < 0) {
        elog_e("ioctl(SIOCADDRT) failed");

        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

int net_if_del_route(struct rtentry* route)
{
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        elog_e("Failed to create socket for ioctl");
        return 1;
    }

    if (ioctl(sockfd, SIOCDELRT, route) < 0) {
        elog_e("ioctl(SIOCDELRT) failed");

        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

int net_set_ipv6_fwd(int state, int* prev_state)
{
    FILE* f;
    char buf[16];

    f = fopen(SYSCTL_IPV6_FORWARDING, "r+");
    if (!f) {
        elog_e("Failed to open %s", SYSCTL_IPV6_FORWARDING);
        return 1;
    }

    if (prev_state) {
        if (!fgets(buf, sizeof(buf), f)) {
            elog_e("Failed to read previous state");
            goto err_close_f;
        }
        buf[strcspn(buf, "\n")] = '\0';
        if (parse_int(buf, prev_state) != 0) {
            log_e("Failed to parse previous state");
            goto err_close_f;
        }

        fseek(f, 0, SEEK_SET);
    }

    if (fprintf(f, "%d\n", state) < 0) {
        elog_e("Failed to set state");
        goto err_close_f;
    }

    fflush(f);
    fclose(f);
    return 0;
err_close_f:
    fclose(f);

    return 1;
}