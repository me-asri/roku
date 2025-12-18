#define _DEFAULT_SOURCE

#include "tun.h"

#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if_tun.h>

#include "log.h"

static const char TUN_DEV[] = "/dev/net/tun";

int tun_open(const char* preferred_name, char name[IF_NAMESIZE])
{
    struct ifreq ifr = { 0 };
    int tunfd;

    tunfd = open(TUN_DEV, O_RDWR);
    if (tunfd < 0) {
        elog_e("Failed to open %s", TUN_DEV);
        return -1;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, preferred_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(tunfd, TUNSETIFF, &ifr) < 0) {
        elog_e("ioctl(TUNSETIFF) failed");
        goto err_close_tun;
    }
    strncpy(name, ifr.ifr_name, IF_NAMESIZE - 1);
    name[IF_NAMESIZE - 1] = '\0';

    return tunfd;

err_close_tun:
    close(tunfd);

    return -1;
}

int tun_up(const char* ifname)
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

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        elog_e("ioctl(SIOCGIFFLAGS) failed");
        goto err_close_sock;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        elog_e("ioctl(SIOCSIFFLAGS) failed");
        goto err_close_sock;
    }

    close(sockfd);
    return 0;
err_close_sock:
    close(sockfd);

    return 1;
}
