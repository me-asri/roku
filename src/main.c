#include <stddef.h>
#include <stdbool.h>

#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <net/route.h>
#include <sys/select.h>

#include "args.h"
#include "log.h"
#include "tun.h"
#include "net.h"
#include "trans.h"
#include "clat.h"
#include "firewall.h"
#include "sigfd.h"
#include "addr.h"

#define PACKET_BUFSIZE 65535
#define ROUTE_METRIC 2000

static int roku_run(args_t* args);
static int iface_setup(args_t* args, char ifname[IF_NAMESIZE], struct rtentry* route, int* ipfwd);
static int iface_destroy(args_t* args, char ifname[IF_NAMESIZE],
    struct rtentry* route, int ipfwd);

int main(int argc, char** argv)
{
    int ret;
    args_t args;

    ret = args_parse(&args, argc, argv);
    if (ret <= 0) {
        return ret;
    }
    log_init(args.log_level);

    return roku_run(&args);
}

int roku_run(args_t* args)
{
    int ret = 0;

    char ifname[IF_NAMESIZE];
    struct rtentry route;
    int ipfwd;

    char packet[PACKET_BUFSIZE];
    ssize_t nread;

    fd_set read_fds;
    int sigfd;
    int maxfd;

    sigfd = sigfd_setup(2, SIGTERM, SIGINT);
    if (sigfd < 0) {
        return 1;
    }

    args->clat.tunfd = iface_setup(args, ifname, &route, &ipfwd);
    if (args->clat.tunfd < 0) {
        sigfd_destroy(sigfd);
        return 1;
    }

    maxfd = ((sigfd > args->clat.tunfd) ? sigfd : args->clat.tunfd) + 1;

    log_i("Roku started on interface \"%s\" - NAT64 prefix: %s/96", ifname,
        addr_str_v6(&args->clat.dst_prefix));
    for (;;) {
        FD_ZERO(&read_fds);
        FD_SET(sigfd, &read_fds);
        FD_SET(args->clat.tunfd, &read_fds);

        if (select(maxfd, &read_fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }

            elog_e("select() failed");
            ret = 1;
            goto stop;
        }
        if (FD_ISSET(sigfd, &read_fds)) {
            log_i("Received signal %d, stopping...", sigfd_read(sigfd));
            goto stop;
        }
        if (FD_ISSET(args->clat.tunfd, &read_fds)) {
            nread = read(args->clat.tunfd, packet, sizeof(packet));
            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }

                elog_e("Failed read packet from TUN interface");
                ret = 1;
                goto stop;
            }

            switch (packet[0] >> 4) {
            case 4:
                if (clat_packet_4to6(&args->clat, packet, nread) < 0) {
                    log_e("Catastrophic failure during v4-to-v6 translation");
                    ret = 1;
                    goto stop;
                }
                break;
            case 6:
                if (clat_packet_6to4(&args->clat, packet, nread) < 0) {
                    log_e("Catastrophic failure during v6-to-v4 translation");
                    ret = 1;
                    goto stop;
                }
                break;
            default:
                log_w("Ignoring packet with invalid IP version %d", packet[0] >> 4);
                break;
            }
        }
    }

stop:
    if (iface_destroy(args, ifname, &route, ipfwd) != 0) {
        ret = 1;
    }

    sigfd_destroy(sigfd);

    return ret;
}

int iface_setup(args_t* args, char ifname[IF_NAMESIZE], struct rtentry* route, int* ipfwd)
{
    int tunfd;

    tunfd = tun_open(args->tun_name, ifname);
    if (tunfd < 0) {
        log_e("Failed to create TUN device");
        return -1;
    }

    if (net_if_set_ip(ifname, args->clat.if_ip, 0xffffffff) != 0) {
        log_e("Failed to set interface IP address");
        goto err_close_tun;
    }
    if (net_if_set_ip6(ifname, &args->clat.if_gw6, 96) != 0) {
        log_e("Failed to set interface IPv6 address");
        goto err_close_tun;
    }
    if (net_if_set_dest_ip(ifname, args->clat.if_gw) != 0) {
        log_e("Failed to set interface destination address");
        goto err_close_tun;
    }
    if (net_if_set_mtu(ifname, args->clat.if_mtu) != 0) {
        log_e("Failed to set interface MTU");
        goto err_close_tun;
    }

    if (tun_up(ifname) != 0) {
        log_e("Failed to bring up interface");
        goto err_close_tun;
    }

    if (args->add_route) {
        net_if_set_route(ifname, args->clat.if_gw,
            ROUTE_METRIC, args->clat.if_mtu - MTU_DIFF, route);
        if (net_if_add_route(route) != 0) {
            log_e("Failed to add IPv4 default route");
            goto err_close_tun;
        } else {
            log_i("Added IPv4 default route");
        }
    } else {
        log_w("Not adding IPv4 default route, you'll have to manually add one.");
    }
    if (args->add_fw_rules) {
        firewall_del_rules(ifname); /* Silently drop previous rules if any */

        if (firewall_add_rules(&args->clat.src_prefix, ifname) != 0) {
            log_e("Failed to add firewall rules");
            goto err_del_route;
        } else {
            log_i("Added firewall rules");
        }
    } else {
        log_w("Not adding firewall rules, you'll have to manually add them.");
    }
    if (args->enable_ip_fwd) {
        if (net_set_ipv6_fwd(1, ipfwd) != 0) {
            log_e("Failed to enable IPv6 forwarding");
            goto err_del_fw;
        } else {
            if (*ipfwd != 1) {
                log_i("Enabled IPv6 forwarding");
            } else {
                args->enable_ip_fwd = false;
            }
        }
    } else {
        log_w("Not enabling IPv6 forwarding, you'll have to manually enable it");
    }

    return tunfd;

err_del_fw:
    firewall_del_rules(ifname);

err_del_route:
    net_if_del_route(route);

err_close_tun:
    close(tunfd);

    return -1;
}

int iface_destroy(args_t* args, char ifname[IF_NAMESIZE], struct rtentry* route, int ipfwd)
{
    int ret = 0;

    if (args->add_route) {
        if (net_if_del_route(route) != 0) {
            log_w("Failed to remove IPv4 route");
            ret = 1;
        }
    }
    if (args->add_fw_rules) {
        if (firewall_del_rules(ifname) != 0) {
            log_w("Failed to delete firewall rules");
            ret = 1;
        }
    }
    if (args->enable_ip_fwd) {
        if (net_set_ipv6_fwd(ipfwd, NULL) != 0) {
            log_w("Failed to restore IPv6 forwarding state");
            ret = 1;
        }
    }

    if (close(args->clat.tunfd) != 0) {
        elog_w("Failed to close TUN file descriptor");
        ret = 1;
    }

    return ret;
}