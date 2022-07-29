#include "roku.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/route.h>

#include "log.h"
#include "tun.h"
#include "clat.h"
#include "addr.h"

#define STR_(x) #x
#define STR(x) STR_(x)

static const char USAGE_TEXT[] = "Usage: roku [OPTIONS] <NAT64 PREFIX>";
static const char BADOPT_TEXT[] = "Try 'roku -h' for more information.";
static const char GUIDE_TEXT[] =
    "Get IPv4 connectivity on IPv6-only hosts via 464XLAT\n"
    "Example: roku -r 64:ff9b::\n\n"
    "Options:\n"
    "  -i name   : Interface name [" DEFAULT_IFNAME "]\n"
    "  -4 ip     : IPv4 address [" DEFAULT_IP "]\n"
    "  -g ip     : IPv4 gateway [" DEFAULT_GW "]\n"
    "  -6 prefix : IPv6 CLAT prefix [" DEFAULT_IP6_PREFIX "]\n"
    "  -m mtu    : MTU [" STR(DEFAULT_MTU) "]\n"
    "  -r        : Add default route\n"
    "  -h        : Display this message";

static const char BADIP_FMT_TEXT[] = "'%s' is not a valid IPv4 address.";
static const char BADPREFIX_FMT_TEXT[] = "'%s' is not a valid IPv6 /96 prefix.";

void init(char *gateway, char *ip, char *ip6_prefix, char *nat64_prefix, char *ifname, int mtu);
int create_tun();
void handle_signal(int signum);

struct roku_config roku_cfg;

int main(int argc, char **argv)
{
    char *ip = DEFAULT_IP;
    char *gateway = DEFAULT_GW;
    char *ip6_prefix = DEFAULT_IP6_PREFIX;
    char *ifname = DEFAULT_IFNAME;
    char *nat64_prefix = NULL;
    int mtu = DEFAULT_MTU;

    opterr = 0;

    for (char c; (c = getopt(argc, argv, "i:4:g:6:m:rh")) != -1;)
    {
        switch (c)
        {
        case 'i':
            ifname = optarg;
            break;
        case 'g':
            gateway = optarg;
            break;
        case '4':
            ip = optarg;
            break;
        case '6':
            ip6_prefix = optarg;
            break;
        case 'm':
            mtu = atol(optarg);
            if (mtu < IF_MIN_MTU)
            {
                mtu = IF_MIN_MTU;
            }
            if (mtu > IF_MAX_MTU)
            {
                mtu = IF_MAX_MTU;
            }
            break;
        case 'r':
            roku_cfg.add_route = true;
            break;
        case 'h':
            printf("%s\n%s\n", USAGE_TEXT, GUIDE_TEXT);
            return EXIT_SUCCESS;
        case '?':
            if (optopt == 'i' || optopt == 'g' || optopt == '4' || optopt == '6')
            {
                fprintf(stderr, "Option -%c requires an argument.\n%s\n", optopt, BADOPT_TEXT);
            }
            else
            {
                fprintf(stderr, "Unknown option '-%c'.\n%s\n", optopt, BADOPT_TEXT);
            }
            return EXIT_FAILURE;
        default:
            abort();
        }
    }

    if (argc - optind != 1)
    {
        fprintf(stderr, "%s\n%s\n", USAGE_TEXT, BADOPT_TEXT);
        return EXIT_FAILURE;
    }
    nat64_prefix = argv[optind];

    init(gateway, ip, ip6_prefix, nat64_prefix, ifname, mtu);

    for (;;)
    {
        char in_packet[BUF_SIZE];
        int size;
        int ver;

        size = read(roku_cfg.tunfd, in_packet, sizeof(in_packet));
        if (size < 0)
            die("Failed to read from TUN device");

        ver = in_packet[0] >> 4;

        if (ver == 4)
        {
            if (clat_4to6(in_packet, size) < 0)
                die("Fatal error occured while translating IPv4 packet");
        }
        else if (ver == 6)
        {
            if (clat_6to4(in_packet, size) < 0)
                die("Fatal error occured while translating IPv6 packet");
        }
        else
        {
            log_warn("Dropping IP packet version %d", ver);
        }
    }

    return EXIT_FAILURE;
}

void init(char *gateway, char *ip, char *ip6_prefix, char *nat64_prefix, char *ifname, int mtu)
{
    if (!inet_pton(AF_INET, gateway, &roku_cfg.gateway))
    {
        die(BADIP_FMT_TEXT, gateway);
    }
    if (!inet_pton(AF_INET, ip, &roku_cfg.ip))
    {
        die(BADIP_FMT_TEXT, ip);
    }
    if (!inet_pton(AF_INET6, ip6_prefix, &roku_cfg.src_prefix) || !ADDR_VALID_PREFIX(roku_cfg.src_prefix))
    {
        die(BADPREFIX_FMT_TEXT, ip6_prefix);
    }
    if (!inet_pton(AF_INET6, nat64_prefix, &roku_cfg.dst_prefix) || !ADDR_VALID_PREFIX(roku_cfg.dst_prefix))
    {
        die(BADPREFIX_FMT_TEXT, nat64_prefix);
    }

    roku_cfg.gateway6 = roku_cfg.src_prefix;
    roku_cfg.gateway6.s6_addr32[3] = roku_cfg.gateway;

    strncpy(roku_cfg.ifname, ifname, sizeof(roku_cfg.ifname) - 1);
    roku_cfg.ifname[sizeof(roku_cfg.ifname) - 1] = 0;

    roku_cfg.mtu = mtu;

    roku_cfg.tunfd = create_tun();
    if (roku_cfg.tunfd < 0)
        die("TUN creation failed. Not enough privileges?");

    log_info("Interface: %s", roku_cfg.ifname);
    log_info("MTU: %d", roku_cfg.mtu);
    log_info("IPv4: %s", ip);
    log_info("Gateway: %s", gateway);
    log_info("Client IPv6 prefix: %s", ip6_prefix);
    log_info("NAT64 prefix: %s", nat64_prefix);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
}

int create_tun()
{
    int ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl_fd < 0)
    {
        log_error("Failed to create AF_INET socket");

        return -1;
    }

    int ioctl6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (ioctl6_fd < 0)
    {
        log_error("Failed to create AF_INET6 socket");

        close(ioctl_fd);
        return -1;
    }

    int tunfd = tun_new(roku_cfg.ifname);
    if (tunfd < 0)
    {
        log_error("Failed to create new TUN interface");

        close(ioctl_fd);
        close(ioctl6_fd);
        return -1;
    }

    if (!tun_set_ip(ioctl_fd, roku_cfg.ifname, roku_cfg.ip, 0xffffffff) ||
        !tun_set_ip6(ioctl6_fd, roku_cfg.ifname, &roku_cfg.gateway6, 96) ||
        !tun_set_dest_ip(ioctl_fd, roku_cfg.ifname, roku_cfg.gateway) ||
        !tun_set_mtu(ioctl_fd, roku_cfg.ifname, roku_cfg.mtu) ||
        !tun_up(ioctl_fd, roku_cfg.ifname))
    {
        log_error("Failed to configure TUN interface");

        close(tunfd);
        close(ioctl_fd);
        close(ioctl6_fd);
        return -1;
    }

    if (roku_cfg.add_route)
    {
        tun_set_route(roku_cfg.ifname, roku_cfg.gateway, ROUTE_METRIC, ROUTE_MTU, &roku_cfg.route);
        if (!tun_add_route(ioctl_fd, &roku_cfg.route))
        {
            log_warn("Failed to add route");
            roku_cfg.add_route = false;
        }
    }

    close(ioctl_fd);
    close(ioctl6_fd);
    return tunfd;
}

void handle_signal(int signum)
{
    log_info("Shutting down.");
    if (roku_cfg.add_route)
    {
        int ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (ioctl_fd < 0 || !tun_del_route(ioctl_fd, &roku_cfg.route))
        {
            log_warn("Failed to remove route");
        }
        close(ioctl_fd);
    }
    close(roku_cfg.tunfd);
    exit(EXIT_SUCCESS);
}
