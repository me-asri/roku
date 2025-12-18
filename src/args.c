#define _DEFAULT_SOURCE

#include "args.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>

#include <unistd.h>
#include <libgen.h>

#include <arpa/inet.h>

#include "log.h"
#include "addr.h"
#include "utils.h"

#define DEFAULT_MTU 1500
#define MTU_MAX 65535
#define MTU_MIN 1280

static const char* DEFAULT_GW = "192.0.0.1"; /* RFC 7335 */
static const char* DEFAULT_IP = "192.0.0.2";
static const char* DEFAULT_SRC_PREFIX = "fd64::";
static const char* DEFAULT_DEST_PREFIX = "64:ff9b::";
static const char* DEFAULT_TUN_NAME = "roku";

static void print_usage(FILE* stream, const char* progname);
static void print_error(const char* progname, const char* fmt, ...);

int args_parse(args_t* args, int argc, char** argv)
{
    int c;

    args->tun_name = DEFAULT_TUN_NAME;
    args->log_level = LOG_INFO;
    args->add_route = true;
    args->add_fw_rules = true;
    args->enable_ip_fwd = true;

    args->clat.if_mtu = DEFAULT_MTU;
    inet_pton(AF_INET, DEFAULT_GW, &args->clat.if_gw);
    inet_pton(AF_INET, DEFAULT_IP, &args->clat.if_ip);
    inet_pton(AF_INET6, DEFAULT_SRC_PREFIX, &args->clat.src_prefix);
    inet_pton(AF_INET6, DEFAULT_DEST_PREFIX, &args->clat.dst_prefix);

    while ((c = getopt(argc, argv, "hI:i:g:s:d:m:RFWv")) != -1) {
        switch (c) {
        case 'h':
            print_usage(stdout, argv[0]);
            return 0;
        case 'I':
            args->tun_name = optarg;
            break;
        case 'i':
            if (inet_pton(AF_INET, optarg, &args->clat.if_ip) != 1) {
                print_error(argv[0], "invalid IPv4 address \"%s\"", optarg);
                return -1;
            }
            break;
        case 'g':
            if (inet_pton(AF_INET, optarg, &args->clat.if_gw) != 1) {
                print_error(argv[0], "invalid IPv4 gateway address \"%s\"", optarg);
                return -1;
            }
            break;
        case 's':
            if (inet_pton(AF_INET6, optarg, &args->clat.src_prefix) != 1
                || !addr_prefix_valid(&args->clat.src_prefix)) {
                print_error(argv[0], "invalid IPv6 source prefix \"%s\"", optarg);
                return -1;
            }
            break;
        case 'd':
            if (inet_pton(AF_INET6, optarg, &args->clat.dst_prefix) != 1
                || !addr_prefix_valid(&args->clat.dst_prefix)) {
                print_error(argv[0], "invalid IPv6 destination prefix \"%s\"", optarg);
                return -1;
            }
            break;
        case 'm':
            if (parse_int(optarg, &args->clat.if_mtu) != 0) {
                print_error(argv[0], "invalid MTU \"%s\"", optarg);
                return -1;
            }
            if (args->clat.if_mtu < MTU_MIN || args->clat.if_mtu > MTU_MAX) {
                print_error(argv[0], "MTU must be between %d and %d", MTU_MIN, MTU_MAX);
                return -1;
            }
            break;
        case 'R':
            args->add_route = false;
            break;
        case 'F':
            args->add_fw_rules = false;
            break;
        case 'W':
            args->enable_ip_fwd = false;
            break;
        case 'v':
            args->log_level = LOG_DEBUG;
            break;
        case '?':
            print_usage(stderr, argv[0]);
            return -1;
        default:
            abort();
        }
    }

    /* Derive IPv6 gateway from src prefix and v4 gateway*/
    args->clat.if_gw6 = args->clat.src_prefix;
    args->clat.if_gw6.s6_addr32[3] = args->clat.if_gw;

    return 1;
}

void print_usage(FILE* stream, const char* progname)
{
    static const char USAGE[] = "Usage: %1$s [OPTION...]\n"
                                "\n"
                                "Options:\n"
                                "   -I <Interface>    interface name (default: %2$s)\n"
                                "   -i <IP>           interface IPv4 address (default: %3$s)\n"
                                "   -g <IP>           interface gateway IPv4 address (default: %4$s)\n"
                                "   -s <IPv6 prefix>  CLAT IPv6 source prefix (default: %5$s/96)\n"
                                "   -d <IPv6 prefix>  CLAT IPv6 destination (NAT64) prefix (default: %6$s/96)\n"
                                "   -m <MTU>          interface MTU (default: %7$d)\n"
                                "   -R                do not add default IPv4 route\n"
                                "   -F                do not add firewall rules for NAT & forward\n"
                                "   -W                do not enable IPv6 forwarding\n"
                                "   -v                verbose logging\n"
                                "   -h                show this help message\n";

    fprintf(stream, USAGE, progname, DEFAULT_TUN_NAME, DEFAULT_IP, DEFAULT_GW, DEFAULT_SRC_PREFIX,
        DEFAULT_DEST_PREFIX, DEFAULT_MTU);
}

void print_error(const char* progname, const char* fmt, ...)
{
    va_list args;

    flockfile(stderr);

    fprintf(stderr, "%s: ", progname);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    print_usage(stderr, progname);

    funlockfile(stderr);
}
