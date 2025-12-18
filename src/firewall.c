#include "firewall.h"

#include <stdio.h>
#include <alloca.h>

#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <nftables/libnftables.h>

#include "log.h"
#include "addr.h"

#define PRIORITY_DELTA "- 10"

#define ROKU_NAT_TABLE_PREFIX "roku-"
#define ROKU_FWD_TABLE_PREFIX "roku-fwd-"

#define NFT_DEL_CMD_SIZE 42 /* delete table... + IF_NAMESIZE */

static const char NFT_CMD_ADD_TEMPLATE[] = "create table inet " ROKU_NAT_TABLE_PREFIX "%1$s;"
                                           "add chain inet " ROKU_NAT_TABLE_PREFIX "%1$s postrouting { type nat hook postrouting priority srcnat " PRIORITY_DELTA "; policy accept; };"
                                           "add rule inet " ROKU_NAT_TABLE_PREFIX "%1$s postrouting ip6 saddr %2$s/96 oifname != \"%1$s\" counter masquerade;"
                                           "add chain inet " ROKU_NAT_TABLE_PREFIX "%1$s forward { type filter hook forward priority filter " PRIORITY_DELTA "; policy accept; };"
                                           "add rule inet " ROKU_NAT_TABLE_PREFIX "%1$s forward iifname %1$s counter accept;";

static const char NFT_DEL_CMD[] = "delete table inet " ROKU_NAT_TABLE_PREFIX "%s";

int firewall_add_rules(const struct in6_addr* src_prefix, const char* iface)
{
    char src_prefix_str[INET6_ADDRSTRLEN];

    struct nft_ctx* nft;
    char* cmd;
    int cmd_buf_len;

    if (!addr_prefix_valid(src_prefix)
        || !inet_ntop(AF_INET6, src_prefix, src_prefix_str, sizeof(src_prefix_str))) {
        log_e("Invalid source prefix");
        return 1;
    }

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        log_e("Failed to allocate NFT context");
        return 1;
    }
    if (nft_ctx_buffer_error(nft) != 0) {
        log_e("nft_ctx_buffer_error() failed");
        goto err_free_ctx;
    }

    cmd_buf_len = snprintf(NULL, 0, NFT_CMD_ADD_TEMPLATE, iface, src_prefix_str) + 1;
    cmd = alloca(cmd_buf_len);
    if (snprintf(cmd, cmd_buf_len, NFT_CMD_ADD_TEMPLATE, iface, src_prefix_str) != cmd_buf_len - 1) {
        log_e("Failed to generate NFT command");
        goto err_free_ctx;
    }

    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        log_e("Failed to modify firewall rules:\n%s", nft_ctx_get_error_buffer(nft));
        goto err_free_ctx;
    }

    nft_ctx_free(nft);
    return 0;

err_free_ctx:
    nft_ctx_free(nft);

    return 1;
}

int firewall_del_rules(const char* iface)
{
    struct nft_ctx* nft;
    char cmd[NFT_DEL_CMD_SIZE];

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        log_e("Failed to allocate NFT context");
        return 1;
    }
    if (nft_ctx_buffer_error(nft) != 0) {
        log_e("nft_ctx_buffer_error() failed");
        goto err_free_ctx;
    }

    if (snprintf(cmd, sizeof(cmd), NFT_DEL_CMD, iface) >= sizeof(cmd)) {
        log_e("NFT command exceeds buffer size");
        goto err_free_ctx;
    }
    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        if (errno != ENOENT) {
            log_e("Failed to delete a table :\n%s", nft_ctx_get_error_buffer(nft));
        }
    }

    nft_ctx_free(nft);
    return 0;

err_free_ctx:
    nft_ctx_free(nft);

    return 1;
}