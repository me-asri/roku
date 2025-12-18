#pragma once

#include <netinet/in.h>

/* Add masquerade and forward rules */
int firewall_add_rules(const struct in6_addr* src_prefix, const char* iface);
/* Remove masquerade and forward rules */
int firewall_del_rules(const char* iface);
