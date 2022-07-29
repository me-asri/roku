#ifndef ADDR_H
#define ADDR_H

#include <stdbool.h>
#include <netinet/in.h>

#define ADDR_MATCH_PREFIX(a, b) (a.s6_addr32[0] == b.s6_addr32[0] && a.s6_addr32[1] == b.s6_addr32[1])
#define ADDR_VALID_PREFIX(a) (a.s6_addr32[3] == 0)

bool addr_6to4(struct in6_addr *ip6, in_addr_t *ip, bool pseudo);
void addr_4to6(in_addr_t ip, struct in6_addr *ip6, struct in6_addr *prefix);
bool addr_validate(in_addr_t ip);

#endif