#ifndef ROKU_CLAT_H
#define ROKU_CLAT_H

#include <netinet/in.h>

int clat_4to6(char *ip_packet, int packet_size);
int clat_6to4(char *ip6_packet, int packet_length);

#endif