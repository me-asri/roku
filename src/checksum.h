#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

uint16_t checksum(const void *data, int length);
uint16_t checksum_4to6(uint16_t chksum, struct iphdr *ip_header, struct ip6_hdr *ip6_header);
uint16_t checksum_6to4(uint16_t chksum, struct iphdr *ip_header, struct ip6_hdr *ip6_header);
uint16_t checksum_sum(uint16_t a, uint16_t b);
uint16_t checksum_pseudo6(struct ip6_hdr *ip6_header, uint32_t payload_length, uint8_t protocol);


#endif