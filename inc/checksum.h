#pragma once

#include <stdint.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/* Calculate IP checksum for given data */
uint16_t ip_checksum(const void* data, int length);
/* Convert IP checksum from IPv4 to IPv6 by incremental update */
uint16_t ip_checksum_4to6(uint16_t chksum, const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr);
/* Convert IP checksum from IPv6 to IPv4 by incremental update */
uint16_t ip_checksum_6to4(uint16_t chksum, const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr);
/* Add two IP checksums */
uint16_t ip_checksum_add(uint16_t a, uint16_t b);
/* Calculate IPv6 pseudo-header checksum */
uint16_t ip6_ph_checksum(const struct ip6_hdr* ip6hdr, uint16_t payload_len, uint8_t proto);
