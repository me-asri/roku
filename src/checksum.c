#include "checksum.h"

#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

static uint32_t checksum_add(uint32_t current, const void *data, int length)
{
    uint32_t sum = current;
    const uint16_t *cast = (uint16_t *)data;

    while (length > 1)
    {
        sum += *cast;
        cast++;
        length -= 2;
    }

    if (length)
    {
        sum += *(uint8_t *)cast;
    }

    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum > 0xffff)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return ~sum;
}

uint16_t checksum(const void *data, int length)
{
    return checksum_finish(checksum_add(0, data, length));
}

uint16_t checksum_4to6(uint16_t chksum, struct iphdr *ip_header, struct ip6_hdr *ip6_header)
{
    uint32_t sum = ntohs(~chksum);

    sum += ntohs(~ip_header->saddr >> 16) + ntohs(~ip_header->saddr & 0xffff);
    sum += ntohs(~ip_header->daddr >> 16) + ntohs(~ip_header->daddr & 0xffff);

    for (int i = 0; i < 8; i++)
    {
        sum += ntohs(ip6_header->ip6_src.s6_addr16[i]);
        sum += ntohs(ip6_header->ip6_dst.s6_addr16[i]);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~htons(sum);
}

uint16_t checksum_6to4(uint16_t chksum, struct iphdr *ip_header, struct ip6_hdr *ip6_header)
{
    uint32_t sum = ntohs(~chksum);

    for (int i = 0; i < 8; i++)
    {
        sum += ntohs(~ip6_header->ip6_src.s6_addr16[i]);
        sum += ntohs(~ip6_header->ip6_dst.s6_addr16[i]);
    }

    sum += ntohs(ip_header->saddr >> 16) + ntohs(ip_header->saddr & 0xffff);
    sum += ntohs(ip_header->daddr >> 16) + ntohs(ip_header->daddr & 0xffff);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~htons(sum);
}

uint16_t checksum_sum(uint16_t a, uint16_t b)
{
    uint32_t sum = (uint16_t)~a + (uint16_t)~b;
    return ~((sum >> 16) + (sum & 0xffff));
}

uint16_t checksum_pseudo6(struct ip6_hdr *ip6_header, uint32_t payload_length, uint8_t protocol)
{
    uint32_t sum = 0;

    uint32_t length = htonl(payload_length);
    uint32_t next = htonl(protocol);

    sum = checksum_add(sum, &ip6_header->ip6_src, sizeof(struct in6_addr));
    sum = checksum_add(sum, &ip6_header->ip6_dst, sizeof(struct in6_addr));
    sum = checksum_add(sum, &length, sizeof(length));
    sum = checksum_add(sum, &next, sizeof(next));

    return checksum_finish(sum);
}
