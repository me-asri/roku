#define _GNU_SOURCE

#include "checksum.h"

#include <stdint.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

static void ip_checksum_update(uint32_t* sum, const void* data, size_t len, uint8_t* leftover);
static uint16_t ip_checksum_finish(uint32_t sum, uint8_t leftover);

uint16_t ip_checksum(const void* data, int length)
{
    uint32_t sum = 0;
    uint8_t leftover = 0;

    ip_checksum_update(&sum, data, length, &leftover);
    return ip_checksum_finish(sum, leftover);
}

uint16_t ip_checksum_4to6(uint16_t chksum, const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr)
{
    uint32_t sum;
    int i;

    sum = ntohs(~chksum);
    sum += ntohs(~iphdr->saddr >> 16) + ntohs(~iphdr->saddr & 0xffff);
    sum += ntohs(~iphdr->daddr >> 16) + ntohs(~iphdr->daddr & 0xffff);

    for (i = 0; i < 8; i++) {
        sum += ntohs(ip6hdr->ip6_src.s6_addr16[i]);
        sum += ntohs(ip6hdr->ip6_dst.s6_addr16[i]);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~htons(sum);
}

uint16_t ip_checksum_6to4(uint16_t chksum, const struct iphdr* iphdr, const struct ip6_hdr* ip6hdr)
{
    uint32_t sum;
    int i;

    sum = ntohs(~chksum);
    for (i = 0; i < 8; i++) {
        sum += ntohs(~ip6hdr->ip6_src.s6_addr16[i]);
        sum += ntohs(~ip6hdr->ip6_dst.s6_addr16[i]);
    }

    sum += ntohs(iphdr->saddr >> 16) + ntohs(iphdr->saddr & 0xffff);
    sum += ntohs(iphdr->daddr >> 16) + ntohs(iphdr->daddr & 0xffff);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~htons(sum);
}

uint16_t ip_checksum_add(uint16_t a, uint16_t b)
{
    uint32_t sum = (uint16_t)~a + (uint16_t)~b;
    return ~((sum >> 16) + (sum & 0xffff));
}

uint16_t ip6_ph_checksum(const struct ip6_hdr* ip6hdr, uint16_t payload_len, uint8_t proto)
{
    uint32_t sum = 0;
    uint8_t leftover = 0;

    uint32_t plen = htonl(payload_len);
    uint32_t nexthdr = htonl(proto);

    ip_checksum_update(&sum, &ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src), &leftover);
    ip_checksum_update(&sum, &ip6hdr->ip6_dst, sizeof(ip6hdr->ip6_dst), &leftover);
    ip_checksum_update(&sum, &plen, sizeof(plen), &leftover);
    ip_checksum_update(&sum, &nexthdr, sizeof(nexthdr), &leftover);
    return ip_checksum_finish(sum, leftover);
}

void ip_checksum_update(uint32_t* sum, const void* data, size_t len, uint8_t* leftover)
{
    const uint8_t* ptr = data;

    uint16_t word;
    uint16_t* word_ptr;
    size_t word_len;

    if (len == 0) {
        return;
    }

    if (*leftover) {
        word = (ptr[0] << 8) | *leftover;
        *sum += word;

        ptr++;
        len--;

        *leftover = 0;
    }

    word_len = len / 2;
    word_ptr = (uint16_t*)ptr;
    while (word_len > 0) {
        *sum += *word_ptr++;
        word_len--;
    }

    if (len % 2) {
        *leftover = *(const uint8_t*)word_ptr;
    }
}

uint16_t ip_checksum_finish(uint32_t sum, uint8_t leftover)
{
    sum += leftover;

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}