/* ethernet II frame header - 14 bytes: dst mac, src mac, ethertype.
 * parsed by hand from raw bytes rather than casting a struct over the
 * buffer, to sidestep alignment and strict-aliasing pitfalls.
 */
#ifndef ETHERNET_H
#define ETHERNET_H

#include <stddef.h>
#include <stdint.h>

#define ETHERNET_HEADER_LEN 14
#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_ARP  0x0806u
#define ETHERTYPE_IPV6 0x86ddu

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;

/* parses the first ETHERNET_HEADER_LEN bytes of buf into *out.
 * returns 0 on success, -1 if len is too short. */
int ethernet_parse(const unsigned char *buf, size_t len, ethernet_header_t *out);

/* formats a mac address as "aa:bb:cc:dd:ee:ff" into out, which must be at
 * least 18 bytes. */
void ethernet_format_mac(const uint8_t mac[6], char *out);

#endif
