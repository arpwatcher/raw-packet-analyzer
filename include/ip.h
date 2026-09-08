/* ipv4 header - 20 bytes minimum, up to 60 with options. the header
 * length is variable (encoded in the ihl field), which is the classic
 * gotcha compared to the fixed-size ethernet header.
 */
#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

typedef struct {
    uint8_t version;
    uint8_t ihl;            /* header length in 32-bit words, 5-15 */
    uint16_t total_length;
    uint8_t ttl;
    uint8_t protocol;
    uint32_t src_ip;        /* host byte order - use ip_format_addr to print */
    uint32_t dst_ip;
    size_t header_len;      /* ihl * 4 in bytes - where the payload starts */
} ip_header_t;

/* parses an ipv4 header starting at buf. returns 0 on success, -1 if the
 * version isn't 4 or len is too short for the declared header length. */
int ip_parse(const unsigned char *buf, size_t len, ip_header_t *out);

/* formats an ip address (host byte order uint32) as "a.b.c.d" into out,
 * which must be at least 16 bytes. */
void ip_format_addr(uint32_t addr, char *out);

#endif
