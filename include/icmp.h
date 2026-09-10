/* icmp header - 8 bytes minimum (type, code, checksum, then 4 bytes whose
 * meaning depends on the type - for echo request/reply that's identifier
 * and sequence number, which is what most pings actually use).
 */
#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>
#include <stdint.h>

#define ICMP_HEADER_LEN 8

#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_TYPE_DEST_UNREACHABLE  3
#define ICMP_TYPE_ECHO_REQUEST      8
#define ICMP_TYPE_TIME_EXCEEDED     11

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;   /* only meaningful for echo request/reply */
    uint16_t sequence;     /* only meaningful for echo request/reply */
} icmp_header_t;

/* parses an icmp header starting at buf. returns 0 on success, -1 if len is
 * less than ICMP_HEADER_LEN. */
int icmp_parse(const unsigned char *buf, size_t len, icmp_header_t *out);

/* returns a short human-readable name for a (type, code) pair, e.g.
 * "echo request" or "dest unreachable (port)". falls back to a generic
 * "type N code M" string (in a static buffer - not reentrant) for
 * anything not specifically named. */
const char *icmp_type_name(uint8_t type, uint8_t code);

#endif
