/* udp header - always exactly 8 bytes, no options, no variable length. */
#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#define UDP_HEADER_LEN 8

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;    /* total length of udp header + payload, per rfc 768 */
} udp_header_t;

/* parses a udp header starting at buf. returns 0 on success, -1 if len is
 * less than UDP_HEADER_LEN. */
int udp_parse(const unsigned char *buf, size_t len, udp_header_t *out);

#endif
