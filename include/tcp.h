/* tcp header - 20 bytes minimum, up to 60 with options (same variable-length
 * idea as ip, driven by the data offset field instead of ihl).
 */
#ifndef TCP_H
#define TCP_H

#include <stddef.h>
#include <stdint.h>

#define TCP_FLAG_FIN 0x01u
#define TCP_FLAG_SYN 0x02u
#define TCP_FLAG_RST 0x04u
#define TCP_FLAG_PSH 0x08u
#define TCP_FLAG_ACK 0x10u
#define TCP_FLAG_URG 0x20u

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;    /* header length in 32-bit words, 5-15 */
    uint8_t flags;
    uint16_t window_size;
    size_t header_len;      /* data_offset * 4 in bytes - where the payload starts */
} tcp_header_t;

/* parses a tcp header starting at buf. returns 0 on success, -1 if len is
 * too short for the declared header length. */
int tcp_parse(const unsigned char *buf, size_t len, tcp_header_t *out);

/* formats the set flags as e.g. "SYN,ACK" into out, which must be at least
 * 32 bytes. writes "-" if no flags are set. */
void tcp_format_flags(uint8_t flags, char *out);

#endif
