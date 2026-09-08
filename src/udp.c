#include "udp.h"

int udp_parse(const unsigned char *buf, size_t len, udp_header_t *out) {
    if (len < UDP_HEADER_LEN) {
        return -1;
    }

    out->src_port = (uint16_t)((buf[0] << 8) | buf[1]);
    out->dst_port = (uint16_t)((buf[2] << 8) | buf[3]);
    out->length = (uint16_t)((buf[4] << 8) | buf[5]);

    return 0;
}
