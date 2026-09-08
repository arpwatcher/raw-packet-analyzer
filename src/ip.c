#include "ip.h"
#include <stdio.h>

int ip_parse(const unsigned char *buf, size_t len, ip_header_t *out) {
    if (len < 20) {
        return -1;
    }

    out->version = (uint8_t)((buf[0] >> 4) & 0x0f);
    out->ihl = (uint8_t)(buf[0] & 0x0f);
    if (out->version != 4) {
        return -1;
    }

    out->header_len = (size_t)out->ihl * 4;
    if (out->header_len < 20 || len < out->header_len) {
        return -1;
    }

    out->total_length = (uint16_t)((buf[2] << 8) | buf[3]);
    out->ttl = buf[8];
    out->protocol = buf[9];
    out->src_ip = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                  ((uint32_t)buf[14] << 8) | buf[15];
    out->dst_ip = ((uint32_t)buf[16] << 24) | ((uint32_t)buf[17] << 16) |
                  ((uint32_t)buf[18] << 8) | buf[19];

    return 0;
}

void ip_format_addr(uint32_t addr, char *out) {
    sprintf(out, "%u.%u.%u.%u",
            (addr >> 24) & 0xffu, (addr >> 16) & 0xffu,
            (addr >> 8) & 0xffu, addr & 0xffu);
}
