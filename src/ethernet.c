#include "ethernet.h"
#include <stdio.h>
#include <string.h>

int ethernet_parse(const unsigned char *buf, size_t len, ethernet_header_t *out) {
    if (len < ETHERNET_HEADER_LEN) {
        return -1;
    }

    memcpy(out->dst_mac, buf, 6);
    memcpy(out->src_mac, buf + 6, 6);
    /* ethertype is big-endian on the wire regardless of host byte order */
    out->ethertype = (uint16_t)((buf[12] << 8) | buf[13]);

    return 0;
}

void ethernet_format_mac(const uint8_t mac[6], char *out) {
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
