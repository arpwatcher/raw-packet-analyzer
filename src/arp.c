#include "arp.h"

int arp_parse(const unsigned char *buf, size_t len, arp_header_t *out) {
    if (len < ARP_HEADER_LEN) {
        return -1;
    }

    out->hardware_type = (uint16_t)((buf[0] << 8) | buf[1]);
    out->protocol_type = (uint16_t)((buf[2] << 8) | buf[3]);
    out->hardware_len = buf[4];
    out->protocol_len = buf[5];
    out->operation = (uint16_t)((buf[6] << 8) | buf[7]);

    if (out->hardware_type != ARP_HTYPE_ETHERNET || out->protocol_type != ARP_PTYPE_IPV4 ||
        out->hardware_len != 6 || out->protocol_len != 4) {
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        out->sender_mac[i] = buf[8 + i];
    }
    out->sender_ip = ((uint32_t)buf[14] << 24) | ((uint32_t)buf[15] << 16) |
                     ((uint32_t)buf[16] << 8) | buf[17];
    for (int i = 0; i < 6; i++) {
        out->target_mac[i] = buf[18 + i];
    }
    out->target_ip = ((uint32_t)buf[24] << 24) | ((uint32_t)buf[25] << 16) |
                     ((uint32_t)buf[26] << 8) | buf[27];

    return 0;
}

const char *arp_op_name(uint16_t operation) {
    switch (operation) {
        case ARP_OP_REQUEST: return "request";
        case ARP_OP_REPLY:   return "reply";
        default:              return "unknown";
    }
}
