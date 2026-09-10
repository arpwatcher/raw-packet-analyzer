#include "icmp.h"
#include <stdio.h>

int icmp_parse(const unsigned char *buf, size_t len, icmp_header_t *out) {
    if (len < ICMP_HEADER_LEN) {
        return -1;
    }

    out->type = buf[0];
    out->code = buf[1];
    out->checksum = (uint16_t)((buf[2] << 8) | buf[3]);
    out->identifier = (uint16_t)((buf[4] << 8) | buf[5]);
    out->sequence = (uint16_t)((buf[6] << 8) | buf[7]);

    return 0;
}

const char *icmp_type_name(uint8_t type, uint8_t code) {
    static char buf[32];

    switch (type) {
        case ICMP_TYPE_ECHO_REPLY:
            return "echo reply";
        case ICMP_TYPE_ECHO_REQUEST:
            return "echo request";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "time exceeded";
        case ICMP_TYPE_DEST_UNREACHABLE:
            switch (code) {
                case 0: return "dest unreachable (net)";
                case 1: return "dest unreachable (host)";
                case 3: return "dest unreachable (port)";
                default: break;
            }
            break;
        default:
            break;
    }

    snprintf(buf, sizeof(buf), "type %u code %u", type, code);
    return buf;
}
