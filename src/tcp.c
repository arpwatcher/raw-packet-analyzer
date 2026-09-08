#include "tcp.h"
#include <string.h>

int tcp_parse(const unsigned char *buf, size_t len, tcp_header_t *out) {
    if (len < 20) {
        return -1;
    }

    out->src_port = (uint16_t)((buf[0] << 8) | buf[1]);
    out->dst_port = (uint16_t)((buf[2] << 8) | buf[3]);
    out->seq_num = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                   ((uint32_t)buf[6] << 8) | buf[7];
    out->ack_num = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                   ((uint32_t)buf[10] << 8) | buf[11];
    out->data_offset = (uint8_t)((buf[12] >> 4) & 0x0f);
    out->flags = (uint8_t)(buf[13] & 0x3f);
    out->window_size = (uint16_t)((buf[14] << 8) | buf[15]);

    out->header_len = (size_t)out->data_offset * 4;
    if (out->header_len < 20 || len < out->header_len) {
        return -1;
    }

    return 0;
}

void tcp_format_flags(uint8_t flags, char *out) {
    static const struct {
        uint8_t bit;
        const char *name;
    } table[] = {
        {TCP_FLAG_SYN, "SYN"}, {TCP_FLAG_ACK, "ACK"}, {TCP_FLAG_FIN, "FIN"},
        {TCP_FLAG_RST, "RST"}, {TCP_FLAG_PSH, "PSH"}, {TCP_FLAG_URG, "URG"},
    };

    out[0] = '\0';
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (flags & table[i].bit) {
            if (out[0] != '\0') {
                strcat(out, ",");
            }
            strcat(out, table[i].name);
        }
    }

    if (out[0] == '\0') {
        strcpy(out, "-");
    }
}
