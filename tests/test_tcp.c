#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tcp.h"

static void test_parse_syn_packet(void) {
    /* src port 54321, dst port 22 (ssh), syn flag set, no options */
    unsigned char header[20] = {
        0xd4, 0x31,             /* src port 54321 */
        0x00, 0x16,             /* dst port 22 */
        0x00, 0x00, 0x00, 0x01, /* seq */
        0x00, 0x00, 0x00, 0x00, /* ack */
        0x50, 0x02,             /* data offset=5, flags=SYN */
        0x72, 0x10,             /* window */
        0x00, 0x00, 0x00, 0x00, /* checksum + urgent ptr */
    };

    tcp_header_t tcp;
    int rc = tcp_parse(header, sizeof(header), &tcp);
    assert(rc == 0);
    assert(tcp.src_port == 54321);
    assert(tcp.dst_port == 22);
    assert(tcp.data_offset == 5);
    assert(tcp.header_len == 20);
    assert(tcp.flags == TCP_FLAG_SYN);
    printf("test_parse_syn_packet passed\n");
}

static void test_parse_header_with_options(void) {
    /* data offset=8 means 32 byte header - 12 extra bytes of options */
    unsigned char header[32] = {0};
    header[12] = 0x80; /* data offset 8 in high nibble */

    tcp_header_t tcp;
    int rc = tcp_parse(header, sizeof(header), &tcp);
    assert(rc == 0);
    assert(tcp.data_offset == 8);
    assert(tcp.header_len == 32);
    printf("test_parse_header_with_options passed\n");
}

static void test_parse_rejects_truncated_buffer(void) {
    /* data offset says 32 bytes but we only give it 20 */
    unsigned char header[20] = {0};
    header[12] = 0x80;

    tcp_header_t tcp;
    int rc = tcp_parse(header, sizeof(header), &tcp);
    assert(rc == -1);
    printf("test_parse_rejects_truncated_buffer passed\n");
}

static void test_format_flags_multiple(void) {
    char out[32];
    tcp_format_flags(TCP_FLAG_SYN | TCP_FLAG_ACK, out);
    assert(strcmp(out, "SYN,ACK") == 0);
    printf("test_format_flags_multiple passed\n");
}

static void test_format_flags_none(void) {
    char out[32];
    tcp_format_flags(0, out);
    assert(strcmp(out, "-") == 0);
    printf("test_format_flags_none passed\n");
}

int main(void) {
    test_parse_syn_packet();
    test_parse_header_with_options();
    test_parse_rejects_truncated_buffer();
    test_format_flags_multiple();
    test_format_flags_none();
    printf("\nall tests passed\n");
    return 0;
}
