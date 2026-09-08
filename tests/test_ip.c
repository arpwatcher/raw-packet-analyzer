#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ip.h"

static void test_parse_standard_header(void) {
    unsigned char header[20] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x05, /* src 10.0.0.5 */
        0x0a, 0x00, 0x00, 0x0a, /* dst 10.0.0.10 */
    };

    ip_header_t ip;
    int rc = ip_parse(header, sizeof(header), &ip);
    assert(rc == 0);
    assert(ip.version == 4);
    assert(ip.ihl == 5);
    assert(ip.header_len == 20);
    assert(ip.protocol == IP_PROTO_TCP);
    assert(ip.ttl == 64);

    char src[16], dst[16];
    ip_format_addr(ip.src_ip, src);
    ip_format_addr(ip.dst_ip, dst);
    assert(strcmp(src, "10.0.0.5") == 0);
    assert(strcmp(dst, "10.0.0.10") == 0);
    printf("test_parse_standard_header passed\n");
}

static void test_parse_header_with_options(void) {
    /* ihl=6 means a 24 byte header - 4 extra bytes of options after the
     * normal 20, the classic variable-length case that trips up naive
     * fixed-size struct parsing */
    unsigned char header[24] = {
        0x46, 0x00, 0x00, 0x30, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x05,
        0x08, 0x08, 0x08, 0x08,
        0x00, 0x00, 0x00, 0x00, /* 4 bytes of option padding */
    };

    ip_header_t ip;
    int rc = ip_parse(header, sizeof(header), &ip);
    assert(rc == 0);
    assert(ip.ihl == 6);
    assert(ip.header_len == 24);
    assert(ip.protocol == IP_PROTO_UDP);
    printf("test_parse_header_with_options passed\n");
}

static void test_parse_rejects_non_ipv4(void) {
    unsigned char header[20] = {0x65, 0}; /* version 6 in the high nibble */
    ip_header_t ip;
    int rc = ip_parse(header, sizeof(header), &ip);
    assert(rc == -1);
    printf("test_parse_rejects_non_ipv4 passed\n");
}

static void test_parse_rejects_truncated_buffer(void) {
    /* ihl says 24 bytes but we only give it 20 */
    unsigned char header[20] = {0x46, 0};
    ip_header_t ip;
    int rc = ip_parse(header, sizeof(header), &ip);
    assert(rc == -1);
    printf("test_parse_rejects_truncated_buffer passed\n");
}

static void test_format_addr(void) {
    char out[16];
    ip_format_addr(0x0a000005u, out);
    assert(strcmp(out, "10.0.0.5") == 0);
    printf("test_format_addr passed\n");
}

int main(void) {
    test_parse_standard_header();
    test_parse_header_with_options();
    test_parse_rejects_non_ipv4();
    test_parse_rejects_truncated_buffer();
    test_format_addr();
    printf("\nall tests passed\n");
    return 0;
}
