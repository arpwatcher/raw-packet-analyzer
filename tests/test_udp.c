#include <assert.h>
#include <stdio.h>

#include "udp.h"

static void test_parse_dns_query(void) {
    /* src port 51234, dst port 53 (dns), length 40 */
    unsigned char header[8] = {
        0xc8, 0x22, /* src port 51234 */
        0x00, 0x35, /* dst port 53 */
        0x00, 0x28, /* length 40 */
        0x00, 0x00, /* checksum */
    };

    udp_header_t udp;
    int rc = udp_parse(header, sizeof(header), &udp);
    assert(rc == 0);
    assert(udp.src_port == 51234);
    assert(udp.dst_port == 53);
    assert(udp.length == 40);
    printf("test_parse_dns_query passed\n");
}

static void test_parse_rejects_truncated_buffer(void) {
    unsigned char header[6] = {0};
    udp_header_t udp;
    int rc = udp_parse(header, sizeof(header), &udp);
    assert(rc == -1);
    printf("test_parse_rejects_truncated_buffer passed\n");
}

int main(void) {
    test_parse_dns_query();
    test_parse_rejects_truncated_buffer();
    printf("\nall tests passed\n");
    return 0;
}
