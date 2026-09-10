#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "icmp.h"

static void test_parse_echo_request(void) {
    unsigned char header[8] = {
        0x08, 0x00,             /* type=8 (echo request), code=0 */
        0x4d, 0x5a,             /* checksum */
        0x00, 0x01,             /* identifier */
        0x00, 0x2a,             /* sequence 42 */
    };

    icmp_header_t icmp;
    int rc = icmp_parse(header, sizeof(header), &icmp);
    assert(rc == 0);
    assert(icmp.type == ICMP_TYPE_ECHO_REQUEST);
    assert(icmp.code == 0);
    assert(icmp.identifier == 1);
    assert(icmp.sequence == 42);
    printf("test_parse_echo_request passed\n");
}

static void test_parse_rejects_truncated_buffer(void) {
    unsigned char header[6] = {0};
    icmp_header_t icmp;
    int rc = icmp_parse(header, sizeof(header), &icmp);
    assert(rc == -1);
    printf("test_parse_rejects_truncated_buffer passed\n");
}

static void test_type_name_echo_request(void) {
    assert(strcmp(icmp_type_name(ICMP_TYPE_ECHO_REQUEST, 0), "echo request") == 0);
    printf("test_type_name_echo_request passed\n");
}

static void test_type_name_echo_reply(void) {
    assert(strcmp(icmp_type_name(ICMP_TYPE_ECHO_REPLY, 0), "echo reply") == 0);
    printf("test_type_name_echo_reply passed\n");
}

static void test_type_name_dest_unreachable_port(void) {
    assert(strcmp(icmp_type_name(ICMP_TYPE_DEST_UNREACHABLE, 3), "dest unreachable (port)") == 0);
    printf("test_type_name_dest_unreachable_port passed\n");
}

static void test_type_name_unknown_falls_back(void) {
    assert(strcmp(icmp_type_name(200, 7), "type 200 code 7") == 0);
    printf("test_type_name_unknown_falls_back passed\n");
}

int main(void) {
    test_parse_echo_request();
    test_parse_rejects_truncated_buffer();
    test_type_name_echo_request();
    test_type_name_echo_reply();
    test_type_name_dest_unreachable_port();
    test_type_name_unknown_falls_back();
    printf("\nall tests passed\n");
    return 0;
}
