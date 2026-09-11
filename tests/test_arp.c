#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"

static void test_parse_request(void) {
    /* who has 10.0.0.1? tell 10.0.0.5 */
    unsigned char header[28] = {
        0x00, 0x01,             /* hardware type: ethernet */
        0x08, 0x00,             /* protocol type: ipv4 */
        0x06,                   /* hardware len */
        0x04,                   /* protocol len */
        0x00, 0x01,             /* operation: request */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, /* sender mac */
        0x0a, 0x00, 0x00, 0x05,             /* sender ip 10.0.0.5 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* target mac unknown, all zero */
        0x0a, 0x00, 0x00, 0x01,             /* target ip 10.0.0.1 */
    };

    arp_header_t arp;
    int rc = arp_parse(header, sizeof(header), &arp);
    assert(rc == 0);
    assert(arp.operation == ARP_OP_REQUEST);
    assert(arp.sender_ip == 0x0a000005u);
    assert(arp.target_ip == 0x0a000001u);
    assert(arp.sender_mac[0] == 0x02 && arp.sender_mac[5] == 0x01);
    printf("test_parse_request passed\n");
}

static void test_parse_reply(void) {
    unsigned char header[28] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, /* operation: reply */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x0a, 0x00, 0x00, 0x05,
    };

    arp_header_t arp;
    int rc = arp_parse(header, sizeof(header), &arp);
    assert(rc == 0);
    assert(arp.operation == ARP_OP_REPLY);
    printf("test_parse_reply passed\n");
}

static void test_parse_rejects_truncated_buffer(void) {
    unsigned char header[20] = {0};
    arp_header_t arp;
    int rc = arp_parse(header, sizeof(header), &arp);
    assert(rc == -1);
    printf("test_parse_rejects_truncated_buffer passed\n");
}

static void test_parse_rejects_non_ethernet_ipv4(void) {
    unsigned char header[28] = {0};
    header[0] = 0x00; header[1] = 0x06; /* hardware type 6, not ethernet(1) */
    header[2] = 0x08; header[3] = 0x00;
    header[4] = 0x06; header[5] = 0x04;

    arp_header_t arp;
    int rc = arp_parse(header, sizeof(header), &arp);
    assert(rc == -1);
    printf("test_parse_rejects_non_ethernet_ipv4 passed\n");
}

static void test_op_name(void) {
    assert(strcmp(arp_op_name(ARP_OP_REQUEST), "request") == 0);
    assert(strcmp(arp_op_name(ARP_OP_REPLY), "reply") == 0);
    assert(strcmp(arp_op_name(99), "unknown") == 0);
    printf("test_op_name passed\n");
}

int main(void) {
    test_parse_request();
    test_parse_reply();
    test_parse_rejects_truncated_buffer();
    test_parse_rejects_non_ethernet_ipv4();
    test_op_name();
    printf("\nall tests passed\n");
    return 0;
}
