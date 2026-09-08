#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ethernet.h"
#include "pcap_format.h"

static void test_parse_known_bytes(void) {
    unsigned char frame[ETHERNET_HEADER_LEN] = {
        0x02, 0xfc, 0x00, 0x00, 0x00, 0x05, /* dst mac */
        0x02, 0xfc, 0x00, 0x00, 0x00, 0x01, /* src mac */
        0x08, 0x00,                          /* ethertype: ipv4 */
    };

    ethernet_header_t eth;
    int rc = ethernet_parse(frame, sizeof(frame), &eth);
    assert(rc == 0);
    assert(eth.ethertype == ETHERTYPE_IPV4);
    assert(memcmp(eth.dst_mac, frame, 6) == 0);
    assert(memcmp(eth.src_mac, frame + 6, 6) == 0);
    printf("test_parse_known_bytes passed\n");
}

static void test_parse_rejects_short_buffer(void) {
    unsigned char frame[10] = {0};
    ethernet_header_t eth;
    int rc = ethernet_parse(frame, sizeof(frame), &eth);
    assert(rc == -1);
    printf("test_parse_rejects_short_buffer passed\n");
}

static void test_format_mac(void) {
    uint8_t mac[6] = {0x02, 0xfc, 0x00, 0x00, 0x00, 0x05};
    char out[18];
    ethernet_format_mac(mac, out);
    assert(strcmp(out, "02:fc:00:00:00:05") == 0);
    printf("test_format_mac passed\n");
}

static void test_parses_real_pcap_first_frame(void) {
    pcap_reader_t reader;
    pcap_reader_open(&reader, "tests/fixtures/sample.pcap");

    unsigned char buf[65536];
    pcap_packet_header_t header;
    pcap_reader_next(&reader, &header, buf, sizeof(buf));

    ethernet_header_t eth;
    int rc = ethernet_parse(buf, header.incl_len, &eth);
    assert(rc == 0);
    assert(eth.ethertype == ETHERTYPE_IPV4);

    pcap_reader_close(&reader);
    printf("test_parses_real_pcap_first_frame passed\n");
}

int main(void) {
    test_parse_known_bytes();
    test_parse_rejects_short_buffer();
    test_format_mac();
    test_parses_real_pcap_first_frame();
    printf("\nall tests passed\n");
    return 0;
}
