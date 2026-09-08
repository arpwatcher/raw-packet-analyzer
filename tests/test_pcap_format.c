#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "pcap_format.h"

static void test_open_valid_file(void) {
    pcap_reader_t reader;
    int rc = pcap_reader_open(&reader, "tests/fixtures/sample.pcap");
    assert(rc == 0);
    assert(reader.needs_swap == 0);
    assert(reader.global_header.network == 1); /* LINKTYPE_ETHERNET */
    pcap_reader_close(&reader);
    printf("test_open_valid_file passed\n");
}

static void test_open_missing_file(void) {
    pcap_reader_t reader;
    int rc = pcap_reader_open(&reader, "tests/fixtures/does_not_exist.pcap");
    assert(rc == -1);
    printf("test_open_missing_file passed\n");
}

static void test_open_rejects_bad_magic(void) {
    FILE *f = fopen("tests/fixtures/bad_magic.pcap", "wb");
    unsigned char bad[24] = {0};
    bad[0] = 0x00; bad[1] = 0x00; bad[2] = 0x00; bad[3] = 0x00;
    fwrite(bad, 1, sizeof(bad), f);
    fclose(f);

    pcap_reader_t reader;
    int rc = pcap_reader_open(&reader, "tests/fixtures/bad_magic.pcap");
    assert(rc == -1);
    remove("tests/fixtures/bad_magic.pcap");
    printf("test_open_rejects_bad_magic passed\n");
}

static void test_reads_all_packets(void) {
    pcap_reader_t reader;
    int rc = pcap_reader_open(&reader, "tests/fixtures/sample.pcap");
    assert(rc == 0);

    unsigned char buf[65536];
    pcap_packet_header_t header;
    int count = 0;
    int result;

    while ((result = pcap_reader_next(&reader, &header, buf, sizeof(buf))) == 1) {
        count++;
        assert(header.incl_len > 0);
        assert(header.incl_len <= header.orig_len);
    }

    assert(result == 0); /* clean eof, not an error */
    assert(count == 3);
    pcap_reader_close(&reader);
    printf("test_reads_all_packets passed\n");
}

static void test_first_packet_is_tcp_syn(void) {
    pcap_reader_t reader;
    pcap_reader_open(&reader, "tests/fixtures/sample.pcap");

    unsigned char buf[65536];
    pcap_packet_header_t header;
    pcap_reader_next(&reader, &header, buf, sizeof(buf));

    /* ethernet header is 14 bytes, then ip header starts - protocol field
     * (tcp=6) is byte 9 of the ip header */
    unsigned char ip_protocol = buf[14 + 9];
    assert(ip_protocol == 6);

    pcap_reader_close(&reader);
    printf("test_first_packet_is_tcp_syn passed\n");
}

int main(void) {
    test_open_valid_file();
    test_open_missing_file();
    test_open_rejects_bad_magic();
    test_reads_all_packets();
    test_first_packet_is_tcp_syn();
    printf("\nall tests passed\n");
    return 0;
}
