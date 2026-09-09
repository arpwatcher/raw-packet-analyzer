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

static void test_write_then_read_round_trip(void) {
    const char *path = "tests/fixtures/roundtrip.pcap";

    pcap_writer_t writer;
    int rc = pcap_writer_open(&writer, path, 65535, PCAP_LINKTYPE_ETHERNET);
    assert(rc == 0);

    unsigned char packet_a[] = {0x01, 0x02, 0x03};
    unsigned char packet_b[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    assert(pcap_writer_write_packet(&writer, 1700000000, 500, packet_a, sizeof(packet_a)) == 0);
    assert(pcap_writer_write_packet(&writer, 1700000001, 0, packet_b, sizeof(packet_b)) == 0);
    pcap_writer_close(&writer);

    pcap_reader_t reader;
    rc = pcap_reader_open(&reader, path);
    assert(rc == 0);
    assert(reader.needs_swap == 0);
    assert(reader.global_header.snaplen == 65535);
    assert(reader.global_header.network == PCAP_LINKTYPE_ETHERNET);

    unsigned char buf[65536];
    pcap_packet_header_t header;

    assert(pcap_reader_next(&reader, &header, buf, sizeof(buf)) == 1);
    assert(header.ts_sec == 1700000000);
    assert(header.ts_usec == 500);
    assert(header.incl_len == sizeof(packet_a));
    assert(memcmp(buf, packet_a, sizeof(packet_a)) == 0);

    assert(pcap_reader_next(&reader, &header, buf, sizeof(buf)) == 1);
    assert(header.ts_sec == 1700000001);
    assert(header.incl_len == sizeof(packet_b));
    assert(memcmp(buf, packet_b, sizeof(packet_b)) == 0);

    assert(pcap_reader_next(&reader, &header, buf, sizeof(buf)) == 0); /* clean eof */

    pcap_reader_close(&reader);
    remove(path);
    printf("test_write_then_read_round_trip passed\n");
}

int main(void) {
    test_open_valid_file();
    test_open_missing_file();
    test_open_rejects_bad_magic();
    test_reads_all_packets();
    test_first_packet_is_tcp_syn();
    test_write_then_read_round_trip();
    printf("\nall tests passed\n");
    return 0;
}
