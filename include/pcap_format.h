/* reads the classic libpcap file format by hand - global header then a
 * stream of (packet header, raw bytes) records. see the format description
 * at https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
#ifndef PCAP_FORMAT_H
#define PCAP_FORMAT_H

#include <stdint.h>
#include <stdio.h>

#define PCAP_MAGIC_NATIVE 0xa1b2c3d4u
#define PCAP_MAGIC_SWAPPED 0xd4c3b2a1u
#define PCAP_LINKTYPE_ETHERNET 1u

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

typedef struct {
    FILE *file;
    int needs_swap;
    pcap_global_header_t global_header;
} pcap_reader_t;

/* opens path, reads and validates the global header. returns 0 on success,
 * -1 if the file can't be opened or doesn't start with a recognized magic
 * number. */
int pcap_reader_open(pcap_reader_t *reader, const char *path);

/* reads the next packet's header into *header and its raw bytes into buf
 * (buf must be at least header->incl_len bytes once known - caller should
 * pass a buffer sized buf_len >= global_header.snaplen).
 * returns 1 on a packet read, 0 on clean eof, -1 on error or truncated read. */
int pcap_reader_next(pcap_reader_t *reader, pcap_packet_header_t *header,
                      unsigned char *buf, size_t buf_len);

void pcap_reader_close(pcap_reader_t *reader);

typedef struct {
    FILE *file;
} pcap_writer_t;

/* opens path for writing and writes the global header (native byte order,
 * this machine's endianness - a reader on the same machine never needs to
 * swap what this writes). returns 0 on success, -1 if the file can't be
 * created. */
int pcap_writer_open(pcap_writer_t *writer, const char *path,
                      uint32_t snaplen, uint32_t network);

/* writes one packet record: a pcap_packet_header_t built from the given
 * timestamp and length, followed by len bytes from buf. returns 0 on
 * success, -1 on a write error. */
int pcap_writer_write_packet(pcap_writer_t *writer, uint32_t ts_sec, uint32_t ts_usec,
                              const unsigned char *buf, uint32_t len);

void pcap_writer_close(pcap_writer_t *writer);

#endif
