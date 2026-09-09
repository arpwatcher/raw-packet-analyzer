#include "pcap_format.h"
#include <string.h>

static uint32_t swap32(uint32_t v) {
    return ((v & 0x000000ffu) << 24) |
           ((v & 0x0000ff00u) << 8)  |
           ((v & 0x00ff0000u) >> 8)  |
           ((v & 0xff000000u) >> 24);
}

static uint16_t swap16(uint16_t v) {
    return (uint16_t)(((v & 0x00ffu) << 8) | ((v & 0xff00u) >> 8));
}

int pcap_reader_open(pcap_reader_t *reader, const char *path) {
    memset(reader, 0, sizeof(*reader));

    reader->file = fopen(path, "rb");
    if (!reader->file) {
        return -1;
    }

    if (fread(&reader->global_header, sizeof(pcap_global_header_t), 1, reader->file) != 1) {
        fclose(reader->file);
        reader->file = NULL;
        return -1;
    }

    if (reader->global_header.magic_number == PCAP_MAGIC_NATIVE) {
        reader->needs_swap = 0;
    } else if (reader->global_header.magic_number == PCAP_MAGIC_SWAPPED) {
        reader->needs_swap = 1;
        reader->global_header.version_major = swap16(reader->global_header.version_major);
        reader->global_header.version_minor = swap16(reader->global_header.version_minor);
        reader->global_header.thiszone = (int32_t)swap32((uint32_t)reader->global_header.thiszone);
        reader->global_header.sigfigs = swap32(reader->global_header.sigfigs);
        reader->global_header.snaplen = swap32(reader->global_header.snaplen);
        reader->global_header.network = swap32(reader->global_header.network);
    } else {
        fclose(reader->file);
        reader->file = NULL;
        return -1;
    }

    return 0;
}

int pcap_reader_next(pcap_reader_t *reader, pcap_packet_header_t *header,
                      unsigned char *buf, size_t buf_len) {
    size_t got = fread(header, sizeof(pcap_packet_header_t), 1, reader->file);
    if (got == 0) {
        return feof(reader->file) ? 0 : -1;
    }

    if (reader->needs_swap) {
        header->ts_sec = swap32(header->ts_sec);
        header->ts_usec = swap32(header->ts_usec);
        header->incl_len = swap32(header->incl_len);
        header->orig_len = swap32(header->orig_len);
    }

    if (header->incl_len > buf_len) {
        return -1;
    }

    if (fread(buf, 1, header->incl_len, reader->file) != header->incl_len) {
        return -1;
    }

    return 1;
}

void pcap_reader_close(pcap_reader_t *reader) {
    if (reader->file) {
        fclose(reader->file);
        reader->file = NULL;
    }
}

int pcap_writer_open(pcap_writer_t *writer, const char *path,
                      uint32_t snaplen, uint32_t network) {
    writer->file = fopen(path, "wb");
    if (!writer->file) {
        return -1;
    }

    pcap_global_header_t global_header = {
        .magic_number = PCAP_MAGIC_NATIVE,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = snaplen,
        .network = network,
    };

    if (fwrite(&global_header, sizeof(global_header), 1, writer->file) != 1) {
        fclose(writer->file);
        writer->file = NULL;
        return -1;
    }

    return 0;
}

int pcap_writer_write_packet(pcap_writer_t *writer, uint32_t ts_sec, uint32_t ts_usec,
                              const unsigned char *buf, uint32_t len) {
    pcap_packet_header_t header = {
        .ts_sec = ts_sec,
        .ts_usec = ts_usec,
        .incl_len = len,
        .orig_len = len,
    };

    if (fwrite(&header, sizeof(header), 1, writer->file) != 1) {
        return -1;
    }
    if (fwrite(buf, 1, len, writer->file) != len) {
        return -1;
    }

    return 0;
}

void pcap_writer_close(pcap_writer_t *writer) {
    if (writer->file) {
        fclose(writer->file);
        writer->file = NULL;
    }
}
