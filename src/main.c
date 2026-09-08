#include <stdio.h>

#include "ethernet.h"
#include "ip.h"
#include "pcap_format.h"
#include "tcp.h"
#include "udp.h"

static const char *protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IP_PROTO_TCP:  return "tcp";
        case IP_PROTO_UDP:  return "udp";
        case IP_PROTO_ICMP: return "icmp";
        default:            return "other";
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    pcap_reader_t reader;
    if (pcap_reader_open(&reader, argv[1]) != 0) {
        fprintf(stderr, "error: could not open %s as a pcap file\n", argv[1]);
        return 1;
    }

    unsigned char buf[65536];
    pcap_packet_header_t header;
    int count = 0;
    int result;

    while ((result = pcap_reader_next(&reader, &header, buf, sizeof(buf))) == 1) {
        count++;

        ethernet_header_t eth;
        if (ethernet_parse(buf, header.incl_len, &eth) != 0) {
            printf("%3d: (truncated ethernet frame, %u bytes)\n", count, header.incl_len);
            continue;
        }

        if (eth.ethertype != ETHERTYPE_IPV4) {
            printf("%3d: non-ipv4 frame (ethertype 0x%04x)\n", count, eth.ethertype);
            continue;
        }

        ip_header_t ip;
        if (ip_parse(buf + ETHERNET_HEADER_LEN, header.incl_len - ETHERNET_HEADER_LEN, &ip) != 0) {
            printf("%3d: (malformed ip header)\n", count);
            continue;
        }

        char src[16], dst[16];
        ip_format_addr(ip.src_ip, src);
        ip_format_addr(ip.dst_ip, dst);

        const unsigned char *payload = buf + ETHERNET_HEADER_LEN + ip.header_len;
        size_t payload_len = header.incl_len - ETHERNET_HEADER_LEN - ip.header_len;

        if (ip.protocol == IP_PROTO_TCP) {
            tcp_header_t tcp;
            if (tcp_parse(payload, payload_len, &tcp) == 0) {
                char flags[32];
                tcp_format_flags(tcp.flags, flags);
                printf("%3d: %-15s:%-5u -> %-15s:%-5u %-5s len=%u ttl=%u flags=%s\n",
                       count, src, tcp.src_port, dst, tcp.dst_port,
                       protocol_name(ip.protocol), ip.total_length, ip.ttl, flags);
                continue;
            }
        } else if (ip.protocol == IP_PROTO_UDP) {
            udp_header_t udp;
            if (udp_parse(payload, payload_len, &udp) == 0) {
                printf("%3d: %-15s:%-5u -> %-15s:%-5u %-5s len=%u ttl=%u\n",
                       count, src, udp.src_port, dst, udp.dst_port,
                       protocol_name(ip.protocol), ip.total_length, ip.ttl);
                continue;
            }
        }

        printf("%3d: %-15s -> %-15s %-5s len=%u ttl=%u\n",
               count, src, dst, protocol_name(ip.protocol), ip.total_length, ip.ttl);
    }

    if (result == -1) {
        fprintf(stderr, "error: truncated or corrupt pcap file after %d packets\n", count);
        pcap_reader_close(&reader);
        return 1;
    }

    printf("\n%d packets\n", count);
    pcap_reader_close(&reader);
    return 0;
}
