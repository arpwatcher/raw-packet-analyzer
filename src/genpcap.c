/* genpcap - writes a small synthetic pcap file entirely in C, no python or
 * scapy involved. builds raw ethernet+ip+tcp/udp frames by hand (same idea
 * as the hardcoded byte arrays in the unit tests, just assembled into a
 * real file instead of an inline buffer) and pipes them through
 * pcap_writer. exists so this repo can generate its own test fixtures
 * without depending on tests/fixtures/make_sample_pcap.py.
 */
#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ip.h"
#include "pcap_format.h"

static const uint8_t SRC_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t DST_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

static size_t build_ethernet(unsigned char *buf, uint16_t ethertype) {
    memcpy(buf, DST_MAC, 6);
    memcpy(buf + 6, SRC_MAC, 6);
    buf[12] = (unsigned char)(ethertype >> 8);
    buf[13] = (unsigned char)(ethertype & 0xff);
    return 14;
}

static size_t build_ipv4(unsigned char *buf, uint8_t protocol, uint16_t total_length,
                          uint32_t src_ip, uint32_t dst_ip) {
    buf[0] = 0x45; /* version 4, ihl 5 (20 bytes, no options) */
    buf[1] = 0x00; /* dscp/ecn */
    buf[2] = (unsigned char)(total_length >> 8);
    buf[3] = (unsigned char)(total_length & 0xff);
    buf[4] = 0x00; buf[5] = 0x00; /* identification */
    buf[6] = 0x40; buf[7] = 0x00; /* flags/fragment offset: don't fragment */
    buf[8] = 64;   /* ttl */
    buf[9] = protocol;
    buf[10] = 0x00; buf[11] = 0x00; /* checksum, left zero - not validated by this repo's parser */
    buf[12] = (unsigned char)(src_ip >> 24);
    buf[13] = (unsigned char)(src_ip >> 16);
    buf[14] = (unsigned char)(src_ip >> 8);
    buf[15] = (unsigned char)(src_ip);
    buf[16] = (unsigned char)(dst_ip >> 24);
    buf[17] = (unsigned char)(dst_ip >> 16);
    buf[18] = (unsigned char)(dst_ip >> 8);
    buf[19] = (unsigned char)(dst_ip);
    return 20;
}

static size_t build_tcp_syn(unsigned char *buf, uint16_t src_port, uint16_t dst_port) {
    memset(buf, 0, 20);
    buf[0] = (unsigned char)(src_port >> 8);
    buf[1] = (unsigned char)(src_port & 0xff);
    buf[2] = (unsigned char)(dst_port >> 8);
    buf[3] = (unsigned char)(dst_port & 0xff);
    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x01; /* seq = 1 */
    buf[12] = 0x50; /* data offset 5, no options */
    buf[13] = 0x02; /* SYN */
    buf[14] = 0x72; buf[15] = 0x10; /* window */
    return 20;
}

static size_t build_udp(unsigned char *buf, uint16_t src_port, uint16_t dst_port,
                         uint16_t udp_len) {
    buf[0] = (unsigned char)(src_port >> 8);
    buf[1] = (unsigned char)(src_port & 0xff);
    buf[2] = (unsigned char)(dst_port >> 8);
    buf[3] = (unsigned char)(dst_port & 0xff);
    buf[4] = (unsigned char)(udp_len >> 8);
    buf[5] = (unsigned char)(udp_len & 0xff);
    buf[6] = 0x00; buf[7] = 0x00; /* checksum, left zero */
    return 8;
}

static size_t build_icmp_echo_request(unsigned char *buf, uint16_t identifier, uint16_t sequence) {
    buf[0] = ICMP_TYPE_ECHO_REQUEST;
    buf[1] = 0x00; /* code */
    buf[2] = 0x00; buf[3] = 0x00; /* checksum, left zero */
    buf[4] = (unsigned char)(identifier >> 8);
    buf[5] = (unsigned char)(identifier & 0xff);
    buf[6] = (unsigned char)(sequence >> 8);
    buf[7] = (unsigned char)(sequence & 0xff);
    return 8;
}

static size_t build_arp_request(unsigned char *buf, uint32_t sender_ip, uint32_t target_ip) {
    buf[0] = 0x00; buf[1] = 0x01; /* hardware type: ethernet */
    buf[2] = 0x08; buf[3] = 0x00; /* protocol type: ipv4 */
    buf[4] = 0x06; /* hardware len */
    buf[5] = 0x04; /* protocol len */
    buf[6] = 0x00; buf[7] = 0x01; /* operation: request */
    memcpy(buf + 8, SRC_MAC, 6);
    buf[14] = (unsigned char)(sender_ip >> 24);
    buf[15] = (unsigned char)(sender_ip >> 16);
    buf[16] = (unsigned char)(sender_ip >> 8);
    buf[17] = (unsigned char)(sender_ip);
    memset(buf + 18, 0, 6); /* target mac unknown - that's the point of asking */
    buf[24] = (unsigned char)(target_ip >> 24);
    buf[25] = (unsigned char)(target_ip >> 16);
    buf[26] = (unsigned char)(target_ip >> 8);
    buf[27] = (unsigned char)(target_ip);
    return 28;
}

static uint32_t ip_addr(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output.pcap>\n", argv[0]);
        return 1;
    }

    pcap_writer_t writer;
    if (pcap_writer_open(&writer, argv[1], 65535, PCAP_LINKTYPE_ETHERNET) != 0) {
        fprintf(stderr, "error: could not open %s for writing\n", argv[1]);
        return 1;
    }

    unsigned char packet[128];
    size_t off;

    /* packet 1: tcp syn, 203.0.113.5:51000 -> 10.0.0.10:22 */
    off = build_ethernet(packet, ETHERTYPE_IPV4);
    off += build_ipv4(packet + off, IP_PROTO_TCP, 40,
                       ip_addr(203, 0, 113, 5), ip_addr(10, 0, 0, 10));
    off += build_tcp_syn(packet + off, 51000, 22);
    pcap_writer_write_packet(&writer, 1700000000, 0, packet, (uint32_t)off);

    /* packet 2: udp, 10.0.0.5:52000 -> 8.8.8.8:53 */
    off = build_ethernet(packet, ETHERTYPE_IPV4);
    off += build_ipv4(packet + off, IP_PROTO_UDP, 28,
                       ip_addr(10, 0, 0, 5), ip_addr(8, 8, 8, 8));
    off += build_udp(packet + off, 52000, 53, 8);
    pcap_writer_write_packet(&writer, 1700000001, 0, packet, (uint32_t)off);

    /* packet 3: icmp echo request, 10.0.0.5 -> 10.0.0.1 */
    off = build_ethernet(packet, ETHERTYPE_IPV4);
    off += build_ipv4(packet + off, IP_PROTO_ICMP, 28,
                       ip_addr(10, 0, 0, 5), ip_addr(10, 0, 0, 1));
    off += build_icmp_echo_request(packet + off, 1, 1);
    pcap_writer_write_packet(&writer, 1700000002, 0, packet, (uint32_t)off);

    /* packet 4: arp request, who has 10.0.0.1? tell 10.0.0.5 */
    off = build_ethernet(packet, ETHERTYPE_ARP);
    off += build_arp_request(packet + off, ip_addr(10, 0, 0, 5), ip_addr(10, 0, 0, 1));
    pcap_writer_write_packet(&writer, 1700000003, 0, packet, (uint32_t)off);

    pcap_writer_close(&writer);

    fprintf(stderr, "wrote 4 packets to %s\n", argv[1]);
    return 0;
}
