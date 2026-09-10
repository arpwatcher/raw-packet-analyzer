#include <stdio.h>
#include <string.h>

#include "ethernet.h"
#include "icmp.h"
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

static void print_verbose_ethernet(const ethernet_header_t *eth) {
    char src[18], dst[18];
    ethernet_format_mac(eth->src_mac, src);
    ethernet_format_mac(eth->dst_mac, dst);
    printf("       ethernet: src=%s dst=%s ethertype=0x%04x\n", src, dst, eth->ethertype);
}

static void print_verbose_ip(const ip_header_t *ip) {
    printf("       ip: version=%u ihl=%u (header_len=%zu) total_length=%u ttl=%u protocol=%u\n",
           ip->version, ip->ihl, ip->header_len, ip->total_length, ip->ttl, ip->protocol);
}

static void print_verbose_tcp(const tcp_header_t *tcp) {
    char flags[32];
    tcp_format_flags(tcp->flags, flags);
    printf("       tcp: seq=%u ack=%u data_offset=%u (header_len=%zu) window=%u flags=%s\n",
           tcp->seq_num, tcp->ack_num, tcp->data_offset, tcp->header_len, tcp->window_size, flags);
}

static void print_verbose_udp(const udp_header_t *udp) {
    printf("       udp: length=%u\n", udp->length);
}

static void print_verbose_icmp(const icmp_header_t *icmp) {
    printf("       icmp: type=%u code=%u (%s) identifier=%u sequence=%u\n",
           icmp->type, icmp->code, icmp_type_name(icmp->type, icmp->code),
           icmp->identifier, icmp->sequence);
}

int main(int argc, char **argv) {
    int verbose = 0;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (path == NULL) {
            path = argv[i];
        } else {
            path = NULL;
            break;
        }
    }

    if (path == NULL) {
        fprintf(stderr, "usage: %s [--verbose] <pcap file>\n", argv[0]);
        return 1;
    }

    pcap_reader_t reader;
    if (pcap_reader_open(&reader, path) != 0) {
        fprintf(stderr, "error: could not open %s as a pcap file\n", path);
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
            if (verbose) {
                print_verbose_ethernet(&eth);
            }
            continue;
        }

        ip_header_t ip;
        if (ip_parse(buf + ETHERNET_HEADER_LEN, header.incl_len - ETHERNET_HEADER_LEN, &ip) != 0) {
            printf("%3d: (malformed ip header)\n", count);
            if (verbose) {
                print_verbose_ethernet(&eth);
            }
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
                if (verbose) {
                    print_verbose_ethernet(&eth);
                    print_verbose_ip(&ip);
                    print_verbose_tcp(&tcp);
                }
                continue;
            }
        } else if (ip.protocol == IP_PROTO_UDP) {
            udp_header_t udp;
            if (udp_parse(payload, payload_len, &udp) == 0) {
                printf("%3d: %-15s:%-5u -> %-15s:%-5u %-5s len=%u ttl=%u\n",
                       count, src, udp.src_port, dst, udp.dst_port,
                       protocol_name(ip.protocol), ip.total_length, ip.ttl);
                if (verbose) {
                    print_verbose_ethernet(&eth);
                    print_verbose_ip(&ip);
                    print_verbose_udp(&udp);
                }
                continue;
            }
        } else if (ip.protocol == IP_PROTO_ICMP) {
            icmp_header_t icmp;
            if (icmp_parse(payload, payload_len, &icmp) == 0) {
                printf("%3d: %-15s -> %-15s %-5s len=%u ttl=%u %s\n",
                       count, src, dst, protocol_name(ip.protocol), ip.total_length,
                       ip.ttl, icmp_type_name(icmp.type, icmp.code));
                if (verbose) {
                    print_verbose_ethernet(&eth);
                    print_verbose_ip(&ip);
                    print_verbose_icmp(&icmp);
                }
                continue;
            }
        }

        printf("%3d: %-15s -> %-15s %-5s len=%u ttl=%u\n",
               count, src, dst, protocol_name(ip.protocol), ip.total_length, ip.ttl);
        if (verbose) {
            print_verbose_ethernet(&eth);
            print_verbose_ip(&ip);
        }
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
