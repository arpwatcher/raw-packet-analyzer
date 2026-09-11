/* arp header - 28 bytes for the common case (ethernet hardware addresses,
 * ipv4 protocol addresses). unlike tcp/udp/icmp this isn't layered inside
 * an ip packet - it's a direct ethernet payload (ethertype 0x0806),
 * announced by ethernet_header_t.ethertype rather than ip_header_t.protocol.
 */
#ifndef ARP_H
#define ARP_H

#include <stddef.h>
#include <stdint.h>

#define ARP_HEADER_LEN 28

#define ARP_HTYPE_ETHERNET 1u
#define ARP_PTYPE_IPV4 0x0800u

#define ARP_OP_REQUEST 1u
#define ARP_OP_REPLY   2u

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
} arp_header_t;

/* parses an arp header starting at buf. returns 0 on success, -1 if len is
 * too short, or if the packet isn't the common ethernet/ipv4 case (this
 * repo doesn't try to handle other hardware/protocol address sizes). */
int arp_parse(const unsigned char *buf, size_t len, arp_header_t *out);

/* returns "request", "reply", or "unknown" for anything else. */
const char *arp_op_name(uint16_t operation);

#endif
