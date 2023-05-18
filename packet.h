#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// >= MTU
#define PKT_BUFF_SIZE 2048

typedef struct address_ {
    char family;
    union {
        uint32_t        address_un_data32[4]; /* type-specific field */
        uint16_t        address_un_data16[8]; /* type-specific field */
        uint8_t         address_un_data8[16]; /* type-specific field */
        // to str: inet_ntop(AF_INET6, &(ip6h->ip6_src), (char *)src_ip_v6, INET6_ADDRSTRLEN);
        struct in6_addr address_un_in6;
        // to str: 
        // src_ip[0] = iph->saddr & 0xFF;
		// src_ip[1] = (iph->saddr >> 8) & 0xFF;
		// src_ip[2] = (iph->saddr >> 16) & 0xFF;
		// src_ip[3] = (iph->saddr >> 24) & 0xFF;
        struct in_addr  address_un_in4;
    } address;
    uint8_t mac[8]; // can only get MAC from source
} address_t;

typedef uint16_t port_t;

// USE PROVIDED FUNCTION TO CREATE / DELETE PACKET_T OBJ / UPDATE PAYLOAD
// DO NOT MANUALLY HANDLE PAYLOAD PTR
typedef struct packet_
{
    int32_t id; // nfq id
    address_t src;
    address_t dst;
    // in network format, use ntohs
    port_t sp;
    // in network format, use ntohs
    port_t dp;
    // nfq doc is shit, not sure how long ptr to nfq_data remains valid, so copy to our own buffer
    uint8_t *payload;
    // get from nfq_get_payload. converted to unsigned
    uint32_t payload_len;
    // offset to data starting from payload, avoid having 2 ptrs -> missuses
    int32_t data_offset;
} packet_t;

// Will do memcpy of buffer pointed to by payload into newly created obj if not null
packet_t *packet_create(uint8_t *payload, uint16_t payload_len);
// Used in nfq callback, parse data here instead of in the callback itself
// https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Parsing.html
packet_t *packet_create_nfdata(struct nfq_data *nfad);
// Will free the referenced packet and its payload
void packet_destroy(packet_t **packet);
// Replace current payload with new malloced buffer using new payload len, then memcpy new_payload
void packet_payload_realloc(packet_t *packet, uint8_t *new_payload, uint16_t new_payload_len);
// TODO METHODS TO HANDLE OTHER FIELDS
uint8_t *packet_get_src_mac(packet_t *packet);

#endif
