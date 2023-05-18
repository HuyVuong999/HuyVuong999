#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "packet.h"
#include "debug.h"

packet_t *packet_create(uint8_t *payload, uint16_t payload_len)
{
    packet_t *new = (packet_t *)malloc(sizeof(packet_t));
    if (!new) {
        debug_print("Packet create failure: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (!payload || payload_len == 0) {
        new->id = -1;
        new->payload = NULL;
        new->payload_len = 0;
    }
    else {
        new->payload_len = payload_len;
        new->payload = (uint8_t *)malloc(payload_len);
        if (!new->payload){
            debug_print("malloc error: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        memcpy(new->payload, payload, payload_len);
    }
    // TODO SET OTHER FIELDS
    return new;
}

static int get_payload_offset(uint8_t isIPv4, const uint8_t *data_p)
{
	const struct tcphdr *tcp;
	int payload_offset;
#ifdef DEBUG
	debug_print("isIPv4<%hhu>\n", isIPv4);
#endif
	if (isIPv4) {
		const struct iphdr *iph;

		iph = (const struct iphdr *)data_p;
		tcp = (const struct tcphdr *)(data_p + (iph->ihl<<2));
		payload_offset = ((iph->ihl)<<2) + (tcp->doff<<2);
#ifdef DEBUG
		debug_print("offset<%d>\n", payload_offset);
#endif
		return payload_offset;
	}
	else {
		const struct ip6_hdr *ip6h;
		const struct ip6_ext *ip_ext_p;
		uint8_t nextHdr;
		int count = 8;

		ip6h = (const struct ip6_hdr *)data_p;
		nextHdr = ip6h->ip6_nxt;
		ip_ext_p = (const struct ip6_ext *)(ip6h + 1);
		payload_offset = sizeof(struct ip6_hdr);

		do
		{
			if ( nextHdr == IPPROTO_TCP )
			{
					tcp = (struct tcphdr *)ip_ext_p;
					payload_offset += tcp->doff << 2;
#ifdef DEBUG
					debug_print("offset<%d>\n", payload_offset);
#endif
					return payload_offset;
			}

			payload_offset += (ip_ext_p->ip6e_len + 1) << 3;
			nextHdr = ip_ext_p->ip6e_nxt;
			ip_ext_p = (struct ip6_ext *)(data_p + payload_offset);
			count--; /* at most 8 extension headers */
		} while(count);
	}

	return -1;
}

packet_t *packet_create_nfdata(struct nfq_data *nfad)
{
    if (!nfad) {
        debug_print("%s\n", "packet_create_nfdata nullptr");
        exit(EXIT_FAILURE);
    }
    packet_t *new = (packet_t *)malloc(sizeof(packet_t));
    if (!new) {
        debug_print("Packet create failure: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfad);
	if (ph) {
		new->id = ntohl(ph->packet_id);
	}
   
    // nfq doc is shit, not sure how long ptr to nfq_data remains valid, so copy to our own buffer
    uint8_t *data;
    int datalen = nfq_get_payload(nfad, &data);
    if (datalen <= 0) {
        debug_print("%s\n", "nfq_get_payload fail datalen == -1");
        exit(EXIT_FAILURE);
    }
    new->payload_len = (uint32_t) datalen;
    new->payload = (uint8_t *)malloc(new->payload_len);
    memcpy(new->payload, data, new->payload_len);

    // Get other data
    // MAC

    // Can only get MAC from source
    memset(&new->src.mac, 0, 8);
    memset(&new->dst.mac, 0, 8);

    struct nfqnl_msg_packet_hw * pk_hw = NULL;
    pk_hw = nfq_get_packet_hw(nfad);
    if(pk_hw != 0) {
        for(int i = 0; i < 6; i++) {
            new->src.mac[i] = pk_hw->hw_addr[i];
        }
    }
    else {
        debug_print("%s\n", "Can't get source mac addr!\r");
    }

    // IPV4
    const struct tcphdr *tcp = NULL;
    uint8_t isIPv4;

    isIPv4 = (((struct iphdr *)data)->version == 4) ? 1 : 0;

	if (isIPv4 == 0) {
		// IPV6
        struct ip6_hdr *ip6h = (struct ip6_hdr *)data;
        new->src.family = 6;
        new->dst.family = 6;
        memcpy(&(new->src.address.address_un_in6), &(ip6h->ip6_src), sizeof(struct in6_addr));
        memcpy(&(new->dst.address.address_un_in6), &(ip6h->ip6_dst), sizeof(struct in6_addr));
		tcp = (const struct tcphdr *)(ip6h + 1);
	}
	else {
		// IPV4
        struct iphdr *iph = (struct iphdr *)data;
		new->src.family = 4;
        new->dst.family = 4;
        memcpy(&(new->src.address.address_un_in4), &(iph->saddr), sizeof(struct in_addr));
        memcpy(&(new->dst.address.address_un_in4), &(iph->daddr), sizeof(struct in_addr));
		tcp = (const struct tcphdr *)(data + (iph->ihl<<2));
	}

    // in network format
	new->sp = tcp->source;
	new->dp = tcp->dest;

    // allow invalid value
    new->data_offset = get_payload_offset(isIPv4, data);

    return new;
}

void packet_destroy(packet_t **packet)
{
    if (!packet || !(*packet)) {
        debug_print("%s\n", "packet_destroy error: nullptr");
        exit(EXIT_FAILURE);
    }
    // can free(0)
    packet_t *pkt_ptr = *packet;
    free(pkt_ptr->payload);
    pkt_ptr->payload = 0;
    pkt_ptr->payload_len = 0;
    free(pkt_ptr);
    *packet = 0;
}

void packet_payload_realloc(packet_t *packet, uint8_t *new_payload, uint16_t new_payload_len)
{
    if(!packet) {
        debug_print("%s\n", "packet error: nullptr");
        exit(EXIT_FAILURE);
    }
    if (!new_payload || new_payload_len == 0) {
        free(packet->payload);
        packet->payload = NULL;
        packet->payload_len = 0;
    }
    else {
        packet->payload_len = new_payload_len;
        packet->payload = realloc(packet->payload, new_payload_len);
        if (!packet->payload){
            debug_print("realloc error: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        memcpy(packet->payload, new_payload, new_payload_len);
    }
}

uint8_t *packet_get_src_mac(packet_t *packet)
{
    return &packet->src.mac;
}
