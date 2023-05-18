#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <syslog.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>


#include "packet.h"
#include "packet_pool.h"
#include "debug.h"
#include "filter.h"

// NEEDED for struct tcphdr
#define _GNU_SOURCE

// TODO: https://netfilter.org/projects/libnetfilter_queue/doxygen/html/ -> Performance

// NFQ handle list, each queue get 1
struct nfq_handle **h = NULL;
struct nfnl_handle **nh = NULL;
struct nfq_q_handle **qh = NULL;
// Recv fd, each queue get 1
int *nfq_recv_fd = NULL;
// Packet pools, each queue get 1
packet_pool_t **packet_pools;
// Lock for nfq_handle_packet, each queue get 1
// Not sure if this is thread safe - lock it, pushing to pool is relatively quick so can take some mutex penalty
// Also is nfq_set_verdict thread safe
pthread_mutex_t *nfq_handle_packet_locks = NULL;
// Threads list
// Each queue get 1 read thread and 1 verdict thread
pthread_t *read_threads = NULL;
pthread_t *verdict_threads = NULL;
// init-ed
bool inited = false;
// Need a list of queue num ptrs to pass to callbacks & thread handlers
uint32_t *queue_num_list = NULL;

_Atomic uint8_t is_startup_rst = 1;
pthread_spinlock_t startup_rst_lock;
startup_ip_node *startup_ip_list = NULL;
_Atomic unsigned int ip_list_count=0;



void insertionSort(startup_ip_node **list_handle)
{
	int i, j;
	startup_ip_node *tmp=0;
	startup_ip_node *sorted_p = *list_handle, *unsorted_p=*list_handle;
	sorted_p=sorted_p->next;
	while(sorted_p && unsorted_p->ip > sorted_p->ip )
	{
		tmp=sorted_p;
		sorted_p=sorted_p->next;
	}
	if(tmp!=0)
	{
		*list_handle = unsorted_p->next;
		unsorted_p->next=tmp->next;
		tmp->next=unsorted_p;
	}

	tmp = *list_handle;
}

ret_t binarySearch(startup_ip_node *list_handle, int l, int r, uint64_t data)
{
	startup_ip_node *middle = list_handle, *l_p;
	unsigned int m = 0;
	int i = 0;
	
	if(r>=0){
	r--;
	while(l <= r){
		m = l + (r-l)/2;
		l_p=middle;//at first search middle == head of list
		for( ; i < m; i++)
		{
			middle = middle->next;
		}
		if(data == middle->ip)
		{
			return RETURN_SUCCESS;
		}
		else if(data < middle->ip)
		{
			r = m - 1;
			i = l;
			middle= i==0 ? l_p : l_p->next;
		}
		else
		{
			l = m + 1;
		}
	}
	}
	return RETURN_FAILURE;
}

void startup_ip_push(startup_ip_node **list_handle, uint64_t data)
{
	if (!data) {
		debug_print("%s\n", "IP LIST PUSH NULLPTR");
		exit(EXIT_FAILURE);
	}
	startup_ip_node *next_node = (startup_ip_node*)malloc(sizeof(startup_ip_node));
	if (!next_node) {
		debug_print("IP LIST PUSH MALLOC ERROR %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	next_node->ip = data;
	next_node->next = *list_handle;
	*list_handle = next_node;
    ip_list_count++;
	insertionSort(list_handle);

}

ret_t startup_ip_search_node(startup_ip_node *list_handle, uint64_t data)
{
	if(!data) {
		debug_print("%s\n", "IP LIST SEARCH data NULLPTR");
		exit(EXIT_FAILURE);
	}
	if(!list_handle){
		debug_print("%s\n", "IP LIST SEARCH list_handle NULLPTR");
		return RETURN_FAILURE;
	}
	//startup_ip_node *tmp = list_handle;
	//while(tmp) {
	return binarySearch(list_handle, 0, ip_list_count, data);
		//if(tmp->ipv4_src == data->src.address.address_un_in4.s_addr){
		//    if(tmp->ipv4_dst == data->dst.address.address_un_in4.s_addr){
		//		break;
		//	}
		//}
	//	tmp = tmp->next;
	//}
	//return tmp;
}

void startup_ip_flush_all_node(startup_ip_node **list_handle)
{
	if(!list_handle) {
		debug_print("%s\n", "IP LIST DEL NULLPTR");
		return;
	}
	startup_ip_node *tmp = 0;
	startup_ip_node *head = *list_handle;
	while(head)
	{
		if(head->next) {
			tmp = head->next;
		}
		else tmp = 0;
		head->next = 0;
		free(head);
		head = tmp;
	}
	*list_handle = 0;
}

/* 
static int updateOffset(uint8_t isIPv4, const char *data_p)
{
	const struct tcphdr *tcp;
	int payload_offset;
#ifdef DEBUG
	debug_print("isIPv4<%d>\n", isIPv4);
#endif
	if (isIPv4)
	{
		const struct iphdr *iph;

		iph = (const struct iphdr *)data_p;
		tcp = (const struct tcphdr *)(data_p + (iph->ihl<<2));
		payload_offset = ((iph->ihl)<<2) + (tcp->doff<<2);
#ifdef DEBUG
		debug_print("offset<%d>\n", payload_offset);
#endif
		return payload_offset;
	}
	else
	{
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
			count--; // at most 8 extension headers
		} while(count);
	}

	return -1;
}
 */

/* 
static int pkt_decision_old(struct nfq_data * payload)
{
	char *data = NULL;
	SSL_PAYLOAD ssl_payload={0};
	char *tcp_pkt_payload = NULL;
	int payload_offset, data_len;

	struct iphdr *iph = NULL;
	struct ip6_hdr *ip6h = NULL;
	
	uint8_t isIPv4;

	const struct tcphdr *tcp = NULL;
	uint16_t tcp_sport; // source port
    uint16_t tcp_dport; // destination port

	unsigned char src_ip[4];
	unsigned char src_ip_v6[64] = {0};

	char *tmp_str = NULL;
	char *tmp_str_2 = NULL;
	size_t host_header_size;

	data_len = nfq_get_payload(payload, &data);
	if( data_len == -1 )
	{
		debug_print("%s\n", "data_len == -1!!!!!!!!!!!!!!!, EXIT");
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG
	debug_print("data_len=%d ", data_len);
#endif

	// IPV4
	iph = (struct iphdr *)data;
	isIPv4 = (iph->version == 4) ? 1 : 0;
	
	if (isIPv4 == 0)
	{
		// IPV6
		ip6h = (struct ip6_hdr *)data;
		inet_ntop(AF_INET6, &(ip6h->ip6_src), (char *)src_ip_v6, INET6_ADDRSTRLEN);
		tcp = (const struct tcphdr *)(ip6h + 1);
	}
	else {
		// IPV4
		src_ip[0] = iph->saddr & 0xFF;
		src_ip[1] = (iph->saddr >> 8) & 0xFF;
		src_ip[2] = (iph->saddr >> 16) & 0xFF;
		src_ip[3] = (iph->saddr >> 24) & 0xFF;
		tcp = (const struct tcphdr *)(data + (iph->ihl<<2));
	}

	tcp_sport = ntohs(tcp->source);
	tcp_dport = ntohs(tcp->dest);

	payload_offset = updateOffset(isIPv4, data);

	pkt_decision_enum verdict = PKT_ACCEPT; // pass by default

	if (payload_offset < 0)
	{
		// always accept the packet if error happens
		return PKT_ACCEPT;
	}

	tcp_pkt_payload = (char *)(data + payload_offset);


#ifdef DEBUG
	debug_print("Packet from port %hu to %hu\n", tcp_sport, tcp_dport);
#endif

#ifdef DEBUG
	debug_print("%s\n", "PACKET DATA");
	for (int i = 0; i < 50; i++) {
		debug_print("%02X\t%02X\t%02X\t%02X\t%02X\t%02X\t%02X\t%02X\t%02X\t%02X\n",
			(unsigned char)tcp_pkt_payload[i],
			(unsigned char)tcp_pkt_payload[i + 1],
			(unsigned char)tcp_pkt_payload[i + 2],
			(unsigned char)tcp_pkt_payload[i + 3],
			(unsigned char)tcp_pkt_payload[i + 4],
			(unsigned char)tcp_pkt_payload[i + 5],
			(unsigned char)tcp_pkt_payload[i + 6],
			(unsigned char)tcp_pkt_payload[i + 7],
			(unsigned char)tcp_pkt_payload[i + 8],
			(unsigned char)tcp_pkt_payload[i + 9]
		);
	}
#endif

	if (tcp_dport == 443) {
		// https
		if(tcp_pkt_payload[0] == 22) // TYPE HANDSHAKE
		{
			if (construct_ssl_payload(&ssl_payload, tcp_pkt_payload) == 0) {
#ifdef DEBUG
				debug_print("%s", "\r\nConstruct ssl payload success!!\r\n");
#endif
				if(ssl_payload.sn){
#ifdef DEBUG
					debug_print("%s\n", ssl_payload.sn);
#endif
					if (!blocked_domain_tree_ptr) {
						debug_print("%s\n", "Domain list not initialized!");
						exit(EXIT_FAILURE);
					}
					if (domain_tree_search_domain(blocked_domain_tree_ptr, ssl_payload.sn)) {
#ifdef DEBUG
						debug_print("DROPPED %s\n", ssl_payload.sn);
#endif
						return PKT_DROP;
					}
					else
						return PKT_ACCEPT;
				}
				ssl_payload_cleaner(&ssl_payload);
			}
			else {
#ifdef DEBUG
				debug_print("%s", "\r\nSomething went wrong when constructing ssl payload!!!!\r\n");
#endif
				ssl_payload_cleaner(&ssl_payload);
				// always accept the packet if error happens
				return PKT_ACCEPT;
			}
		}
	}
	else
	if (tcp_dport == 80) {
		// http
		// Don't see the need to be strict about this, we are not handling any data,
		// just to confirm its http
		if(tcp_pkt_payload[0] != 'G' && // GET
			tcp_pkt_payload[0] != 'H' && // HEAD
			tcp_pkt_payload[0] != 'P' ) // POST
		{
#ifdef DEBUG
			debug_print("%s\n","Received packet in port 80 with invalid HTTP method");
#endif
			return PKT_ACCEPT;
		}
		tmp_str = strcasestr(tcp_pkt_payload, "Host: ");
		if (tmp_str == NULL) {
#ifdef DEBUG
			debug_print("%s\n", "Suspected HTTP packet hoes not have host header, pass...");
#endif
			return PKT_ACCEPT;
		}
		tmp_str += 6; // strlen("Host: "), sizeof returns 7 must -1
		host_header_size = strcspn(tmp_str, "\r\n");
		tmp_str_2 = (char *)malloc(host_header_size + 1);
		strncpy(tmp_str_2, tmp_str, host_header_size);
		tmp_str_2[host_header_size] = '\x00';
		if (domain_tree_search_domain(blocked_domain_tree_ptr, tmp_str_2)) {
#ifdef DEBUG
			debug_print("DROPPED %s\n", tmp_str_2);
#endif
			verdict = PKT_DROP;
		}
		free(tmp_str_2);
		return verdict;
	}
	return PKT_ACCEPT;
}
 */

static uint16_t checksum(uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= sizeof (uint16_t);
    }

    if (nleft == 1)
    {
        *(uint8_t *) (&answer) = *(uint8_t *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}
 

/*
 * Build IPv4 TCP pseudo-header and call checksum function
 */

static uint16_t tcp4_checksum(struct iphdr ip_hdr, struct tcphdr tcphdr, const u_char *payload, int payloadlen)
{
    uint16_t svalue, optionslen, bound_32;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int i, chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy(ptr, &ip_hdr.saddr, sizeof(ip_hdr.saddr));
    ptr += sizeof (ip_hdr.saddr);
    chksumlen += sizeof (ip_hdr.saddr);

    // Copy destination IP address into buf (32 bits)
    memcpy(ptr, &ip_hdr.daddr, sizeof(ip_hdr.daddr));
    ptr += sizeof(ip_hdr.daddr);
    chksumlen += sizeof(ip_hdr.daddr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy(ptr, &ip_hdr.protocol, sizeof(ip_hdr.protocol));
    ptr += sizeof(ip_hdr.protocol);
    chksumlen += sizeof(ip_hdr.protocol);

    // Copy TCP length to buf (16 bits)
    svalue = htons((tcphdr.th_off << 2) + payloadlen);
    memcpy(ptr, &svalue, sizeof(svalue));
    ptr += sizeof(svalue);
    chksumlen += sizeof(svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
    ptr += sizeof(tcphdr.th_sport);
    chksumlen += sizeof(tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy(ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
    ptr += sizeof(tcphdr.th_seq);
    chksumlen += sizeof(tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
    ptr += sizeof(tcphdr.th_ack);
    chksumlen += sizeof(tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy(ptr, &cvalue, sizeof(cvalue));
    ptr += sizeof(cvalue);
    chksumlen += sizeof(cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
    ptr += sizeof(tcphdr.th_flags);
    chksumlen += sizeof(tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
    ptr += sizeof(tcphdr.th_win);
    chksumlen += sizeof(tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
    ptr += sizeof(tcphdr.th_urp);
    chksumlen += sizeof(tcphdr.th_urp);

    // Copy options field
    optionslen = (tcphdr.th_off << 2) - sizeof(tcphdr);
    if (optionslen > 0)
    {
        memcpy(ptr, payload-optionslen, optionslen);
        ptr += optionslen;
        chksumlen += optionslen;

        // Pad to the next 32-bit boundary
        if ((bound_32 = 4 - optionslen%4) == 4)
            bound_32 = 0;
        for (i=0; i<bound_32; i++)
        {
            *ptr = 0;
            ptr++;
            chksumlen++;
        }
    }

    // Copy payload to buf
    if (payloadlen > 0)
    {
        memcpy(ptr, payload, payloadlen);
        ptr += payloadlen;
        chksumlen += payloadlen;

        // Pad to the next 16-bit boundary
        for (i=0; i<payloadlen%2; i++, ptr++)
        {
            *ptr = 0;
            ptr++;
            chksumlen++;
        }
    }

    return checksum((uint16_t *) buf, chksumlen);
}

// send the constructed packet to client
static void send_packet_to_socket(char *packet, int len, struct ether_header *eh)
{
    struct sockaddr_ll device;
    int send_sockfd;
    int bytes;

    // init the device which the packet should be sent to

    memset(&device, 0, sizeof(device));

    if ((device.sll_ifindex = if_nametoindex(filtered_iface)) == 0)
    {
		debug_print("Failed to obtain interface index %s\n", filtered_iface);
        exit(EXIT_FAILURE);
    }

    // fill out remaining sockaddr_ll members.
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, eh->ether_dhost, 6 * sizeof (uint8_t));
    device.sll_halen = htons(6);

    // submit request for a raw socket descriptor.
    if ((send_sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    //  send ethernet frame to socket.
    if ((bytes = sendto(send_sockfd, packet, len, 0, (struct sockaddr *) &device, sizeof (device))) <= 0)
    {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    close(send_sockfd);
}

static int tcp_reset_ipv4(packet_t *pkt)
{
    char sendbuf[1024];
    int tx_len = 0; // total length of ethernet frame
    unsigned char *http_payload; // the payload of TCP, here points to HTTP 
    unsigned short size_payload = 0; // the payload size of TCP

	struct iphdr *iph;
	uint8_t isIPv4;
	int i;

	const struct tcphdr *tcp;
	int httppktlen = 0;
	int payload_offset = 0;
	
    struct ether_header *eh = (struct ether_header *) sendbuf;
    struct iphdr *ip_hdr = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    struct tcphdr *tcp_hdr = (struct tcphdr *) (sendbuf + sizeof(struct ether_header) + (int)sizeof(struct iphdr));
    http_payload = (u_char *)(sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr) + (int)sizeof(struct tcphdr));
    
	//Comment this part if run on pc
	//uint8_t *mac = packet_get_src_mac(pkt);

	//int check_mac=0;
	//for(int i=0; i<8; i++)
	//{
	//	check_mac+=mac[i];
	//}
	//if(check_mac==0)
    //    return 0;

    // Construct the Ethernet header
    memset(sendbuf, 0, sizeof(sendbuf));

	iph = (struct iphdr *)pkt->payload;
	isIPv4 = (iph->version == 4) ? 1 : 0;
	if(isIPv4 == 0)
        return -1;

	//Use this when debugging on pc
	char test[8];
	char macAddr3[32]="42:d7:69:ae:8e:81"; //mac address of gateway
	sscanf(macAddr3,"%02x:%02x:%02x:%02x:%02x:%02x",&test[0],&test[1],&test[2],&test[3],&test[4],&test[5]);


	for (i = 0; i < 6; i++) {
       eh->ether_shost[i] = filtered_iface_mac[i];
       eh->ether_dhost[i] = test[i];
	// Use this when debugging on pc
	//    eh->ether_shost[i] = filtered_iface_mac[i];
    //    eh->ether_dhost[i] = test[i];
    }

	eh->ether_type = htons(ETHERTYPE_IP);
    tx_len += sizeof(struct ether_header);
	

	tcp = (const struct tcphdr *)(pkt->payload + (iph->ihl<<2));
	payload_offset = ((iph->ihl)<<2) + (tcp->doff<<2);
    httppktlen = pkt->payload_len - payload_offset;
    // Construct IP Header
    memcpy(ip_hdr, iph, sizeof(struct iphdr));
    //ip_hdr->ip_len = htons(size_payload + (ip->ip_hl << 2) + (tcp->th_off << 2));   //set it after http payload 
    ip_hdr->saddr = iph->daddr;
    ip_hdr->daddr = iph->saddr;
    ip_hdr->check = 0;
    //ip_hdr->ip_sum = checksum((uint16_t *)ip_hdr, sizeof(struct ip));  // set it after http payload
    tx_len += sizeof(struct iphdr);

    // Construct TCP Header
    memcpy(tcp_hdr, tcp, sizeof(struct tcphdr));
    tcp_hdr->th_sport = tcp->th_dport;
    tcp_hdr->th_dport = tcp->th_sport;
    tcp_hdr->th_seq = tcp->th_ack;
    tcp_hdr->th_ack = htonl(ntohl(tcp->th_seq) + httppktlen);
    
	//tcp_hdr->th_flags = TH_RST;//Sending back: client(no),server(no)
	//tcp_hdr->th_flags = TH_RST|TH_ACK; //Sending back: client(yes:RST),server(no)
	tcp_hdr->th_flags = TH_FIN|TH_PUSH|TH_ACK;//Sending back: client(yes:FIN|PUSH|ACK),server(no:NOT even work)
    //We can only send FIN|PUSH|ACK to the client. Don't know why, but when client sends back a FIN|PUSH|ACK packet, we saw a SSL in it. That's maybe the reason.



    tcp_hdr->th_off = TCP_HEADER_LENGTH_WORDS; // some http packet from mobile has tcp header 32 bytes with 12 bytes timestamps option, we just ignore the option and always response 20bytes 
    tx_len += sizeof(struct tcphdr);
	tx_len += 60 - tx_len; // TCP frame min 60 bytes

    // fill out ip total length and checksum here 
    ip_hdr->tot_len = htons(size_payload + sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    // fill out tcp checksum option here 
    tcp_hdr->th_sum = tcp4_checksum(*ip_hdr, *tcp_hdr, http_payload, size_payload);
	
    //  send ethernet frame packet to client.
#ifdef DEBUG
	debug_print("%s\n", "send_packet_to_socket");
#endif
    send_packet_to_socket(sendbuf, tx_len, eh);

	return 0;
}


static uint16_t tcp6_checksum(struct ip6_hdr iphdr, struct tcphdr tcphdr, const u_char *payload, int payloadlen)
{
	uint32_t lvalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int i, chksumlen = 0;

	ptr = &buf[0]; 

	memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
	ptr += sizeof (iphdr.ip6_src);
	chksumlen += sizeof (iphdr.ip6_src);

	// Copy destination IP address into buf (128 bits)
	memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
	ptr += sizeof (iphdr.ip6_dst);
	chksumlen += sizeof (iphdr.ip6_dst);

	// Copy TCP length to buf (32 bits)
	lvalue = htonl (sizeof (tcphdr) + payloadlen);
	memcpy (ptr, &lvalue, sizeof (lvalue));
	ptr += sizeof (lvalue);
	chksumlen += sizeof (lvalue);

	// Copy zero field to buf (24 bits)
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 3;

	// Copy next header field to buf (8 bits)
	memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
	ptr += sizeof (iphdr.ip6_nxt);
	chksumlen += sizeof (iphdr.ip6_nxt);

	// Copy TCP source port to buf (16 bits)
	memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
	ptr += sizeof (tcphdr.th_sport);
	chksumlen += sizeof (tcphdr.th_sport);

	// Copy TCP destination port to buf (16 bits)
	memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
	ptr += sizeof (tcphdr.th_dport);
	chksumlen += sizeof (tcphdr.th_dport);

	// Copy sequence number to buf (32 bits)
	memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
	ptr += sizeof (tcphdr.th_seq);
	chksumlen += sizeof (tcphdr.th_seq);

	// Copy acknowledgement number to buf (32 bits)
	memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
	ptr += sizeof (tcphdr.th_ack);
	chksumlen += sizeof (tcphdr.th_ack);

	// Copy data offset to buf (4 bits) and
	// copy reserved bits to buf (4 bits)
	cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
	memcpy (ptr, &cvalue, sizeof (cvalue));
	ptr += sizeof (cvalue);
	chksumlen += sizeof (cvalue);

	// Copy TCP flags to buf (8 bits)
	memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
	ptr += sizeof (tcphdr.th_flags);
	chksumlen += sizeof (tcphdr.th_flags);

	// Copy TCP window size to buf (16 bits)
	memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
	ptr += sizeof (tcphdr.th_win);
	chksumlen += sizeof (tcphdr.th_win);

	// Copy TCP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy urgent pointer to buf (16 bits)
	memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
	ptr += sizeof (tcphdr.th_urp);
	chksumlen += sizeof (tcphdr.th_urp);

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}
 

static int redirect_ipv6(packet_t *pkt)
{
	char sendbuf[2048] = {0};
	int tx_len = 0; // total length of ethernet frame 
	unsigned char *payload; // the payload of TCP, here points to HTTP 
	unsigned short size_payload = 0; // the payload size of TCP

	char *data;
	int data_len;

	struct nfqnl_msg_packet_hw * pk_hw = NULL;
	struct ip6_hdr *ip6h = NULL;
	int i;
	FILE *fp = NULL;

	struct tcphdr *tcp = NULL;
	int httppktlen = 0;
	int payload_offset = 0;

	struct ether_header *eth_hdr = (struct ether_header *) sendbuf;
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) (sendbuf + sizeof(struct ether_header));
	struct tcphdr *tcp_hdr = (struct tcphdr *) (sendbuf + sizeof(struct ether_header) + (int)sizeof(struct ip6_hdr));
	payload = (u_char *)(sendbuf + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + (int)sizeof(struct tcphdr));

	memset(sendbuf, 0, sizeof(sendbuf));
    //Comment this part if run on pc
	uint8_t *mac = packet_get_src_mac(pkt);
	int check_mac=0;
	for(int i=0; i<8; i++)
	{
		check_mac+=mac[i];
	}
	if(check_mac==0)
        return 0;
	//------------------------------
	
	// Construct Ethernet header
	for (i=0; i<6; i++)
	{
		eth_hdr->ether_shost[i] = mac[i];
		eth_hdr->ether_dhost[i] = filtered_iface_mac[i];
	}
	eth_hdr->ether_type = htons(ETHERTYPE_IPV6);
	tx_len += sizeof(struct ether_header);

	// Construct IP Header
	ip6h = (struct ip6_hdr *)pkt->payload;
	memcpy(ipv6_hdr, ip6h, sizeof(struct ip6_hdr));
	ipv6_hdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
	// Payload length (16 bits): TCP header + TCP data --> Configure it later
	//ipv6_hdr->ip6_plen = htons (TCP_HDRLEN + payloadlen);
	// Next header (8 bits): 6 for TCP
	ipv6_hdr->ip6_nxt = IPPROTO_TCP;
	// Hop limit (8 bits): default to maximum value
	ipv6_hdr->ip6_hops = 255;
	memcpy(&ipv6_hdr->ip6_src, &ip6h->ip6_dst, sizeof (struct in6_addr));
	memcpy(&ipv6_hdr->ip6_dst, &ip6h->ip6_src, sizeof (struct in6_addr));
	tx_len += sizeof(struct ip6_hdr);

	// Construct TCP Header
	struct ip6_ext *ip_ext_p = NULL;
	uint8_t nextHdr;
	int count = 8;

	nextHdr = ipv6_hdr->ip6_nxt;
	ip_ext_p = (struct ip6_ext *)(ip6h + 1);
	payload_offset = sizeof(struct ip6_hdr);
	do
	{
		if (nextHdr == IPPROTO_TCP)
		{
			tcp = (struct tcphdr *)ip_ext_p;
			payload_offset += tcp->doff << 2;
#ifdef DEBUG
			debug_print("offset<%d>\n", payload_offset);
#endif
			break;
		}

		payload_offset += (ip_ext_p->ip6e_len + 1) << 3;
		nextHdr = ip_ext_p->ip6e_nxt;
		ip_ext_p = (struct ip6_ext *)(pkt->payload + payload_offset);
		count--; // at most 8 extension headers
	} while(count);

	if (tcp == NULL)
	{
		debug_print("%s", "cannot find IPv6 TCP Header!!\n");
		return 0;
	}

	httppktlen = pkt->payload_len - payload_offset;
	memcpy(tcp_hdr, tcp, sizeof(struct tcphdr));
	tcp_hdr->th_sport = tcp->th_sport;
	tcp_hdr->th_dport = tcp->th_dport;
	tcp_hdr->th_seq = htonl(ntohl(tcp->th_seq) + httppktlen);
	tcp_hdr->th_ack = tcp->th_ack;
	tcp_hdr->th_flags = TH_RST;
	tcp_hdr->th_off = TCP_HEADER_LENGTH_WORDS; // some http packet from mobile has tcp header 32 bytes with 12 bytes timestamps option, we just ignore the option and always response 20bytes
	tx_len += sizeof(struct tcphdr);

    //TODO LOCATION

	// Construct http payload with 302 Redirect
	/*
	strcpy(&sendbuf[tx_len], "HTTP/1.1 302 Redirect\r\n");
	tx_len += strlen("HTTP/1.1 302 Redirect\r\n");
	size_payload += strlen("HTTP/1.1 302 Redirect\r\n");
	strcpy(&sendbuf[tx_len], "Cache-Control: no-cache\r\n");
	tx_len += strlen("Cache-Control: no-cache\r\n");
	size_payload += strlen("Cache-Control: no-cache\r\n");

	strcpy(&sendbuf[tx_len], "Location: http://127.0.0.1\r\n");
	tx_len += strlen("Location: http://127.0.0.1\r\n");
	size_payload += strlen("Location: http://127.0.0.1\r\n");

	strcpy(&sendbuf[tx_len], "Content-Type: text/html\r\n");
	tx_len += strlen("Content-Type: text/html\r\n");
	size_payload += strlen("Content-Type: text/html\r\n");
	strcpy(&sendbuf[tx_len], "Connection: Close\r\n\r\n");
	tx_len += strlen("Connection: Close\r\n\r\n");
	size_payload += strlen("Connection: Close\r\n\r\n");
    */
	// fill out ip total length and checksum here 
	ipv6_hdr->ip6_plen = htons(size_payload + sizeof(struct tcphdr));

	// fill out tcp checksum option here 
	tcp_hdr->th_sum = tcp6_checksum(*ipv6_hdr, *tcp_hdr, payload, size_payload);

	//  send ethernet frame packet to client.
	send_packet_to_socket(sendbuf, tx_len, eth_hdr);

	return 0;
}


/*
static int call_back_old(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	int decision, id=0;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
	{
		id = ntohl(ph->packet_id);
	}

	// check if we should block this packet
	decision = pkt_decision(nfa);
	if( decision == PKT_ACCEPT)
	{
#ifdef DEBUG
		debug_print("ACCEPT packet ID %d\n", id);
#endif
		// TODO MAKE THREAD SAFE
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else
	{
		if(is_redirect && nfa)
		{
			int ret = 0;
			ret = construct_raw_packet(nfa); //redirect to localhost
			if (ret == -1)
			{
				construct_raw_packet_ipv6(nfa);
			}
			
		}
#ifdef DEBUG
			debug_print("DROP packet ID %d\n", id);
#endif
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
}
*/

uint8_t construct_ssl_payload(SSL_PAYLOAD *ssl_payload, char *payload)
{
    unsigned short offset=0;
#ifdef DEBUG
	debug_print("%s", "****Data recieved!!!\n\r");
	debug_print("%s", "***Secure Sockets Layer:\r\n");
#endif

	ssl_payload->content_type=payload[0];
#ifdef DEBUG
	debug_print("Content-type: Handshake(%d)\n\r", ssl_payload->content_type);
#endif

	if(payload[5]==1){
	ssl_payload->handshake_protocol=1;
#ifdef DEBUG
	debug_print("Handshake Protocol: Client Hello(%d)\n\r", ssl_payload->handshake_protocol);
#endif
	}
	else {
    ssl_payload->handshake_protocol=16;
#ifdef DEBUG
	debug_print("%s", "Handshake Protocol: not client hello\r\n");
#endif
	return 1;
	}
	
	ssl_payload->handshake_length = ((unsigned int)payload[6]<<(8*2))|((unsigned short)payload[7]<<8)|(unsigned char)payload[8];
	#ifdef DEBUG
	debug_print("Length: %u\n\r", ssl_payload->handshake_length);
    #endif
	if(ssl_payload->handshake_length >= PKT_BUFF_SIZE)
	    return 1;

	offset=43;//offset to session_id_len due to all the above parts are fixed length
#ifdef DEBUG
	debug_print("%s", "\r\n");
#endif
	ssl_payload->session_id_len=(unsigned char)payload[offset];
	#ifdef DEBUG
	debug_print("Session ID Length: %d\n\r", ssl_payload->session_id_len);//correct
	#endif
	
	offset = offset + ssl_payload->session_id_len;///ssl_payload->session_id
	
	if (offset >= ssl_payload->handshake_length-1)
	    return 1;
	offset += (((unsigned short)payload[offset+=1]<<8)|(unsigned char)payload[offset+=1]);//ssl_payload->cipher_sui_len
	
	if (offset >= ssl_payload->handshake_length)
	    return 1;

    offset += payload[offset+=1];//ssl_payload->comp_meth_len + 2bytes of ssl_payload->extension_len
	
	if (offset >= ssl_payload->handshake_length - 3)
	    return 1;

	//find sni extension start from here ssl_payload->extension_len

    ssl_payload->extension_field_len = (((unsigned short)payload[offset+=1]<<8)|(unsigned char)payload[offset+=1]);
	if (ssl_payload->extension_field_len > ssl_payload->handshake_length)
	    return 1;
	for(int i=0;i<ssl_payload->extension_field_len-2;i++){
	    switch(((unsigned short)payload[offset+=1]<<8)|(unsigned char)payload[offset+=1])
		{
			case 0:
				offset += 5; // 2 of ssl_payload->server_name_len + 2 of ssl_payload->sn_list_len + 1 of ssl_payload->sn_type
	            if (offset >= ssl_payload->handshake_length - 1)
	                return 1;
			    ssl_payload->sn_len = ((unsigned short)payload[offset+=1]<<8)|(unsigned char)payload[offset+=1];
#ifdef DEBUG
			    debug_print("***Server Name length: %d\n\r",ssl_payload->sn_len);

#endif
                if(ssl_payload->sn_len > 65535)
				    return 1;
				ssl_payload->sn=(char*)calloc(ssl_payload->sn_len+1,sizeof(char));
	            strncpy(ssl_payload->sn,(payload+offset+1),ssl_payload->sn_len);
#ifdef DEBUG
	            debug_print("***Server Name: %s\r\n",ssl_payload->sn);
#endif
			    return 0;

			default:
#ifdef DEBUG
			    debug_print("%s","Not server name extension\r\n");
#endif
			    ssl_payload->extension_len=((unsigned short)payload[offset+=1]<<8)|(unsigned char)payload[offset+=1];//ssl_payload->extension_len
			    offset+=ssl_payload->extension_len;
				if(offset >= ssl_payload->handshake_length -1)	
				    return 1;
		}
	}
#ifdef DEBUG
		debug_print("Type: (%u) not server_name\n\r", ssl_payload->extension_type);
#endif
	return 1;
}

static void ssl_payload_cleaner(SSL_PAYLOAD *ssl_payload)
{
	if (!ssl_payload) {
		debug_print("%s\n", "ssl_payload_cleaner NULLPTR");
		exit(EXIT_FAILURE);
	}
	// FREE MALLOCED ONLY
	if (ssl_payload->handshake_random){
		free(ssl_payload->handshake_random);
		ssl_payload->handshake_random=0;
	}
	if (ssl_payload->session_id){
		free(ssl_payload->session_id);
		ssl_payload->session_id=0;
	}
	if (ssl_payload->cipher_sui){
		free(ssl_payload->cipher_sui);
		ssl_payload->cipher_sui=0;
	}
	if (ssl_payload->sn) {
		free(ssl_payload->sn);
		ssl_payload->sn=0;
	}
}


static int pkt_decision(packet_t *pkt)
{
	if (!pkt) {
		debug_print("%s\n", "pkt_decision NULLPTR");
		exit(EXIT_FAILURE);
	}

	SSL_PAYLOAD ssl_payload={0};
	char *tcp_pkt_payload = NULL;

	uint16_t tcp_sport; // source port
    uint16_t tcp_dport; // destination port

	unsigned char src_ip[4] = {0};
	unsigned char dst_ip[4] = {0};
	unsigned char src_ip_v6[64] = {0};
	unsigned char dst_ip_v6[64] = {0};

	char *tmp_str = NULL;
	char *tmp_str_2 = NULL;
	size_t host_header_size;
	uint64_t pkt_ip = 0; 
	int err;

	// IP
	if (pkt->src.family == 4) {
		// IPV4
		src_ip[0] =  pkt->src.address.address_un_in4.s_addr        & 0xFF;
		src_ip[1] = (pkt->src.address.address_un_in4.s_addr >>  8) & 0xFF;
		src_ip[2] = (pkt->src.address.address_un_in4.s_addr >> 16) & 0xFF;
		src_ip[3] = (pkt->src.address.address_un_in4.s_addr >> 24) & 0xFF;
		pkt_ip = ((uint64_t)pkt->src.address.address_un_in4.s_addr) << 32;
	}
	else {
		// IPV6
		printf("IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6IPV6");
		inet_ntop(AF_INET6, &(pkt->src.address.address_un_in6), (char *)src_ip_v6, INET6_ADDRSTRLEN);
	}

	if (pkt->dst.family == 4) {
		// IPV4
		dst_ip[0] =  pkt->dst.address.address_un_in4.s_addr        & 0xFF;
		dst_ip[1] = (pkt->dst.address.address_un_in4.s_addr >>  8) & 0xFF;
		dst_ip[2] = (pkt->dst.address.address_un_in4.s_addr >> 16) & 0xFF;
		dst_ip[3] = (pkt->dst.address.address_un_in4.s_addr >> 24) & 0xFF;
		pkt_ip |= pkt->dst.address.address_un_in4.s_addr;
	}
	else {
		// IPV6
		inet_ntop(AF_INET6, &(pkt->dst.address.address_un_in6), (char *)dst_ip_v6, INET6_ADDRSTRLEN);
	}

	// Port
	tcp_sport = ntohs(pkt->sp);
	tcp_dport = ntohs(pkt->dp);

	pkt_decision_enum verdict = PKT_ACCEPT; // pass by default

	if (pkt->data_offset < 0) {
		// always accept the packet if error happens
		return PKT_ACCEPT;
	}

	tcp_pkt_payload = (char *)(pkt->payload + pkt->data_offset);

#ifdef DEBUG
	if (pkt->src.family == 4) {
		debug_print("Packet from %hhu.%hhu.%hhu.%hhu:%hu\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3], tcp_sport);
	}
	else {
		debug_print("Packet from %s:%hu\n", src_ip_v6, tcp_sport);
	}
	if (pkt->dst.family == 4) {
		debug_print("Packet to %hhu.%hhu.%hhu.%hhu:%hu\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], tcp_dport);
	}
	else {
		debug_print("Packet to %s:%hu\n", dst_ip_v6, tcp_dport);
	}
#endif

	if (tcp_dport == 443) {
		// https
		if(tcp_pkt_payload[0] == 22) // TYPE HANDSHAKE
		{
			if (construct_ssl_payload(&ssl_payload, tcp_pkt_payload) == 0) {
#ifdef DEBUG
				debug_print("%s", "\r\nConstruct ssl payload success!!\r\n");
#endif
				if(ssl_payload.sn) {
#ifdef DEBUG
					debug_print("%s\n", ssl_payload.sn);
#endif
					if (!blocked_domain_tree_ptr) {
						debug_print("%s\n", "Domain list not initialized!");
						exit(EXIT_FAILURE);
					}

					if (domain_tree_search_domain(blocked_domain_tree_ptr, ssl_payload.sn)) {
						debug_print("DROPPED %s\n", ssl_payload.sn);
						verdict = PKT_DROP;
					}
					else {
						if(is_startup_rst) {
							if((err = pthread_spin_lock(&startup_rst_lock)) != 0){//The current thread already owns the spin lock.
								debug_print("pthread_spin_lock error: %s\n", strerror(err));
								exit(EXIT_FAILURE);
							}
							ret_t tmp = startup_ip_search_node(startup_ip_list, pkt_ip);
							if( tmp == RETURN_FAILURE) {
								startup_ip_push(&startup_ip_list, pkt_ip);
							}
							if((err = pthread_spin_unlock(&startup_rst_lock)) != 0){//The current thread already owns the spin lock.
								debug_print("pthread_spin_unlock error: %s\n", strerror(err));
								exit(EXIT_FAILURE);
							}
						}
					}
				}
			}
			else {
				// always accept the packet if error happens
#ifdef DEBUG
				debug_print("%s", "\r\nSomething went wrong when constructing ssl payload!!!!\r\n");
#endif
			}
			ssl_payload_cleaner(&ssl_payload);
		}
		else {
			// Handling non handshake pkt
			if(is_startup_rst) {
				if((err = pthread_spin_lock(&startup_rst_lock))) {
					debug_print("pthread_spin_lock error: %s\n", strerror(err));
					exit(EXIT_FAILURE);
				}
				//startup_ip_node *
				ret_t tmp = startup_ip_search_node(startup_ip_list, pkt_ip);
				if( tmp == RETURN_FAILURE) {
					//startup_ip_push(&startup_ip_list, pkt_ip);
					verdict = PKT_INIT_DROP;
				}
				if((err=pthread_spin_unlock(&startup_rst_lock))){//The current thread already owns the spin lock.
					debug_print("pthread_spin_unlock error: %s\n", strerror(err));
					exit(EXIT_FAILURE);
				}
			}
			//
		}
	}
	else if (tcp_dport == 80) {
		// http
		// Don't see the need to be strict about this, we are not handling any data,
		// just to confirm its http
		if(tcp_pkt_payload[0] == 'G' || // GET
			tcp_pkt_payload[0] == 'H' || // HEAD
			tcp_pkt_payload[0] == 'P' ) // POST
		{
			tmp_str = strcasestr(tcp_pkt_payload, "Host: ");
			if (tmp_str != NULL) {
				tmp_str += 6; // strlen("Host: "), sizeof returns 7 must -1
				host_header_size = strcspn(tmp_str, "\r\n");
				tmp_str_2 = (char *)malloc(host_header_size + 1);
				strncpy(tmp_str_2, tmp_str, host_header_size);
				tmp_str_2[host_header_size] = '\x00';
				if (domain_tree_search_domain(blocked_domain_tree_ptr, tmp_str_2)) {
					debug_print("DROPPED %s\n", tmp_str_2);
					verdict = PKT_INIT_DROP;
				}
				free(tmp_str_2);
			}
			else {
#ifdef DEBUG
				debug_print("%s\n", "Suspected HTTP packet hoes not have host header, pass...");
#endif
			}
		}
		else {
#ifdef DEBUG
			debug_print("%s\n","Received packet in port 80 with invalid HTTP method");
#endif
		}
	}
#ifdef DEBUG
	switch(verdict) {
		case PKT_ACCEPT:
			debug_print("%s\n","VERDICT PKT_ACCEPT");
			break;
		case PKT_DROP:
			debug_print("%s\n","VERDICT PKT_DROP");
			break;
		case PKT_INIT_DROP:
			debug_print("%s\n","VERDICT PKT_INIT_DROP");
			break;
		default:
			debug_print("%s\n","VERDICT FUCKED");
			break;
	}
#endif
	return verdict;
}

static int call_back(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t *queue_num_ptr = (uint32_t *)data;
	uint32_t ind = *queue_num_ptr - starting_queue;
#ifdef DEBUG
	debug_print("call_back ind %u\n", ind);
#endif
	packet_t *new = packet_create_nfdata(nfa);
	// each queue has a pool so does not need lock on the pool itself
	packet_pool_enqueue(packet_pools[ind], new);
	return 0;
}

void netlink_open_connection(uint32_t queue_num)
{
	// TODO: NOTE: From linux kernels from 3.8 onward nfq_unbind_pf / nfq_bind_pf are ignored, test on earlier..
	uint32_t ind = queue_num - starting_queue;
#ifdef DEBUG
	debug_print("netlink_open_connection queue num: %u, index: %u\n", queue_num, ind);
#endif
	int v4_ok = 1, v6_ok = 1;
	h[ind] = nfq_open();
	if (!h[ind]) 
	{
		debug_print("%s", "error during nfq_open()\n");
		exit(EXIT_FAILURE);
	}

	if (nfq_unbind_pf(h[ind], AF_INET) < 0) 
	{
		debug_print("%s", "error during nfq_unbind_pf() for IPv4\n");
		v4_ok = 0;
	}

	if (nfq_unbind_pf(h[ind], AF_INET6) < 0) 
	{
		debug_print("%s", "error during nfq_unbind_pf() for IPv6\n");
		v6_ok = 0;
	}

	if ( !(v4_ok || v6_ok) )
	{
		debug_print("%s", "error during nfq_unbind_pf()\n");
		exit(EXIT_FAILURE);
	}

	v4_ok = v6_ok = 1;

	if (nfq_bind_pf(h[ind], AF_INET) < 0) 
	{
		debug_print("%s", "error during nfq_bind_pf() for IPv4\n");
		v4_ok = 0;
	}

	if (nfq_bind_pf(h[ind], AF_INET6) < 0) 
	{
		debug_print("%s", "error during nfq_bind_pf() for IPv6\n");
		v6_ok = 0;
	}

	if ( !(v4_ok || v6_ok) )
	{
		debug_print("%s", "error during nfq_bind_pf()\n");
		exit(EXIT_FAILURE);
	}

	qh[ind] = nfq_create_queue(h[ind], queue_num, &call_back, (void *)&queue_num_list[ind]);
	if (!qh[ind])
	{
		debug_print("%s", "error during nfq_create_queue()\n");
		exit(EXIT_FAILURE);
	}

	int r = nfq_set_queue_flags(qh[ind], NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);
    if (r == -1) {
        debug_print("Can't set fail-open mode: %s\n", strerror(errno));
    }

	if (nfq_set_mode(qh[ind], NFQNL_COPY_PACKET, 0xffff) < 0) 
	{
		debug_print("%s", "can't set packet_copy mode\n");
		exit(EXIT_FAILURE);
	}

	nh[ind] = nfq_nfnlh(h[ind]);
	nfq_recv_fd[ind] = nfnl_fd(nh[ind]);
}

void *read_func(void *queue_num_void)
{
	uint32_t *queue_num_ptr = (uint32_t *)queue_num_void;
	uint32_t ind = *queue_num_ptr - starting_queue;
	char buf[PKT_BUFF_SIZE];
	int recieved_bytes;
	while(1) {
		recieved_bytes = recv(nfq_recv_fd[ind], buf, PKT_BUFF_SIZE, 0);
		if ( recieved_bytes >= 0)
		{
			// TODO nfq_handle_packet seems to only modify a single handle,
			// in current model with 1 handling thread and 1 process thread this might not be the problem
			// but when there are multiple handling thread will need lock - per queue
			// pthread_mutex_lock(nfq_handle_packet_locks);
			// Callback will create packet_t and push to pool
			nfq_handle_packet(h[ind], buf, recieved_bytes);
			// pthread_mutex_unlock(nfq_handle_packet_locks);
		}
		else
		{
            debug_print("NETLINK recv error on ind %u: %s\n", ind, strerror(errno));
			// No buffer space available
			exit(EXIT_FAILURE);
			// TODO HANDLE ERROR
		}
	}
}

void *process_func(void *queue_num_void)
{
	uint32_t *queue_num_ptr = (uint32_t *)queue_num_void;
	uint32_t ind = *queue_num_ptr - starting_queue;
	while(1) {
		// dequeue 1 pkt
		packet_t * target = packet_pool_dequeue(packet_pools[ind]);
		if (target) {
			// check if we should block this packet
			switch(pkt_decision(target)) {
				case PKT_ACCEPT:
#ifdef DEBUG
					debug_print("ACCEPT packet ID %d on queue %u\n", target->id, ind);
#endif
					// is nfq_set_verdict thread safe ? TODO
					// TODO, check call_back_old
					if(nfq_set_verdict(qh[ind], target->id, NF_ACCEPT, 0, NULL) < 0) {
						debug_print("nfq_set_verdict ACCEPT error on queue %u\n", ind);
						exit(EXIT_FAILURE);
					}
					break;
				case PKT_DROP:
					// is nfq_set_verdict thread safe ? TODO
					// TODO, check call_back_old
					if(nfq_set_verdict(qh[ind], target->id, NF_DROP, 0, NULL) < 0) {
						debug_print("nfq_set_verdict DROP error on queue %u\n", ind);
						exit(EXIT_FAILURE);
					}
					if (is_redirect) {
						// TODO REDIRECT
					}
					break;
				case PKT_INIT_DROP:
#ifdef DEBUG
					debug_print("%s\n", "CALLING tcp_reset_ipv4");
#endif
					tcp_reset_ipv4(target); 
					// TODO add tcp_reset_ipv6
					// is nfq_set_verdict thread safe ? TODO
					// TODO, check call_back_old
					if(nfq_set_verdict(qh[ind], target->id, NF_DROP, 0, NULL) < 0) {
						debug_print("nfq_set_verdict DROP error on queue %u\n", ind);
						exit(EXIT_FAILURE);
					}
					break;
				default:
					debug_print("%s", "process_func DEFAULTED!!!!!\n");
					exit(EXIT_FAILURE);
			}
			packet_destroy(&target);
		}
	}
}

void filter_init()
{
	int err;
	if (inited)
		return;

	// queue_num_list init
	queue_num_list = (uint32_t *)malloc(sizeof(uint32_t) * n_queue);
	for (int i = 0; i < n_queue; i++) {
		queue_num_list[i] = i + starting_queue;
	}
	// init handles
	if (!h)
		h = (struct nfq_handle **)malloc((sizeof(struct nfq_handle *)) * n_queue);
	if (!nh)
		nh = (struct nfnl_handle **)malloc((sizeof(struct nfnl_handle *)) * n_queue);
	if (!qh)
		qh = (struct nfq_q_handle **)malloc((sizeof(struct nfq_q_handle *)) * n_queue);
	if (!h || !nh || !qh) {
		debug_print("%s\n", "init malloc handle failure");
		exit(EXIT_FAILURE);
	}
	if (!nfq_recv_fd)
		nfq_recv_fd = (int *)malloc(sizeof(int) * n_queue);
	if (!nfq_recv_fd) {
		debug_print("%s\n", "init malloc nfq_recv_fd failure");
		exit(EXIT_FAILURE);
	}
	if (!packet_pools)
		packet_pools = (packet_pool_t **)malloc(sizeof(packet_pool_t *) * n_queue);
	if (!packet_pools) {
		debug_print("%s\n", "init malloc packet_pools failure");
		exit(EXIT_FAILURE);
	}
	read_threads = (pthread_t *)malloc(sizeof(pthread_t) * n_queue);
	verdict_threads = (pthread_t *)malloc(sizeof(pthread_t) * n_queue);
	if (!read_threads || !verdict_threads) {
		debug_print("%s\n", "init malloc pthread_t failure");
		exit(EXIT_FAILURE);
	}
	// QUEUE PTRS INIT
	for (int i = 0; i < n_queue; i++) {
#ifdef DEBUG
		debug_print("netlink_open_connection %u\n", i + starting_queue);
#endif
		netlink_open_connection(i + starting_queue);
		packet_pools[i] = packet_pool_create(qh[i]);
	}

	// mutex for handle func
#ifdef DEBUG
	debug_print("%s\n", "Initing lock");
#endif
	nfq_handle_packet_locks = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((err = pthread_mutex_init(nfq_handle_packet_locks, 0)) != 0) {
		debug_print("pthread_mutex_init error: %s\n", strerror(err));
		exit(EXIT_FAILURE);
    }
	for (int i = 0; i < n_queue; i++) {
		// start threads
		if ((err = pthread_create(&read_threads[i], 0, read_func, (void *)&queue_num_list[i])) != 0) {
			debug_print("create read thread error: %s\n", strerror(err));
			exit(EXIT_FAILURE);
    	}
		if ((err = pthread_create(&verdict_threads[i], 0, process_func, (void *)&queue_num_list[i])) != 0) {
			debug_print("create verdict thread error: %s\n", strerror(err));
			exit(EXIT_FAILURE);
    	}
	}
	inited = true;
}

// Call after init all worker thread
void filter_startup_wait()
{
    // lock for rst list
    int err;
    if((err = pthread_spin_init(&startup_rst_lock, PTHREAD_PROCESS_PRIVATE)) != 0){
		debug_print("pthread_spin_init error: %s\n", strerror(err));
		exit(EXIT_FAILURE);
	}
    struct timespec req, rem;
    req.tv_sec = startup_timeout;
    req.tv_nsec = 0;
    while(nanosleep(&req, &rem) == -1) {
        if (errno == EINTR) {
            req.tv_sec = rem.tv_sec;
            req.tv_nsec = rem.tv_nsec;
        }
        else {
            debug_print("Startup rst wait error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    is_startup_rst = 0;
    if((err = pthread_spin_lock(&startup_rst_lock)) != 0) {
        debug_print("pthread_spin_lock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
	}

    startup_ip_flush_all_node(&startup_ip_list);

    if((err = pthread_spin_destroy(&startup_rst_lock)) != 0){
        debug_print("pthread_spin_destroy error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
	}
}

void filter_wait()
{
	for (int i = 0; i < n_queue; i++) {
		pthread_join(read_threads[i], 0);
		pthread_join(verdict_threads[i], 0);
	}
}

void filter_cleanup()
{
#ifdef DEBUG
    debug_print("%s", "TODO filter_cleanup\n");
#endif
	exit(EXIT_SUCCESS);
	// nfq_destroy_queue(qh);
	// nfq_close(h);
}