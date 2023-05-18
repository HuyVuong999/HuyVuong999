#ifndef FILTER_H
#define FILTER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include "domain_tree.h"
#include "packet_pool.h"
#include "common.h"

#define TCP_HEADER_LENGTH_WORDS   5 /* 20 Bytes */
// >= MTU
#define PKT_BUFF_SIZE 2048

// Option params
extern domain_tree_char_node_ptr blocked_domain_tree_ptr; // NOT THREAD SAFE TODO IF NEED LIVE EDITING
extern bool is_redirect;
extern uint32_t n_queue;
extern uint32_t starting_queue;
extern char *filtered_iface;
extern uint8_t filtered_iface_mac[8];
// For startup period, in this mode RST pkt would be sent to current connecting ssl sessions
extern uint32_t startup_timeout;

// TODO SUPPORT IPV6, add family, and use address_t in packet.h
typedef struct _startup_ip_node
{
	//uint32_t ipv4_src;
	//uint32_t ipv4_dst;
	uint64_t ip;
	struct _startup_ip_node *next;
} startup_ip_node;

void insertionSort(startup_ip_node **list_handle);
ret_t binarySearch(startup_ip_node *list_handle,  int l,  int r, uint64_t data);
void startup_ip_push(startup_ip_node **list_handle, uint64_t data);
ret_t startup_ip_search_node(startup_ip_node *list_handle, uint64_t data);
void startup_ip_flush_all_node(startup_ip_node **list_handle);

typedef enum
{
	PKT_ACCEPT,
	PKT_DROP,
	PKT_INIT_DROP
} pkt_decision_enum;

typedef struct _ssl_payload_ 
{
	uint8_t content_type;
	char *ssl_version;
	uint16_t ssl_len;
	uint8_t handshake_protocol;
	uint32_t handshake_length;
	char *handshake_ssl_version;
	char *handshake_random; // malloced
	uint8_t session_id_len;
	char *session_id;  // malloced
	uint16_t cipher_sui_len;
	char *cipher_sui; // malloced
	uint8_t comp_meth_len;
	uint8_t comp_meth;
	uint16_t extension_field_len;
	uint16_t extension_len;
	uint16_t extension_type;
	uint16_t server_name_len;
	uint16_t sn_list_len;
	uint8_t sn_type;
	uint16_t sn_len;
	char *sn; // malloced
} SSL_PAYLOAD;

// Start handler threads
void filter_init();
// Wait for startup sending rst
void filter_startup_wait();
// Wait for handler threads, will block
void filter_wait();
// TODO, just kill the process ATM
void filter_cleanup();

#endif
