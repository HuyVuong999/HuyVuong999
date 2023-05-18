#ifndef PACKET_POOL_H
#define PACKET_POOL_H

#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

#include "packet.h"

// Pool is implemented as double linked list, push from tail, pop from head
// To avoid complication when access the queue from multiple threads need lock on both nodes and ptrs
// the pool always has 2 dummy nodes. Head / tail, push / pop happens between those 2 after all locks are aqquired
// NULL <-p- TAIL -n-> ... <-p- HEAD -n-> NULL
typedef struct packet_node_ {
    packet_t *packet;
    struct packet_node_ *next;
    struct packet_node_ *prev;
    pthread_spinlock_t lock;
} packet_node_t;

// Offloading from nfqueue
typedef struct packet_pool_ {
    // Each packet pool belongs to a queue
    // Handle to the given nfq, do not change once set
    // used by callback to set verdict
    struct nfq_q_handle *qh;
    // RO ptrs
    packet_node_t* head;
    packet_node_t* tail;
    // 
    sem_t has_data;
} packet_pool_t;

// Create a packet_pool_t, with head & tail dummy nodes ready
packet_pool_t *packet_pool_create(struct nfq_q_handle *h);
// Delete a packet_pool_t, not impl, implement deallocation of packet first TODO
// void packet_pool_delete(packet_pool_t *pp);
// Queue a packet into given packet pool, locked using a spinlock
void packet_pool_enqueue(packet_pool_t *pp, packet_t *packet);
// Dequeue a packet from given packet pool, locked using a spinlock
// The node is deallocated in the process, returns a packet_t, null if empty
packet_t *packet_pool_dequeue(packet_pool_t* pp);

#endif
