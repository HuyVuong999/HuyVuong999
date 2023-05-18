#include <stdlib.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sched.h>

#include "debug.h"
#include "packet_pool.h"

packet_pool_t *packet_pool_create(struct nfq_q_handle *h)
{
    packet_pool_t *tmp = (packet_pool_t *)malloc(sizeof(packet_pool_t));
    if (!tmp) {
        debug_print("malloc error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    tmp->qh   = h;
    tmp->head = (packet_node_t *)malloc(sizeof(packet_node_t));
    tmp->tail = (packet_node_t *)malloc(sizeof(packet_node_t));
    tmp->head->packet = 0;
    tmp->tail->packet = 0;
    if (!tmp->head || !tmp->tail) {
        debug_print("malloc error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int err;
    if ((err = pthread_spin_init(&tmp->head->lock, PTHREAD_PROCESS_PRIVATE)) != 0) {
        debug_print("pthread_spin_init error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    if ((err = pthread_spin_init(&tmp->tail->lock, PTHREAD_PROCESS_PRIVATE)) != 0) {
        debug_print("pthread_spin_init error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    // NULL <-p- TAIL -n-><-p- HEAD -n-> NULL
    tmp->head->next = 0;
    tmp->head->prev = tmp->tail;
    tmp->tail->next = tmp->head;
    tmp->tail->prev = 0;
    // sem
    if ((err = sem_init(&tmp->has_data, 0, 0)) != 0) {
        debug_print("sem_init error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    return tmp;
}

void packet_pool_enqueue(packet_pool_t *pp, packet_t *packet)
{
    if (!pp || !packet) {
        debug_print("%s\n", "packet_pool_enqueue NULL ptr");
        exit(EXIT_FAILURE);
    }
    // Add to tail
    packet_node_t *tail = pp->tail;
    // Accquire lock for tail node
    int err;
    if ((err = pthread_spin_lock(&tail->lock)) != 0) {
        debug_print("pthread_spin_lock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    packet_node_t *tail_next = tail->next;
    // Accquire lock for tail next node
    if ((err = pthread_spin_lock(&tail_next->lock)) != 0) {
        debug_print("pthread_spin_lock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    // New node
    packet_node_t *new_node = (packet_node_t *)malloc(sizeof(packet_node_t));
    if (!new_node) {
        debug_print("malloc error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    if ((err = pthread_spin_init(&new_node->lock, PTHREAD_PROCESS_PRIVATE)) != 0) {
        debug_print("pthread_spin_init error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    new_node->packet = packet;
    new_node->next = tail_next;
    new_node->prev = tail;
    tail->next = new_node;
    tail_next->prev = new_node;
    // unlock
    if ((err = pthread_spin_unlock(&tail_next->lock)) != 0) {
        debug_print("pthread_spin_unlock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    if ((err = pthread_spin_unlock(&tail->lock)) != 0) {
        debug_print("pthread_spin_unlock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    if (sem_post(&pp->has_data) != 0) {
        debug_print("sem_post error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

packet_t *packet_pool_dequeue(packet_pool_t* pp) {
    if (!pp) {
        debug_print("%s\n", "packet_pool_dequeue NULL ptr");
        exit(EXIT_FAILURE);
    }
    if (sem_wait(&pp->has_data) != 0) {
        debug_print("sem_wait error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // Pop from head
    packet_node_t *head = pp->head;
    // Accquire lock for head node
    int err;
    if ((err = pthread_spin_lock(&head->lock)) != 0) {
        debug_print("pthread_spin_lock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    packet_node_t *head_prev = head->prev;
    // Check if == tail -> empty
    if (head_prev == pp->tail) {
        if ((err = pthread_spin_unlock(&head->lock)) != 0) {
            debug_print("pthread_spin_unlock error: %s\n", strerror(err));
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    packet_node_t *head_prev_prev = NULL;

    while (1) {
        // Lock prev node
        if ((err = pthread_spin_lock(&head_prev->lock)) != 0) {
            debug_print("pthread_spin_lock error: %s\n", strerror(err));
            exit(EXIT_FAILURE);
        }
        head_prev_prev = head_prev->prev;
        // Lock prev prev node
        // Deadlock can happen here if prev_prev == tail and tail is locked
        if ((err = pthread_spin_trylock(&head_prev_prev->lock)) != 0) {
            if (err == EINVAL || err == EDEADLK) {
                debug_print("pthread_spin_trylock error: %s\n", strerror(err));
                exit(EXIT_FAILURE);
            }
            else {
                // Release prev lock
                if ((err = pthread_spin_unlock(&head_prev->lock)) != 0) {
                    debug_print("pthread_spin_unlock error: %s\n", strerror(err));
                    exit(EXIT_FAILURE);
                }
                // let enqueue finish first
                if (sched_yield() != 0) {
                    debug_print("sched_yield error: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }
        }
        else {
            // Got prev prev lock, continue
            break;
        }
    }

    if(!head_prev_prev) {
        debug_print("%s\n", "head_prev_prev NULL");
        exit(EXIT_FAILURE);
    }

    // unlink prev node
    head_prev_prev->next = head;
    head->prev = head_prev_prev;
    head_prev->next = 0;
    head_prev->prev = 0;
    // get the data ptr
    packet_t *data = head_prev->packet;
    head_prev->packet = 0;
    // unlock & free prev
    if ((err = pthread_spin_unlock(&head_prev->lock)) != 0) {
        debug_print("pthread_spin_unlock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    free(head_prev);
    // unlock prev prev
    if ((err = pthread_spin_unlock(&head_prev_prev->lock)) != 0) {
        debug_print("pthread_spin_unlock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    // unlock head
    if ((err = pthread_spin_unlock(&head->lock)) != 0) {
        debug_print("pthread_spin_unlock error: %s\n", strerror(err));
        exit(EXIT_FAILURE);
    }
    return data;
}
