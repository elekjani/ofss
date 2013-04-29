/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef PACKETPROC_INT_H
#define PACKETPROC_INT_H 1

#include <uthash/uthash.h>
#include "lib/list.h"

#define MAX_PP_NUM_GLOBAL 255;

/* Extended pl_pkt structure. Used by pp_send_msg to send a pipeline
 * packet to a specific pp's msg_mbox with the mbox mechanism*/
struct pp_msg {
    struct list_node list;

    struct pl_pkt *pl_pkt;
    uint32_t process_id;
    uint32_t input_id;
};

/* Every packet processor type has a shared data.
 * This is essentainly a hash map with the type id as an unique id */
struct pp_shared_data {
    uint32_t type;
    void *private;
    UT_hash_handle hh;
};

/* A reference to a packet processor. The ref member can be a flow_entry's
 * uid, or a packet processor's proc_id */
struct pp_refs {
    uint32_t ref;
    uint32_t input_id;
    struct pp_refs *prev;
    struct pp_refs *next;
};

struct pp {
    uint32_t            proc_id;
    uint32_t            type_id;

	struct logger      *logger;
    struct packetproc  *packetproc;
    struct pp_refs     *flow_refs;
    struct pp_refs     *processor_refs;

    uint8_t             inputs_num;
    uint8_t             outputs_num;
    struct mbox        *msg_mbox;
    void               *private;

    UT_hash_handle      hh;
};

struct packetproc {
    struct dp              *dp;
    struct logger          *logger;

    pthread_t              *thread;
    struct ev_loop         *loop;

    struct packetproc_loop *packetproc_loop;
    struct mbox            *msg_mbox;

    struct pp              *pp_map;  /* map of entries based on their unique ID. */
    uint32_t                max_pp_num_global;
    uint32_t                current_pp_num_global;

    struct pp_shared_data  *pp_shared_data;
    //struct ofl_table_stats  *stats;  /* structure storing table statistics. */

    pthread_mutex_t  *mutex;
};

struct packetproc_loop {
    struct dp *dp;
    struct logger *logger;

    struct ev_loop *loop;
    
    struct packetproc *packetproc;
};

#endif /* PACKETPROC_INT_H */
