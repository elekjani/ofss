/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include <pthread.h>
#include "packetproc_types.h"
#include "packetproc.h"
#include "lib/list.h"
#include "logger/logger_mgr.h"
#include "logger/logger.h"
#include "lib/logger_names.h"
#include "datapath/dp.h"
#include "lib/message_box.h"
#include "lib/thread_id.h"
#include "control/ctrl.h"

static void *event_loop(void *packetproc_loop_);


struct packetproc*
packetproc_new(struct dp *dp) {
    struct packetproc *packetproc = malloc(sizeof(struct packetproc));
    packetproc->dp = dp;
    packetproc->logger = logger_mgr_get(LOGGER_NAME_PP, dp_get_uid(dp));

    packetproc->pp_map = NULL;
    packetproc->max_pp_num_global = MAX_PP_NUM_GLOBAL;
    packetproc->current_pp_num_global = 0;

    struct packetproc_loop *packetproc_loop = malloc(sizeof(struct packetproc_loop));
    packetproc_loop->dp = dp;
    packetproc_loop->logger = logger_mgr_get(LOGGER_NAME_PP_LOOP, dp_get_uid(dp));

    packetproc->packetproc_loop = packetproc_loop;
    packetproc_loop->packetproc = packetproc;

    packetproc->thread = malloc(sizeof(pthread_t));
    packetproc->loop   = ev_loop_new(0/*flags*/);
    packetproc_loop->loop = packetproc->loop;

    init_packetprocessors(packetproc);

    ev_set_userdata(packetproc->loop, (void *)packetproc_loop);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc;
    if ((rc = pthread_create(packetproc->thread, &attr, event_loop, (void *)packetproc_loop)) != 0) {
        logger_log(packetproc->logger, LOG_ERR, "Unable to create thread (%d).", rc);
        //TODO free structures
        return NULL;
    }

    logger_log(packetproc->logger, LOG_INFO, "Initialized.");

    return packetproc;
}

void
pp_send_msg(struct packetproc *packetproc, struct pl_pkt *pl_pkt, uint32_t process_id, uint32_t input_id) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &process_id, sizeof(size_t), pp);
    //TODO: check existance

    struct pp_msg *pp_msg =  malloc(sizeof(struct pp_msg));
    pp_msg->pl_pkt = pl_pkt_clone(pl_pkt);
    pp_msg->process_id = process_id;
    pp_msg->input_id = input_id;
    mbox_send(pp->msg_mbox,(struct list_node *)pp_msg);
}

void
packetproc_add_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
    //TODO: check existance

    //TODO: check if already added
    struct pp_refs *pp_refs = malloc(sizeof(struct pp_refs));
    pp_refs->ref      = flow_ref;
    pp_refs->input_id = input_id;
    DL_APPEND(pp->flow_refs, pp_refs);
}

void
packetproc_del_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
    //TODO: check existance

    struct pp_refs *pp_refs;
    DL_SEARCH_SCALAR(pp->flow_refs, pp_refs, ref, flow_ref); /* its enogh to search based on ref
                                                                an input  can referred only by one flow */
    //TODO: check existance
    DL_DELETE(pp->flow_refs, pp_refs);
}

void
packetproc_add_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref /* processor_id */) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
    //TODO: check existance

    struct pp_refs *pp_refs = malloc(sizeof(struct pp_refs));
    pp_refs->ref = pp_ref;
    pp_refs->input_id = input_id;
    DL_APPEND(pp->processor_refs, pp_refs);
}

void
packetproc_del_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
    //TODO: check existance

    struct pp_refs *pp_refs;
    DL_SEARCH_SCALAR(pp->processor_refs, pp_refs, ref, pp_ref); /* its enogh to search based on ref,
                                                                   an input  can referred only by one processor */
    //TODO: check existance
    DL_DELETE(pp->processor_refs, pp_refs);
}

struct ofl_msg_stats_reply_header*
packetproc_stats_reply_all(struct packetproc *packetproc) {
    struct PP_types_list *pp_type;
    size_t count = 0;
    DL_FOREACH(PP_types_list,pp_type) { count++; }

    size_t buff_len = 0;
    buff_len = count * sizeof(struct ofl_processor_stat) + sizeof(struct ofl_msg_stats_reply_processor);

    struct ofl_msg_stats_reply_processor *rep = malloc(buff_len);
    rep->total_num = packetproc->current_pp_num_global;
    rep->total_max = packetproc->max_pp_num_global;

    count = 0;
    DL_FOREACH(PP_types_list,pp_type) { 
        rep->stats[count].type    = pp_type->PP_type; 
        rep->stats[count].current = pp_type->current_pp_num;
        rep->stats[count].max     = pp_type->max_pp_num;
        count++;
    }

    return (struct ofl_msg_stats_reply_header *)rep;
}

struct ofl_msg_stats_reply_header*
packetproc_stats_reply(struct packetproc *packetproc, uint32_t type) {
    struct PP_types_list *pp_type = pp_types_get(type);

    size_t buff_len = 0;
    buff_len = sizeof(struct ofl_processor_stat) + sizeof(struct ofl_msg_stats_reply_processor);

    struct ofl_msg_stats_reply_processor *rep = malloc(buff_len);
    rep->total_num = packetproc->current_pp_num_global;
    rep->total_max = packetproc->max_pp_num_global;

    rep->stats[0].type    = pp_type->PP_type; 
    rep->stats[0].current = pp_type->current_pp_num;
    rep->stats[0].max     = pp_type->max_pp_num;

    return (struct ofl_msg_stats_reply_header *)rep;
}

struct ofl_msg_stats_reply_header*
packetproc_inst_stats_reply_all(struct packetproc *packetproc, uint32_t proc_id) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &proc_id, sizeof(size_t), pp);

    size_t buff_len = 0;
    buff_len = pp->inputs_num * sizeof(struct ofl_processor_inst_stat) + sizeof(struct ofl_msg_stats_reply_processor_inst);
    struct ofl_msg_stats_reply_processor_inst *rep = malloc(buff_len);

    /* very inefficient... */
    size_t max = 0, count = 0, i;
    struct pp_refs *pp_ref, *tmp;
    DL_FOREACH(pp->flow_refs, tmp) { if(tmp->input_id > max) max = tmp->input_id; }
    for(i=0; i<max; i++) {
        rep->stats[count].proc_id    = proc_id;
        rep->stats[count].input_id   = i;
        rep->stats[count].flow_count = 0;
        DL_SEARCH_SCALAR(pp->flow_refs, tmp, input_id, i);
        if(tmp) {
            while(tmp) {
                rep->stats[count].flow_count++;
                pp_ref = tmp;
                DL_SEARCH_SCALAR(pp_ref->next, tmp, input_id, i);
            }
            count++;
        }
    }

    max = 0; count = 0;
    DL_FOREACH(pp->processor_refs, tmp) { if(tmp->input_id > max) max = tmp->input_id; }
    for(i=0; i<max; i++) {
        rep->stats[count].proc_id    = proc_id;
        rep->stats[count].input_id   = i;
        rep->stats[count].processor_count = 0;
        DL_SEARCH_SCALAR(pp->processor_refs, tmp, input_id, i);
        if(tmp) {
            while(tmp) {
                rep->stats[count].processor_count++;
                pp_ref = tmp;
                DL_SEARCH_SCALAR(pp_ref->next, tmp, input_id, i);
            }
            count++;
        }
    }

    return (struct ofl_msg_stats_reply_header *)rep;
}

struct ofl_msg_stats_reply_header*
packetproc_inst_stats_reply(struct packetproc *packetproc, uint32_t proc_id, uint32_t input) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &proc_id, sizeof(size_t), pp);

    size_t buff_len = 0;
    buff_len = sizeof(struct ofl_processor_inst_stat) + sizeof(struct ofl_msg_stats_reply_processor_inst);
    struct ofl_msg_stats_reply_processor_inst *rep = malloc(buff_len);

    struct pp_refs *pp_ref, *tmp;
    rep->stats[0].proc_id    = proc_id;
    rep->stats[0].input_id   = input;
    rep->stats[0].flow_count = 0;
    rep->stats[0].processor_count = 0;
    DL_SEARCH_SCALAR(pp->flow_refs, tmp, input_id, input);
    if(tmp) {
        while(tmp) {
            rep->stats[0].flow_count++;
            pp_ref = tmp;
            DL_SEARCH_SCALAR(pp_ref->next, tmp, input_id, input);
        }
    }

    DL_SEARCH_SCALAR(pp->processor_refs, tmp, input_id, input);
    if(tmp) {
        while(tmp) {
            rep->stats[0].processor_count++;
            pp_ref = tmp;
            DL_SEARCH_SCALAR(pp_ref->next, tmp, input_id, input);
        }
    }

    return (struct ofl_msg_stats_reply_header *)rep;
}

static void *
event_loop(void *packetproc_loop_) {
    assert(packetproc_loop_ != NULL);
    struct packetproc_loop *packetproc_loop = (struct packetproc_loop *)packetproc_loop_;

    thread_id_set();

    logger_log(packetproc_loop->logger, LOG_INFO, "Thread started for packet processors.");

    ev_ref(packetproc_loop->loop); //makes sure an empty loop stays alive
    ev_run(packetproc_loop->loop, 0/*flags*/);

    logger_log(packetproc_loop->logger, LOG_ERR, "Loop exited.");

    pthread_exit(NULL);
    return NULL;
}
