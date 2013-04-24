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

#include "control/ctrl.h"
#include "datapath/dp.h"
#include "lib/list.h"
#include "lib/logger_names.h"
#include "lib/message_box.h"
#include "lib/thread_id.h"
#include "logger/logger_mgr.h"
#include "logger/logger.h"

static void *event_loop(void *packetproc_loop_);

static bool process_msg(void *packetproc_loop_, struct list_node *cmd_);

struct packetproc*
packetproc_new(struct dp *dp) {
    struct packetproc *packetproc = malloc(sizeof(struct packetproc));
    packetproc->dp     = dp;
    packetproc->logger = logger_mgr_get(LOGGER_NAME_PP);

    packetproc->pp_map                = NULL;
    packetproc->max_pp_num_global     = MAX_PP_NUM_GLOBAL;
    packetproc->current_pp_num_global = 0;

    packetproc->pp_shared_data = NULL;

    struct packetproc_loop *packetproc_loop = malloc(sizeof(struct packetproc_loop));
    packetproc_loop->dp                     = dp;
    packetproc_loop->logger                 = logger_mgr_get(LOGGER_NAME_PP_LOOP);

    packetproc->packetproc_loop = packetproc_loop;
    packetproc_loop->packetproc = packetproc;

    packetproc->thread    = malloc(sizeof(pthread_t));
    packetproc->loop      = ev_loop_new(0/*flags*/);
    packetproc_loop->loop = packetproc->loop;
    packetproc->msg_mbox   = mbox_new(packetproc->loop, packetproc_loop, process_msg);
    
    packetproc->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(packetproc->mutex, NULL);

    /* Initialize basic packet processor structures and
     * call #ppName#_packetproc_init for every pp type */
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
    pthread_mutex_lock(packetproc->mutex);
    HASH_FIND(hh, packetproc->pp_map, &process_id, sizeof(size_t), pp);
    if(pp == NULL) {
        logger_log(packetproc->logger, LOG_ERR, "There is no pp whit proc_id %d", process_id);
        pthread_mutex_unlock(packetproc->mutex);
        return;
    }
    pthread_mutex_unlock(packetproc->mutex);

    struct pp_msg *pp_msg =  malloc(sizeof(struct pp_msg));
    pp_msg->pl_pkt = pl_pkt_clone(pl_pkt);
    pp_msg->process_id = process_id;
    pp_msg->input_id = input_id;
    mbox_send(pp->msg_mbox,(struct list_node *)pp_msg);
}

void
packetproc_add_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref) {
    struct pp *pp;
    pthread_mutex_lock(packetproc->mutex);
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
    if(pp == NULL) {
        //TODO:send error
        logger_log(packetproc->logger, LOG_ERR, "Cant add reference to non existing pp (proc_id: %d)", processor_id);
        pthread_mutex_unlock(packetproc->mutex);
        return;
    }

    //TODO: check if already added
    struct pp_refs *pp_refs = malloc(sizeof(struct pp_refs));
    pp_refs->ref      = flow_ref;
    pp_refs->input_id = input_id;
    DL_APPEND(pp->flow_refs, pp_refs);
    pthread_mutex_unlock(packetproc->mutex);
    logger_log(packetproc->logger, LOG_DEBUG, "Added new flow reference to pp: %d", processor_id);
}

void
packetproc_del_flow_ref(struct packetproc *packetproc, uint32_t processor_id, UNUSED_ATTR uint32_t input_id, uint32_t flow_ref) {
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
    //TODO: check existance

    struct pp_refs *pp_refs;
    DL_SEARCH_SCALAR(pp->flow_refs, pp_refs, ref, flow_ref); /* its enogh to search based on ref
                                                                one input can be referred only by one flow */
    //TODO: check existance
    DL_DELETE(pp->flow_refs, pp_refs);
}

void
packetproc_add_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref /* processor_id */) {
    pthread_mutex_lock(packetproc->mutex);
    struct pp *pp;
    HASH_FIND(hh, packetproc->pp_map, &processor_id, sizeof(size_t), pp);
     if(pp == NULL) {
        //TODO:send error
        logger_log(packetproc->logger, LOG_ERR, "Cant add reference to non existing pp (proc_id: %d)", processor_id);
        pthread_mutex_unlock(packetproc->mutex);
        return;
    }

    struct pp_refs *pp_refs = malloc(sizeof(struct pp_refs));
    pp_refs->ref = pp_ref;
    pp_refs->input_id = input_id;
    DL_APPEND(pp->processor_refs, pp_refs);
    pthread_mutex_unlock(packetproc->mutex);
}

void
packetproc_del_pp_ref(struct packetproc *packetproc, uint32_t processor_id, UNUSED_ATTR uint32_t input_id, uint32_t pp_ref) {
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
    rep->header.type = OFPST_PROCESSOR;
    rep->total_num = packetproc->current_pp_num_global;
    rep->total_max = packetproc->max_pp_num_global;
    rep->stats_num = count;

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
    rep->header.type = OFPST_PROCESSOR_INST;
    rep->stats_num  = pp->inputs_num;

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

ssize_t
packetproc_spec_proc_spec_type(struct packetproc *packetproc,struct ofl_msg_processor *msg) {
    ssize_t error = 0;
    struct PP_types_list *pp_type = pp_types_get(msg->type);
    if(pp_type == NULL) {
        logger_log(packetproc->logger, LOG_ERR, "There is no such pp_type: %d", msg->type);
        return -1;
    }

    pthread_mutex_lock(packetproc->mutex);

    struct pp *pp = NULL;
    HASH_FIND(hh, packetproc->pp_map, &(msg->proc_id), sizeof(uint32_t), pp);

    struct pp_shared_data *pp_shared_data;
    HASH_FIND(hh, packetproc->pp_shared_data, &(msg->type), sizeof(uint32_t), pp_shared_data);
    if(pp_shared_data == NULL) {
        //TODO: send error msg to controller
        logger_log(pp_type->logger, LOG_WARN, "The shared data is not initialized for pp type %s", PP_types_name[msg->type] );
        pthread_mutex_unlock(packetproc->mutex);
        return -1;
    }

    if(msg->header.type == OFPT_PROCESSOR_CTRL) {
        struct ofl_msg_processor_ctrl *req = (struct ofl_msg_processor_ctrl*)msg;
        if(pp == NULL) {
            logger_log(pp_type->logger, LOG_WARN, "There is no pp with proc_id: %d", req->proc_id);
            error = -1;
        }else {
            pp_type->ctrl_cb(packetproc, req, pp, pp_shared_data);
        }

    }else if(msg->header.type == OFPT_PROCESSOR_MOD){
        struct ofl_msg_processor_mod *req = (struct ofl_msg_processor_mod*)msg;
        switch (req->command) {
            case OFPPRC_ADD: {
                if( pp != NULL ) { 
                    //TODO:send error msg to controller
                    logger_log(pp_type->logger, LOG_WARN, "There is already a pp with proc_id: %d", req->proc_id);
                    error = -1;
                    break;
                }

                pp                       = malloc(sizeof(struct pp));
                pp->proc_id              = req->proc_id;
                pp->type_id              = req->type;
                pp->logger               = logger_mgr_get(LOGGER_NAME_PP_PROC, PP_types_name[req->type], req->proc_id);
                pp->packetproc           = packetproc;
                pp->flow_refs            = NULL;
                pp->processor_refs       = NULL;
                
                pp_type->mod_cb(packetproc, req, pp, pp_shared_data);

                HASH_ADD(hh, packetproc->pp_map, proc_id, sizeof(uint32_t), pp);

                pp_type->current_pp_num++;
                packetproc->current_pp_num_global++;

                mbox_notify(pp->msg_mbox);

                logger_log(pp_type->logger, LOG_DEBUG, "Packet processor instance added with proc id %d", req->proc_id);

                break;
            }
            case OFPPRC_MODIFY: {
                if( pp == NULL ) { 
                    //TODO:send error msg to controller
                    logger_log(pp_type->logger, LOG_WARN, "There is no pp with proc_id: %d", req->proc_id);
                    error = -1;
                    break;
                }

                pp_type->mod_cb(packetproc, req, pp, pp_shared_data);

                break;
            }
            case OFPPRC_DELETE: {
                if( pp == NULL ) { 
                    //TODO:send error msg to controller
                    logger_log(pp_type->logger, LOG_WARN, "There is no pp with proc_id: %d", req->proc_id);
                    error = -1;
                    break;
                }

                if(pp_type->mod_cb(packetproc, req, pp, pp_shared_data) == 0) {
                    pp_type->current_pp_num--;
                    packetproc->current_pp_num_global--;

                    HASH_DELETE(hh, packetproc->pp_map, pp);
                    mbox_free(pp->msg_mbox);
                    free(pp);
                }else {
                    //TODO: error?
                    error = -1;
                    break;
                }

                break;
            }
        }
    }
    pthread_mutex_unlock(packetproc->mutex);

    return error;
}


ssize_t
packetproc_all_proc_all_type(struct packetproc *packetproc,struct ofl_msg_processor *req) {
    struct pp *pp;
    for(pp=packetproc->pp_map; pp!=NULL; pp = pp->hh.next) {
        req->type = pp->type_id;
        req->proc_id = pp->proc_id;
        packetproc_spec_proc_spec_type(packetproc, req);
    }

    return 0;
}

ssize_t
packetproc_all_proc_spec_type(struct packetproc *packetproc,struct ofl_msg_processor *req) {
    struct pp *pp;
    for(pp=packetproc->pp_map; pp!=NULL; pp = pp->hh.next) {
        if(pp->type_id == req->type) {
            req->proc_id = pp->proc_id;
            packetproc_spec_proc_spec_type(packetproc, req);
        }
    }

    return 0;
}

ssize_t
packetproc_proc_msg(struct packetproc *packetproc, struct ofl_msg_processor *msg) {
    uint32_t proc_id = msg->proc_id;
    uint32_t type    = msg->type;

    if(msg->proc_id == 0xffffffff || msg->type == 0xffffffff) {
        //TODO: spacial behavior for NONE type
        return 0;
    }


    ssize_t error = 0;
    if(msg->proc_id == 0xfffffffe) {
        if(msg->type == 0xfffffffe) { //ALL proc_id and ALL type
            error = packetproc_all_proc_all_type(packetproc, msg);
        }else { //ALL proc_id and specific type
            error = packetproc_all_proc_spec_type(packetproc, msg);
        }
    }else{
        if(msg->type == 0xfffffffe) { //specific proc_id and ALL type (undefined)
            //TODO: error?
        }else { //specific proc_id and specific type
            error = packetproc_spec_proc_spec_type(packetproc, msg);
        }
    }

    msg->proc_id = proc_id;
    msg->type    = type;

    return error;

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

static bool process_msg(void *packetproc_loop_, struct list_node *cmd_) {
    //make something
    return true;
}

