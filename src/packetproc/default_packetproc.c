/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include <uthash/uthash.h>
#include <pthread.h>
#include "packetproc_int.h"
#include "lib/message_box.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/logger_names.h"
#include "openflow/openflow.h"
#include "datapath/dp.h"
#include "default_packetproc.h"
#include "datapath/dp_int.h"

#define MAX_PP_NUM 100

struct default_msg_data {
    uint8_t data[0];
};

static void
default_packetproc_mod(struct packetproc *packetproc, uint32_t type ,uint32_t proc_id ,uint16_t command, void *data);

static int 
default_unpack(uint8_t *src, uint8_t *msg, enum ofp_type type, char *errbuf);

static int
default_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type);

static bool
default_process_msg(void *pp_, struct list_node *cmd_);

struct PP_types_list*
default_packetproc_init(struct packetproc *packetproc);

struct PP_types_list*
default_packetproc_init(struct packetproc *packetproc) {
    struct PP_types_list *PP_type = malloc(sizeof(struct PP_types_list));
    PP_type->PP_type              = DEFAULT;
    PP_type->mod_cb               = default_packetproc_mod;
    PP_type->unpack_cb            = default_unpack;
    PP_type->pack_cb              = default_pack;
    PP_type->PP_msg_data_len      = sizeof(struct default_msg_data);
    PP_type->current_pp_num       = 0;
    PP_type->max_pp_num           = MAX_PP_NUM;
    PP_type->prev                 = NULL;
    PP_type->next                 = NULL;
    logger_log(packetproc->logger, LOG_DEBUG, "Init \"Default\" packetprocessors. (%d)", DEFAULT);

    return PP_type;
}

static void
default_packetproc_mod(struct packetproc *packetproc, uint32_t type ,uint32_t proc_id ,uint16_t command, void *data) {
    switch (command) {
        case OFPPR_ADD: {
            struct pp *pp;
            HASH_FIND(hh, packetproc->pp_map, &proc_id, sizeof(uint32_t), pp);
            if( pp != NULL ) { //send_error
                return;
            }

            pp = malloc(sizeof(struct pp));
            pp->proc_id = proc_id;
            pp->type_id = type;

            pp->logger =  logger_mgr_get(LOGGER_NAME_PP_PROC, dp_get_uid(packetproc->dp), proc_id);

            pp->packetproc = packetproc;

            pp->flow_refs = NULL;
            pp->processor_refs = NULL;

            pp->inputs_num = 1;
            pp->outputs_num = 1;

            pp->msg_mbox = mbox_new(packetproc->loop, pp, default_process_msg);

            pp->private = NULL;

            HASH_ADD(hh, packetproc->pp_map, proc_id, sizeof(uint32_t), pp);

            struct PP_types_list *pp_type = pp_types_get(type);
            pp_type->current_pp_num++;
            packetproc->current_pp_num_global++;

            break;
        }
        case OFPPR_MODIFY: {
            struct pp *pp;
            HASH_FIND(hh, packetproc->pp_map, &proc_id, sizeof(uint32_t), pp);
            if( pp == NULL ) { //send_error
                return;
            }

            //make modification
            break;
        }
        case OFPPR_DELETE: {
            struct pp *pp;
            HASH_FIND(hh, packetproc->pp_map, &proc_id, sizeof(uint32_t), pp);
            if( pp == NULL ) { //send_error
                return;
            }

            mbox_free(pp->msg_mbox);
            free(pp);

            HASH_DELETE(hh, packetproc->pp_map, pp);

            struct PP_types_list *pp_type = pp_types_get(type);
            pp_type->current_pp_num--;
            packetproc->current_pp_num_global--;

            break;
        }
    }
}

static int 
default_unpack(uint8_t *src, uint8_t *msg, enum ofp_type type, char *errbuf) {
    if(type == OFPT_PROCESSOR_MOD) {
        //make something
    }else if(type == OFPT_PROCESSOR_CTRL) {
        //make something
    }
    return 0;
}

static int
default_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type) {
    if(type == OFPT_PROCESSOR_MOD) {
        //make something
    }else if(type == OFPT_PROCESSOR_CTRL) {
        //make something
    }
 
    return 0;
}

static bool
default_process_msg(void *pp_, struct list_node *cmd_) {
    struct pp *pp      = (struct pp*)pp_;
    struct pp_msg *pp_msg = (struct pp_msg *)cmd_;
    struct packetproc *packetproc = pp->packetproc;
    struct dp *dp = packetproc->dp;
    struct dp_loop *dp_loop = dp->dp_loop;
    of_port_no_t port = OFPP_LOCAL; // = enum ofp_port_no
    struct pl_pkt *pl_pkt = pp_msg->pl_pkt;

    logger_log(pp->logger, LOG_DEBUG, "Packet received. input: %u", pp_msg->input_id);

    //dp_pl_pkt_to_port(dp_loop, port, max_len, pl_pkt);

    return true;
}


