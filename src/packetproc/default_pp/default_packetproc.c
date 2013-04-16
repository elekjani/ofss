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

#include "default_packetproc.h"

#include "datapath/dp.h"
#include "datapath/dp_int.h"
#include "datapath/pipeline_packet.h"
#include "lib/message_box.h"
#include "lib/logger_names.h"
#include "lib/pkt_buf.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "oflib/ofl_messages.h"
#include "openflow/openflow.h"
#include "packetproc/packetproc_int.h"

#define MAX_PP_NUM 100

static int
default_mod(struct packetproc *packetproc, struct ofl_msg_processor_mod *req,struct pp *pp,struct pp_shared_data *pp_shared_data);

static int 
default_unpack(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf);

static int
default_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type);

static int
default_free(uint8_t *msg, enum ofp_type type);

static bool
default_process_msg(void *pp_, struct list_node *cmd_);

struct PP_types_list*
default_packetproc_init(struct packetproc *packetproc);

struct PP_types_list*
default_packetproc_init(struct packetproc *packetproc) {
    struct PP_types_list *PP_type = malloc(sizeof(struct PP_types_list));
    PP_type->PP_type              = DEFAULT;
    PP_type->mod_cb               = default_mod;
    PP_type->unpack_cb            = default_unpack;
    PP_type->pack_cb              = default_pack;
	PP_type->free_cb			  = default_free;
    PP_type->current_pp_num       = 0;
    PP_type->max_pp_num           = MAX_PP_NUM;
    PP_type->prev                 = NULL;
    PP_type->next                 = NULL;
    PP_type->logger               = logger_mgr_get(LOGGER_NAME_PP_TYPE, PP_types_name[DEFAULT]);

    struct pp_shared_data *pp_shared_data = malloc(sizeof(struct pp_shared_data));
    pp_shared_data->type = DEFAULT;
    pp_shared_data->private = NULL;
    HASH_ADD(hh, packetproc->pp_shared_data, type, sizeof(uint32_t), pp_shared_data);

    logger_log(PP_type->logger, LOG_DEBUG, "\"%s\" packet processor initiated. (%d)",PP_types_name[DEFAULT], DEFAULT);

    return PP_type;
}

static int
default_mod(struct packetproc *packetproc, struct ofl_msg_processor_mod *req,struct pp *pp, struct pp_shared_data *pp_shared_data) {
    struct PP_types_list *pp_type = pp_types_get(req->type);

    switch (req->command) {
        case OFPPR_ADD: {
            pp->inputs_num = 1;
            pp->outputs_num = 1;
            pp->msg_mbox = mbox_new(packetproc->loop, pp, default_process_msg);
            pp->private = NULL;

            break;
        }
        case OFPPR_MODIFY: {
            //make modification
            
            break;
        }
        case OFPPR_DELETE: {
            //free
            break;
        }
    }

    return 0;
}

static int 
default_unpack(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf) {
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

static int
default_free(uint8_t *msg, enum ofp_type type) {
	if(type == OFPT_PROCESSOR_MOD) {
	}else if(type == OFPT_PROCESSOR_CTRL) {
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
    struct pl_pkt *pl_pkt = pp_msg->pl_pkt;
    struct pkt_buf *pkt_buf = pl_pkt->pkt;

    logger_log(pp->logger, LOG_DEBUG, "Packet received. input: %u", pp_msg->input_id);

    return true;
}


