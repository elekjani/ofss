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
#include <netinet/in.h>
#include "openflow/openflow.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/message_box.h"
#include "lib/logger_names.h"
#include "lib/pkt_buf.h"
#include "lib/packets.h"
#include "oflib/ofl_messages.h"
#include "datapath/dp.h"
#include "datapath/dp_int.h"
#include "datapath/pipeline_packet.h"
#include "packetproc/packetproc_int.h"
#include "packetproc/packetproc_types.h"

#include "gre_structs.h"
#include "gre_pkt.h"

#define MAX_PP_NUM 100

static int
gre_mod(struct packetproc *packetproc, struct ofl_msg_processor_mod *req,struct pp *pp,struct pp_shared_data *pp_shared_data);

static int 
gre_unpack(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf);

static int
gre_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type);

static int
gre_free(uint8_t *msg, enum ofp_type type);

static bool
gre_process_msg(void *pp_, struct list_node *cmd_);

struct PP_types_list*
gre_packetproc_init(struct packetproc *packetproc) {
    struct pp_shared_data *pp_shared_data = malloc(sizeof(struct pp_shared_data));
    pp_shared_data->type                  = GRE;
    pp_shared_data->private       = NULL;
    HASH_ADD(hh, packetproc->pp_shared_data, type, sizeof(uint32_t), pp_shared_data);

    struct PP_types_list *PP_type = malloc(sizeof(struct PP_types_list));
    PP_type->PP_type              = GRE;
    PP_type->mod_cb               = gre_mod;
    PP_type->unpack_cb            = gre_unpack;
    PP_type->pack_cb              = gre_pack;
	PP_type->free_cb			  = gre_free;
    PP_type->current_pp_num       = 0;
    PP_type->max_pp_num           = MAX_PP_NUM;
    PP_type->prev                 = NULL;
    PP_type->next                 = NULL;
    PP_type->logger               = logger_mgr_get(LOGGER_NAME_PP_TYPE, PP_types_name[GRE]);
    logger_log(PP_type->logger, LOG_DEBUG, "\"%s\" packet processor initiated. (%d)", PP_types_name[GRE], GRE);

    return PP_type;
}

static int
gre_mod(struct packetproc *packetproc, struct ofl_msg_processor_mod *req,struct pp *pp,struct pp_shared_data *pp_shared_data) {
    struct PP_types_list *pp_type = pp_types_get(req->type);
    struct gre_pp_mod *gre_pp_mod = (struct gre_pp_mod*)req->data;
    struct gre_pp *gre_pp = (struct gre_pp*)pp->private;

    switch (req->command) {
        case OFPPR_ADD: {
            pp->inputs_num           = 2;
            pp->outputs_num          = 1;
            pp->msg_mbox             = mbox_new(packetproc->loop, pp, gre_process_msg);

            struct gre_pp *gre_pp   = malloc(sizeof(struct gre_pp));
            gre_pp->pp              = pp;
            gre_pp->dp              = packetproc->dp;
            gre_pp->packetproc      = packetproc;
            gre_pp->logger          = pp->logger;
            gre_pp->remote_ip       = gre_pp_mod->remote_ip;
            gre_pp->local_ip        = gre_pp_mod->local_ip;
            gre_pp->interface       = gre_pp_mod->interface;
            pp->private             = gre_pp;

            break;
        }
        case OFPPR_MODIFY: {
            //modify
            break;
        }
        case OFPPR_DELETE: {
            free(gre_pp);

            break;
        }
    }

    return 0;
}

static int 
gre_unpack(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf) {
    if(type == OFPT_PROCESSOR_MOD) {
        int offset = 0;
        struct gre_pp_mod *gre_pp_mod = (struct gre_pp_mod*)malloc(sizeof(struct gre_pp_mod));
        gre_pp_mod->local_ip  = ntohl(*((uint32_t*)(src+offset)));
        offset += sizeof(uint32_t);
        gre_pp_mod->local_tunnel_ip  = ntohl(*((uint32_t*)(src+offset)));
        offset += sizeof(uint32_t);
        gre_pp_mod->remote_ip = ntohl(*((uint32_t*)(src+offset)));
        offset += sizeof(uint32_t);
        gre_pp_mod->remote_tunnel_ip  = ntohl(*((uint32_t*)(src+offset)));
        offset += sizeof(uint32_t);
        gre_pp_mod->interface = ntohl(*((uint32_t*)(src+offset)));

        *msg = (uint8_t*)gre_pp_mod;
    }else if(type == OFPT_PROCESSOR_CTRL) {
    }
    return 0;
}

static int
gre_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type) {
    if(type == OFPT_PROCESSOR_MOD) {
    }else if(type == OFPT_PROCESSOR_CTRL) {
    }
 
    return 0;
}

static int
gre_free(uint8_t *msg, enum ofp_type type) {
	if(type == OFPT_PROCESSOR_MOD) {
	}else if(type == OFPT_PROCESSOR_CTRL) {
	}

	return 0;
}

static bool
gre_process_msg(void *pp_, struct list_node *cmd_) {
    struct pp *pp                 = (struct pp*)pp_;
    struct gre_pp *gre_pp         = (struct gre_pp*)pp->private;
    struct pp_msg *pp_msg         = (struct pp_msg *)cmd_;
    struct packetproc *packetproc = pp->packetproc;
    struct dp *dp                 = packetproc->dp;
    struct dp_loop *dp_loop       = dp->dp_loop;
    struct pl_pkt *pl_pkt         = pp_msg->pl_pkt;
    struct pkt_buf *pkt_buf       = pl_pkt->pkt;

    logger_log(pp->logger, LOG_DEBUG, "Packet received. input: %u", pp_msg->input_id);
    logger_log(pp->logger, LOG_DEBUG, "Packet length: %d, in_port: %d", pkt_buf->data_len, pl_pkt->in_port);

    uint16_t length = 0;
    if (pp_msg->input_id == 1) {
        uint8_t *data = add_gre_header(pkt_buf, gre_pp, &length);
        if(data != NULL) {
            struct pl_pkt *gre_pkt = pl_pkt_new(pkt_buf_new_use(data, length), true, gre_pp->interface);
            dp_pl_pkt_to_port(dp_loop, OFPP_IN_PORT, length, gre_pkt);
            pl_pkt_free(gre_pkt, true);
        }
    } else if (pp_msg->input_id == 2) {
        uint8_t *data = del_gre_header(pkt_buf, gre_pp, &length);
        if(data != NULL) {
            struct pl_pkt *gre_pkt = pl_pkt_new(pkt_buf_new_use(data, length), true, 1);
            dp_pl_pkt_to_port(dp_loop, OFPP_TABLE, length, gre_pkt);
            pl_pkt_free(gre_pkt,true);
        }
    }

    pl_pkt_free(pp_msg->pl_pkt, true);
    free(pp_msg);

    return true;
}
