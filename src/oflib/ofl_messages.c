/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <openflow/openflow.h>
#include "ofl.h"
#include "ofl_actions.h"
#include "ofl_messages.h"
#include "ofl_structs.h"
#include "ofl_utils.h"
#include "packetproc/packetproc_types.h"

/* Frees the OFlib stats request message along with any dynamically allocated
 * structures. */
static int
ofl_msg_free_error(struct ofl_msg_error *msg) {
    free(msg->data);
    free(msg);

    return 0;
}



static int
ofl_msg_free_stats_request(struct ofl_msg_stats_request_header *msg, struct ofl_exp *exp, char *errbuf) {
    switch (msg->type) {
        case OFPST_DESC: {
            break;
        }
        case OFPST_FLOW:
        case OFPST_AGGREGATE: {
            ofl_structs_free_match(((struct ofl_msg_stats_request_flow *)msg)->match, exp, errbuf);
            //TODO error
            break;
        }
        case OFPST_TABLE:
        case OFPST_PORT:
        case OFPST_QUEUE:
        case OFPST_GROUP:
        case OFPST_GROUP_DESC:
            break;
        case OFPST_EXPERIMENTER: {
            if (exp == NULL || exp->stats == NULL || exp->stats->req_free == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to free EXPERIMENTER stats request, but no callback was given.");
                }
                free(msg);
                return -1;
            }
            exp->stats->req_free(msg);
            return 0;
        }
        default:
            return -1;
    }
    free(msg);
    return 0;
}



/* Frees the OFlib stats reply message along with any dynamically allocated
 * structures. */
static int
ofl_msg_free_stats_reply(struct ofl_msg_stats_reply_header *msg, struct ofl_exp *exp, char *errbuf) {
    switch (msg->type) {
        case OFPST_DESC: {
            struct ofl_msg_stats_reply_desc *stat = (struct ofl_msg_stats_reply_desc *)msg;
            free(stat->mfr_desc);
            free(stat->hw_desc);
            free(stat->sw_desc);
            free(stat->serial_num);
            free(stat->dp_desc);
            break;
        }
        case OFPST_FLOW: {
            struct ofl_msg_stats_reply_flow *stat = (struct ofl_msg_stats_reply_flow *)msg;
            OFL_UTILS_FREE_ARR_FUN3(stat->stats, stat->stats_num,
                                    ofl_structs_free_flow_stats, exp, errbuf);
            //TODO error
            break;
        }
        case OFPST_AGGREGATE: {
            break;
        }
        case OFPST_TABLE: {
            struct ofl_msg_stats_reply_table *stat = (struct ofl_msg_stats_reply_table *)msg;
            OFL_UTILS_FREE_ARR_FUN(stat->stats, stat->stats_num,
                                   ofl_structs_free_table_stats);
            break;
        }
        case OFPST_PORT: {
            struct ofl_msg_stats_reply_port *stat = (struct ofl_msg_stats_reply_port *)msg;
            OFL_UTILS_FREE_ARR(stat->stats, stat->stats_num);
            break;
        }
        case OFPST_QUEUE: {
            struct ofl_msg_stats_reply_queue *stat = (struct ofl_msg_stats_reply_queue *)msg;
            OFL_UTILS_FREE_ARR(stat->stats, stat->stats_num);
            break;
        }
        case OFPST_GROUP: {
            struct ofl_msg_stats_reply_group *stat = (struct ofl_msg_stats_reply_group *)msg;
            OFL_UTILS_FREE_ARR_FUN(stat->stats, stat->stats_num,
                                   ofl_structs_free_group_stats);
            break;
        }
        case OFPST_GROUP_DESC: {
            struct ofl_msg_stats_reply_group_desc *stat = (struct ofl_msg_stats_reply_group_desc *)msg;
            OFL_UTILS_FREE_ARR_FUN3(stat->stats, stat->stats_num,
                                    ofl_structs_free_group_desc_stats, exp, errbuf);
            //TODO error
            break;
        }
        case OFPST_EXPERIMENTER: {
            if (exp == NULL || exp->stats || exp->stats->reply_free == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to free EXPERIMENTER stats reply, but no callback was given.");
                }
                free(msg);
                return -1;
            }
            exp->stats->reply_free(msg);
            return 0;
        }
        default: {
            return -1;
        }
    }

    free(msg);
    return 0;
}

int
ofl_msg_free_processor_mod(struct ofl_msg_processor_mod *msg, char *errbuf) {
    struct PP_types_list *pp_type = pp_types_get(msg->type);
    pp_type->free_cb(msg->data, msg->header.type);

    return 0;
}

int
ofl_msg_free_processor_ctrl(struct ofl_msg_processor_ctrl *msg, char *errbuf) {
    struct PP_types_list *pp_type = pp_types_get(msg->type);
    pp_type->free_cb(msg->data, msg->header.type);

    return 0;
}



int
ofl_msg_free(struct ofl_msg_header *msg, struct ofl_exp *exp, char *errbuf) {
    switch (msg->type) {
        case OFPT_HELLO: {
            break;
        }
        case OFPT_ERROR: {
            return ofl_msg_free_error((struct ofl_msg_error *)msg);
        }
        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY: {
            free(((struct ofl_msg_echo *)msg)->data);
            break;
        }
        case OFPT_EXPERIMENTER: {
            if (exp == NULL || exp->msg == NULL || exp->msg->free == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to free EXPERIMENTER message, but no callback was given");
                }
                free(msg);
                return -1;
            }
            exp->msg->free((struct ofl_msg_experimenter *)msg);
            return 0;
        }
        case OFPT_FEATURES_REQUEST: {
            break;
        }
        case OFPT_FEATURES_REPLY: {
            struct ofl_msg_features_reply *rep = (struct ofl_msg_features_reply *)msg;
            OFL_UTILS_FREE_ARR_FUN(rep->ports, rep->ports_num,
                                   ofl_structs_free_port);
            break;
        }
        case OFPT_GET_CONFIG_REQUEST: {
            break;
        }
        case OFPT_GET_CONFIG_REPLY: {
            free(((struct ofl_msg_get_config_reply *)msg)->config);
            break;
        }
        case OFPT_SET_CONFIG: {
            free(((struct ofl_msg_set_config *)msg)->config);
            break;
        }
        case OFPT_PACKET_IN: {
            free(((struct ofl_msg_packet_in *)msg)->data);
            break;
        }
        case OFPT_FLOW_REMOVED: {
            return ofl_msg_free_flow_removed((struct ofl_msg_flow_removed *)msg, true, exp, errbuf);
            break;
        }
        case OFPT_PORT_STATUS: {
            free(((struct ofl_msg_port_status *)msg)->desc);
            break;
        }
        case OFPT_PACKET_OUT: {
            return ofl_msg_free_packet_out((struct ofl_msg_packet_out *)msg, true, exp, errbuf);
        }
        case OFPT_FLOW_MOD: {
            return ofl_msg_free_flow_mod((struct ofl_msg_flow_mod *)msg, true, true, exp, errbuf);
        }
        case OFPT_GROUP_MOD: {
            return ofl_msg_free_group_mod((struct ofl_msg_group_mod *)msg, true, exp, errbuf);
        }
        case OFPT_PORT_MOD:
        case OFPT_TABLE_MOD:
        case OFPT_PROCESSOR_MOD:
        case OFPT_PROCESSOR_CTRL: {
            break;
         }
        case OFPT_PROCESSOR_MOD: {
            return ofl_msg_free_processor_mod((struct ofl_msg_processor_mod *)msg, errbuf);;
        }
        case OFPT_PROCESSOR_CTRL: {
            return ofl_msg_free_processor_ctrl((struct ofl_msg_processor_ctrl *)msg, errbuf);;
        } 
        case OFPT_STATS_REQUEST: {
            return ofl_msg_free_stats_request((struct ofl_msg_stats_request_header *)msg, exp, errbuf);
        }
        case OFPT_STATS_REPLY: {
            return ofl_msg_free_stats_reply((struct ofl_msg_stats_reply_header *)msg, exp, errbuf);
        }
        case OFPT_BARRIER_REQUEST:
        case OFPT_BARRIER_REPLY:
        case OFPT_QUEUE_GET_CONFIG_REQUEST: {
            break;
        }
        case OFPT_QUEUE_GET_CONFIG_REPLY: {
            struct ofl_msg_queue_get_config_reply *mod =
                                (struct ofl_msg_queue_get_config_reply *)msg;
            OFL_UTILS_FREE_ARR_FUN(mod->queues, mod->queues_num,
                                   ofl_structs_free_packet_queue);
            break;
        }
    }
    free(msg);
    return 0;
}


int
ofl_msg_free_packet_out(struct ofl_msg_packet_out *msg, bool with_data, struct ofl_exp *exp, char *errbuf) {
    if (with_data) {
        free(msg->data);
    }
    OFL_UTILS_FREE_ARR_FUN3(msg->actions, msg->actions_num,
                            ofl_actions_free, exp, errbuf);
    //TODO err

    free(msg);
    return 0;
}

int
ofl_msg_free_group_mod(struct ofl_msg_group_mod *msg, bool with_buckets, struct ofl_exp *exp, char *errbuf) {
    if (with_buckets) {
        OFL_UTILS_FREE_ARR_FUN3(msg->buckets, msg->buckets_num,
                                ofl_structs_free_bucket, exp, errbuf);
    }

    free(msg);
    return 0;
}

int
ofl_msg_free_flow_mod(struct ofl_msg_flow_mod *msg, bool with_match, bool with_instructions, struct ofl_exp *exp, char *errbuf) {
    if (with_match) {
        ofl_structs_free_match(msg->match, exp, errbuf);
        //TODO error
    }
    if (with_instructions) {
        OFL_UTILS_FREE_ARR_FUN3(msg->instructions, msg->instructions_num,
                                ofl_structs_free_instruction, exp, errbuf);
        //TODO error
    }

    free(msg);
    return 0;
}

int
ofl_msg_free_flow_removed(struct ofl_msg_flow_removed *msg, bool with_stats, struct ofl_exp *exp, char *errbuf) {
    if (with_stats) {
        ofl_structs_free_flow_stats(msg->stats, exp, errbuf);
        //TODO error
    }
    free(msg);
    return 0;
}



bool
ofl_msg_merge_stats_reply_flow(struct ofl_msg_stats_reply_flow *orig, struct ofl_msg_stats_reply_flow *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_flow_stats ** )realloc(orig->stats, new_stats_num * sizeof(struct ofl_flow_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_flow_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPSF_REPLY_MORE) == 0);
}

bool
ofl_msg_merge_stats_reply_table(struct ofl_msg_stats_reply_table *orig, struct ofl_msg_stats_reply_table *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_table_stats **)realloc(orig->stats, new_stats_num * sizeof(struct ofl_table_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_table_stats *)malloc(sizeof(struct ofl_table_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_table_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPSF_REPLY_MORE) == 0);
}

bool
ofl_msg_merge_stats_reply_port(struct ofl_msg_stats_reply_port *orig, struct ofl_msg_stats_reply_port *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_port_stats **)realloc(orig->stats, new_stats_num * sizeof(struct ofl_port_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_port_stats *)malloc(sizeof(struct ofl_port_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_port_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPSF_REPLY_MORE) == 0);
}

bool
ofl_msg_merge_stats_reply_queue(struct ofl_msg_stats_reply_queue *orig, struct ofl_msg_stats_reply_queue *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_queue_stats **)realloc(orig->stats, new_stats_num * sizeof(struct ofl_queue_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_queue_stats *)malloc(sizeof(struct ofl_queue_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_queue_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPSF_REPLY_MORE) == 0);
}

