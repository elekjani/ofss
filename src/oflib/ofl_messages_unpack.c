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
#include <netinet/in.h>
#include <endian.h>
#include <openflow/openflow.h>
#include "lib/compiler.h"
#include "ofl_actions.h"
#include "ofl_messages.h"
#include "ofl_structs.h"
#include "ofl_utils.h"
#include "ofl_print.h"
#include "packetproc/packetproc_types.h"

/****************************************************************************
 * Functions for unpacking ofp wire format to ofl structures.
 ****************************************************************************/


static ofl_err
ofl_msg_unpack_error(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_error_msg *se;
    struct ofl_msg_error *de;

    if (*len < sizeof(struct ofp_error_msg)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received ERROR message invalid length (%zu).", *len);
        }
        return OFL_ERROR;
    }
    *len -= sizeof(struct ofp_error_msg);

    se = (struct ofp_error_msg *)src;

    de = (struct ofl_msg_error *)malloc(sizeof(struct ofl_msg_error));

    de->type = (enum ofp_error_type)ntohs(se->type);
    de->code = ntohs(se->code);
    de->data_length = *len;
    de->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), se->data, *len) : NULL;
    *len = 0;

    (*msg) = (struct ofl_msg_header *)de;
    return 0;
}


static ofl_err
ofl_msg_unpack_echo(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg) {
    struct ofl_msg_echo *e = (struct ofl_msg_echo *)malloc(sizeof(struct ofl_msg_echo));
    uint8_t *data;

    // ofp_header length was checked at ofl_msg_unpack
    *len -= sizeof(struct ofp_header);

    data = (uint8_t *)src + sizeof(struct ofp_header);
    e->data_length = *len;
    e->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), data, *len) : NULL;
    *len = 0;

    *msg = (struct ofl_msg_header *)e;
    return 0;
}


static ofl_err
ofl_msg_unpack_features_reply(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_switch_features *sr;
    struct ofl_msg_features_reply *dr;
    struct ofp_port *port;
    ofl_err error = 0;
    size_t i;

    if (*len < sizeof(struct ofp_switch_features)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received FEATURES_REPLY message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_switch_features);

    sr = (struct ofp_switch_features *)src;
    dr = (struct ofl_msg_features_reply *)malloc(sizeof(struct ofl_msg_features_reply));

    dr->datapath_id  = ntoh64(sr->datapath_id);
    dr->n_buffers    = ntohl( sr->n_buffers);
    dr->n_tables     = ntohl( sr->n_tables);
    dr->capabilities = ntohl( sr->capabilities);

    error = ofl_utils_count_ofp_ports(&(sr->ports), *len, &dr->ports_num);
    if (error) {
        free(dr);
        return error;
    }

    dr->ports = (struct ofl_port **)malloc(dr->ports_num * sizeof(struct ofl_port *));

    port = sr->ports;
    for (i = 0; i < dr->ports_num; i++) {
        error = ofl_structs_port_unpack(port, len, &(dr->ports[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR(dr->ports, i);
            free(dr);
            return error;
        }
        port = (struct ofp_port *)((uint8_t *)port + sizeof(struct ofp_port));
    }

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}


static ofl_err
ofl_msg_unpack_get_config_reply(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_switch_config *sr;
    struct ofl_msg_get_config_reply *dr;

    if (*len < sizeof(struct ofp_switch_config)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GET_CONFIG_REPLY message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_switch_config);

    sr = (struct ofp_switch_config *)src;
    dr = (struct ofl_msg_get_config_reply *)malloc(sizeof(struct ofl_msg_get_config_reply));

    dr->config = (struct ofl_config *)malloc(sizeof(struct ofl_config));
    dr->config->miss_send_len = ntohs(sr->miss_send_len);
    dr->config->flags = ntohs(sr->flags);

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}

static ofl_err
ofl_msg_unpack_set_config(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_switch_config *sr;
    struct ofl_msg_set_config *dr;

     if (*len < sizeof(struct ofp_switch_config)) {
         if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received SET_CONFIG message has invalid length (%zu).", *len);
         }
         return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
     }
     *len -= sizeof(struct ofp_switch_config);

     sr = (struct ofp_switch_config *)src;
     dr = (struct ofl_msg_set_config *)malloc(sizeof(struct ofl_msg_set_config));

     dr->config = (struct ofl_config *)malloc(sizeof(struct ofl_config));
     // TODO Zoltan: validate flags
     dr->config->miss_send_len = ntohs(sr->miss_send_len);
     dr->config->flags = ntohs(sr->flags);

     *msg = (struct ofl_msg_header *)dr;
     return 0;
}

static ofl_err
ofl_msg_unpack_packet_in(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_packet_in *sp;
    struct ofl_msg_packet_in *dp;

    if (*len < sizeof(struct ofp_packet_in)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_IN message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    sp = (struct ofp_packet_in *)src;

    if (ntohl(sp->in_port) == 0 ||
        (ntohl(sp->in_port) > OFPP_MAX &&
         ntohl(sp->in_port) != OFPP_LOCAL)) {
        if (errbuf != NULL) {
            char *ps = ofl_port_to_string(ntohl(sp->in_port));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_IN message has invalid in_port (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    if (sp->table_id == 0xff) {
        if (errbuf != NULL) {
            char *ts = ofl_table_to_string(sp->table_id);
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_IN has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }
    *len -= sizeof(struct ofp_packet_in);

    dp = (struct ofl_msg_packet_in *)malloc(sizeof(struct ofl_msg_packet_in));

    dp->buffer_id = ntohl(sp->buffer_id);
    dp->in_port = ntohl(sp->in_port);
    dp->in_phy_port = ntohl(sp->in_phy_port);
    dp->total_len = ntohs(sp->total_len);
    dp->reason = (enum ofp_packet_in_reason)sp->reason;
    dp->table_id = sp->table_id;

    dp->data_length = *len;
    dp->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), sp->data, *len) : NULL;
    *len = 0;

    *msg = (struct ofl_msg_header *)dp;
    return 0;
}


static ofl_err
ofl_msg_unpack_flow_removed(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_flow_removed *sr;
    struct ofl_msg_flow_removed *dr;
    ofl_err error;

    if (*len < (sizeof(struct ofp_flow_removed) - sizeof(struct ofp_match))) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received FLOW_REMOVED message has invalid length (%zu).", *len);
        }
        return OFL_ERROR;
    }

    sr = (struct ofp_flow_removed *)src;

    if (sr->table_id == 0xff) {
        if (errbuf != NULL) {
            char *ts = ofl_table_to_string(sr->table_id);
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received FLOW_REMOVED message has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }
    *len -= (sizeof(struct ofp_flow_removed) - sizeof(struct ofp_match));

    dr = (struct ofl_msg_flow_removed *)malloc(sizeof(struct ofl_msg_flow_removed));
    dr->reason = (enum ofp_flow_removed_reason)sr->reason;

    dr->stats = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));
    dr->stats->table_id         =        sr->table_id;
    dr->stats->duration_sec     = ntohl( sr->duration_sec);
    dr->stats->duration_nsec    = ntohl( sr->duration_nsec);
    dr->stats->priority         = ntoh64(sr->priority);
    dr->stats->idle_timeout     = ntohs( sr->idle_timeout);
    dr->stats->hard_timeout     = 0;
    dr->stats->cookie           = ntoh64(sr->cookie);
    dr->stats->packet_count     = ntoh64(sr->packet_count);
    dr->stats->byte_count       = ntoh64(sr->byte_count);
    dr->stats->instructions_num = 0;
    dr->stats->instructions     = NULL;

    error = ofl_structs_match_unpack(&(sr->match), len, &(dr->stats->match), exp, errbuf);
    if (error) {
        free(dr->stats);
        free(dr);
        return error;
    }

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}

static ofl_err
ofl_msg_unpack_port_status(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_port_status *ss;
    struct ofl_msg_port_status *ds;
    ofl_err error;

    if (*len < sizeof(struct ofp_port_status)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PORT_STATUS message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= (sizeof(struct ofp_port_status) - sizeof(struct ofp_port));

    ss = (struct ofp_port_status *)src;
    ds = (struct ofl_msg_port_status *)malloc(sizeof(struct ofl_msg_port_status));

    ds->reason = ss->reason;

    error = ofl_structs_port_unpack(&(ss->desc), len, &(ds->desc), errbuf);
    if (error) {
        free(ds);
        return error;
    }

    *msg = (struct ofl_msg_header *)ds;
    return 0;
}

static ofl_err
ofl_msg_unpack_packet_out(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_packet_out *sp;
    struct ofl_msg_packet_out *dp;
    struct ofp_action_header *act;
    uint8_t *data;
    ofl_err error;
    size_t i, actions_num;

    if (*len < sizeof(struct ofp_packet_out)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_OUT message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    sp = (struct ofp_packet_out *)src;

    if (ntohl(sp->in_port) == 0 ||
        (ntohl(sp->in_port) > OFPP_MAX && ntohl(sp->in_port) != OFPP_CONTROLLER)) {
        if (errbuf != NULL) {
            char *ps = ofl_port_to_string(ntohl(sp->in_port));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_OUT message with invalid in_port (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    if (ntohl(sp->buffer_id) != 0xffffffff &&
        *len != sizeof(struct ofp_packet_out) + ntohs(sp->actions_len)) {
        if (errbuf != NULL) {
            char *bs = ofl_buffer_to_string(ntohl(sp->buffer_id));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_OUT message with data and buffer_id (%s).", bs);
            free(bs);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_packet_out);

    dp = (struct ofl_msg_packet_out *)malloc(sizeof(struct ofl_msg_packet_out));

    dp->buffer_id = ntohl(sp->buffer_id);
    dp->in_port = ntohl(sp->in_port);

    if (*len < ntohs(sp->actions_len)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PACKET_OUT message has invalid action length (%zu).", *len);
        }
        free(dp);
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    error = ofl_utils_count_ofp_actions(&(sp->actions), ntohs(sp->actions_len), &actions_num, errbuf);
    if (error) {
        free(dp);
        return error;
    }
    dp->actions_num = actions_num;
    dp->actions = (struct ofl_action_header **)malloc(dp->actions_num * sizeof(struct ofp_action_header *));

    // TODO Zoltan: Output actions can contain OFPP_TABLE
    act = sp->actions;
    for (i = 0; i < dp->actions_num; i++) {
        error = ofl_actions_unpack(act, len, &(dp->actions[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3(dp->actions, i,
                                    ofl_actions_free, exp, errbuf);
            free(dp);
        }
        act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
    }

    data = ((uint8_t *)sp->actions) + ntohs(sp->actions_len);
    dp->data_length = *len;
    dp->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), data, *len) : NULL;
    *len = 0;

    *msg = (struct ofl_msg_header *)dp;
    return 0;
}


static ofl_err
ofl_msg_unpack_flow_mod(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_flow_mod *sm;
    struct ofl_msg_flow_mod *dm;
    struct ofp_instruction *inst;
    ofl_err error;
    size_t i;

    if (*len < (sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match))) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received FLOW_MOD message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= (sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match));

    sm = (struct ofp_flow_mod *)src;
    dm = (struct ofl_msg_flow_mod *)malloc(sizeof(struct ofl_msg_flow_mod));

    dm->cookie =       ntoh64(sm->cookie);
    dm->cookie_mask =  ntoh64(sm->cookie_mask);
    dm->table_id =            sm->table_id;
    dm->command =             (enum ofp_flow_mod_command)sm->command;
    dm->idle_timeout = ntohs( sm->idle_timeout);
    dm->hard_timeout = ntohs( sm->hard_timeout);
    dm->priority =     ntohs( sm->priority);
    dm->buffer_id =    ntohl( sm->buffer_id);
    dm->out_port =     ntohl( sm->out_port);
    dm->out_group =    ntohl( sm->out_group);
    dm->flags =        ntohs( sm->flags);

    error = ofl_structs_match_unpack(&(sm->match), len, &(dm->match), exp, errbuf);
    if (error) {
        free(dm);
        return error;
    }

    error = ofl_utils_count_ofp_instructions(&(sm->instructions), *len, &dm->instructions_num, errbuf);
    if (error) {
        ofl_structs_free_match(dm->match, exp, NULL);
        free(dm);
        return error;
    }

    dm->instructions = (struct ofl_instruction_header **)malloc(dm->instructions_num * sizeof(struct ofl_instruction_header *));
    inst = sm->instructions;
    for (i = 0; i < dm->instructions_num; i++) {
        error = ofl_structs_instructions_unpack(inst, len, &(dm->instructions[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3(dm->instructions, i,
                    ofl_structs_free_instruction, exp, errbuf);
            ofl_structs_free_match(dm->match, exp, NULL);
            free(dm);
            return error;
        }
        inst = (struct ofp_instruction *)((uint8_t *)inst + ntohs(inst->len));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_group_mod(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_group_mod *sm;
    struct ofl_msg_group_mod *dm;
    struct ofp_bucket *bucket;
    ofl_err error;
    size_t i;

    if (*len < sizeof(struct ofp_group_mod)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GROUP_MOD message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_group_mod);

    sm = (struct ofp_group_mod *)src;

    if (ntohs(sm->command) > OFPGC_DELETE) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GROUP_MOD message with invalid command (%u).", ntohs(sm->command));
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
    }

    if (ntohs(sm->type) > OFPGT_FF && ntohs(sm->type) < 128 /* experimenter */) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GROUP_MOD message with invalid type (%u).", ntohs(sm->type));
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
    }

    if (ntohl(sm->group_id) > OFPG_MAX &&
                       !(ntohs(sm->command) == OFPGC_DELETE && ntohl(sm->group_id) == OFPG_ALL)) {
        if (errbuf != NULL) {
            char *gs = ofl_group_to_string(ntohl(sm->group_id));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GROUP_MOD message with invalid group id (%s).", gs);
            free(gs);
        }
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    dm = (struct ofl_msg_group_mod *)malloc(sizeof(struct ofl_msg_group_mod));

    dm->command = (enum ofp_group_mod_command)ntohs(sm->command);
    dm->type = sm->type;
    dm->group_id = ntohl(sm->group_id);

    error = ofl_utils_count_ofp_buckets(&(sm->buckets), *len, &dm->buckets_num, errbuf);
    if (error) {
        free(dm);
        return error;
    }

    if (dm->command == OFPGC_DELETE && dm->buckets_num > 0) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received DELETE group command with buckets (%zu).", dm->buckets_num);
        }
        free(dm);
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    if (dm->type == OFPGT_INDIRECT && dm->buckets_num != 1) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received INDIRECT group doesn't have exactly one bucket (%zu).", dm->buckets_num);
        }
        free(dm);
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    dm->buckets = (struct ofl_bucket **)malloc(dm->buckets_num * sizeof(struct ofl_bucket *));

    bucket = sm->buckets;
    for (i = 0; i < dm->buckets_num; i++) {
        error = ofl_structs_bucket_unpack(bucket, len, dm->type, &(dm->buckets[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3(dm->buckets, i,
                                    ofl_structs_free_bucket, exp, errbuf);
            free(dm);
            return error;
        }
        bucket = (struct ofp_bucket *)((uint8_t *)bucket + ntohs(bucket->len));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_port_mod(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_port_mod *sm;
    struct ofl_msg_port_mod *dm;

    if (*len < sizeof(struct ofp_port_mod)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PORT_MOD has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sm = (struct ofp_port_mod *)src;

    if (ntohl(sm->port_no) == 0 || ntohl(sm->port_no) > OFPP_MAX) {
        if (errbuf != NULL) {
            char *ps = ofl_port_to_string(ntohl(sm->port_no));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PORT_MOD message has invalid in_port (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }
    *len -= sizeof(struct ofp_port_mod);

    dm = (struct ofl_msg_port_mod *)malloc(sizeof(struct ofl_msg_port_mod));

    dm->port_no =   ntohl(sm->port_no);
    memcpy(dm->hw_addr, sm->hw_addr, OFP_ETH_ALEN);
    dm->config =    ntohl(sm->config);
    dm->mask =      ntohl(sm->mask);
    dm->advertise = ntohl(sm->advertise);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_table_mod(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_table_mod *sm;
    struct ofl_msg_table_mod *dm;

    if (*len < sizeof(struct ofp_table_mod)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received TABLE_MOD message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_table_mod);

    sm = (struct ofp_table_mod *)src;
    dm = (struct ofl_msg_table_mod *)malloc(sizeof(struct ofl_msg_table_mod));

    dm->table_id = sm->table_id;
    dm->config = ntohl(sm->config);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_processor_mod(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_processor_mod *sm;
    struct ofl_msg_processor_mod *dm;

    if (*len < sizeof(struct ofp_processor_mod)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PROCESSOR_MOD message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_processor_mod);

    sm = (struct ofp_processor_mod *)src;

	struct PP_types_list *pp_type  = pp_types_get(ntohl(sm->type));

	if (pp_type == NULL) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Not supported type (%u)", ntohl(sm->type));
        }
        return 1;
	}

    size_t plus_data = ntohs(sm->header.length) - sizeof(struct ofp_processor_mod);
	if (*len < plus_data) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PROCESSOR_MOD message has invalid length (%zu)", *len);
            snprintf(errbuf, OFL_ERRBUF_SIZE, "for type %s", PP_types_name[pp_type->PP_type]);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
	}
    *len -= plus_data;

    dm = (struct ofl_msg_processor_mod *)malloc(sizeof(struct ofl_msg_processor_mod));
    dm->header.type = sm->header.type;
    dm->type = ntohl(sm->type);
    dm->proc_id = ntohl(sm->proc_id);
    dm->command = ntohs(sm->command);
    dm->data_length = plus_data;

	pp_type->unpack_cb(sm->data, &dm->data, sm->header.type, errbuf);
    
    *msg = (struct ofl_msg_header *)dm;

	return 0;
}

static ofl_err
ofl_msg_unpack_processor_ctrl(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_processor_ctrl *sm;
    struct ofl_msg_processor_ctrl *dm;

    if (*len < sizeof(struct ofp_processor_ctrl)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PROCESSOR_MOD message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_processor_ctrl);

    sm = (struct ofp_processor_ctrl *)src;

	struct PP_types_list *pp_type  = pp_types_get(sm->type);

	if (pp_type == NULL) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Not supported type (%u)", sm->type);
        }
        return 1;
	}

    size_t plus_data = sm->header.length - sizeof(struct ofp_processor_ctrl);
	if (*len < plus_data) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PROCESSOR_MOD message has invalid length (%zu)", *len);
            snprintf(errbuf, OFL_ERRBUF_SIZE, "for type %s", PP_types_name[pp_type->PP_type]);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
	}
    *len -= plus_data;

    dm = (struct ofl_msg_processor_ctrl *)malloc(sizeof(struct ofl_msg_processor_ctrl));
    dm->type = ntohl(sm->type);
    dm->proc_id = ntohl(sm->proc_id);
    dm->data_length = plus_data;

	pp_type->unpack_cb(sm->data, &dm->data, sm->header.type, errbuf);
    
    *msg = (struct ofl_msg_header *)dm;

	return 0;
}

static ofl_err
ofl_msg_unpack_stats_request_flow(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_flow_stats_request *sm;
    struct ofl_msg_stats_request_flow *dm;
    ofl_err error = 0;

    // ofp_stats_request length was checked at ofl_msg_unpack_stats_request

    if (*len < (sizeof(struct ofp_flow_stats_request) - sizeof(struct ofp_match))) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received FLOW stats request has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= (sizeof(struct ofp_flow_stats_request) - sizeof(struct ofp_match));

    sm = (struct ofp_flow_stats_request *)os->body;
    dm = (struct ofl_msg_stats_request_flow *)malloc(sizeof(struct ofl_msg_stats_request_flow));

    dm->table_id = sm->table_id;
    dm->out_port = ntohl(sm->out_port);
    dm->out_group = ntohl(sm->out_group);
    dm->cookie = ntoh64(sm->cookie);
    dm->cookie_mask = ntoh64(sm->cookie_mask);

    error = ofl_structs_match_unpack(&(sm->match), len, &(dm->match), exp, errbuf);
    if (error) {
        free(dm);
        return error;
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_request_port(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_port_stats_request *sm;
    struct ofl_msg_stats_request_port *dm;

    // ofp_stats_request length was checked at ofl_msg_unpack_stats_request

    if (*len < sizeof(struct ofp_port_stats_request)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PORT stats request has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sm = (struct ofp_port_stats_request *)os->body;

    if (ntohl(sm->port_no) == 0 ||
        (ntohl(sm->port_no) > OFPP_MAX && ntohl(sm->port_no) != OFPP_ANY)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PORT stats request has invalid port (%u).", ntohl(sm->port_no));
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= sizeof(struct ofp_port_stats_request);

    dm = (struct ofl_msg_stats_request_port *)malloc(sizeof(struct ofl_msg_stats_request_port));

    dm->port_no = ntohl(sm->port_no);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_request_queue(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_queue_stats_request *sm;
    struct ofl_msg_stats_request_queue *dm;

    // ofp_stats_request length was checked at ofl_msg_unpack_stats_request

    if (*len < sizeof(struct ofp_queue_stats_request)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received QUEUE stats request has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sm = (struct ofp_queue_stats_request *)os->body;

    if (ntohl(sm->port_no) == 0 ||
        (ntohl(sm->port_no) > OFPP_MAX && ntohl(sm->port_no) != OFPP_ANY)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received QUEUE stats request has invalid port (%u).", ntohl(sm->port_no));
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_queue_stats_request);

    dm = (struct ofl_msg_stats_request_queue *)malloc(sizeof(struct ofl_msg_stats_request_queue));

    dm->port_no = ntohl(sm->port_no);
    dm->queue_id = ntohl(sm->queue_id);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_request_group(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_group_stats_request *sm;
    struct ofl_msg_stats_request_group *dm;

    // ofp_stats_request length was checked at ofl_msg_unpack_stats_request

    if (*len < sizeof(struct ofp_group_stats_request)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GROUP stats request has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_group_stats_request);

    sm = (struct ofp_group_stats_request *)os->body;
    dm = (struct ofl_msg_stats_request_group *)malloc(sizeof(struct ofl_msg_stats_request_group));

    dm->group_id = ntohl(sm->group_id);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}


static ofl_err
ofl_msg_unpack_stats_request_empty(struct ofp_stats_request *os UNUSED_ATTR, size_t *len, struct ofl_msg_header **msg) {

    // ofp_stats_request length was checked at ofl_msg_unpack_stats_request
    len -= sizeof(struct ofp_stats_request);

    *msg = (struct ofl_msg_header *)malloc(sizeof(struct ofl_msg_stats_request_header));
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_request_processor(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
	struct ofp_processor_stats_request *sm;
	struct ofl_msg_stats_request_processor *dm;

	if (*len < sizeof(struct ofp_processor_stats_request)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PROCESSOR stats request has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
	len -= sizeof(struct ofp_processor_stats_request);

	sm = (struct ofp_processor_stats_request *)os->body;
	dm = (struct ofl_msg_stats_request_processor *)malloc(sizeof(struct ofl_msg_stats_request_processor));

	dm->type = ntohl(sm->type);

	*msg = (struct ofl_msg_header *)dm;
	return 0;
}

static ofl_err
ofl_msg_unpack_stats_request_processor_inst(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
	struct ofp_processor_inst_stats_request *sm;
	struct ofl_msg_stats_request_processor_inst *dm;

	if (*len < sizeof(struct ofp_processor_inst_stats_request)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received PROCESSOR stats request has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
	len -= sizeof(struct ofp_processor_inst_stats_request);

	sm = (struct ofp_processor_inst_stats_request *)os->body;
	dm = (struct ofl_msg_stats_request_processor_inst *)malloc(sizeof(struct ofl_msg_stats_request_processor_inst));

	dm->proc_id = ntohl(sm->proc_id);
	dm->input_id = ntohl(sm->input_id);

	*msg = (struct ofl_msg_header *)dm;
	return 0;
}

static ofl_err
ofl_msg_unpack_stats_request(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofl_msg_stats_request_header *ofls;
    struct ofp_stats_request *os;
    int error;

    if (*len < sizeof(struct ofp_stats_request)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received STATS_REQUEST message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_stats_request);

    os = (struct ofp_stats_request *)src;

    switch (ntohs(os->type)) {
    case OFPST_DESC: {
        error = ofl_msg_unpack_stats_request_empty(os, len, msg);
        break;
    }
    case OFPST_FLOW:
    case OFPST_AGGREGATE: {
        error = ofl_msg_unpack_stats_request_flow(os, len, msg, exp, errbuf);
        break;
    }
    case OFPST_TABLE: {
        error = ofl_msg_unpack_stats_request_empty(os, len, msg);
        break;
    }
    case OFPST_PORT: {
        error = ofl_msg_unpack_stats_request_port(os, len, msg, errbuf);
        break;
    }
    case OFPST_QUEUE: {
        error = ofl_msg_unpack_stats_request_queue(os, len, msg, errbuf);
        break;
    }
    case OFPST_GROUP: {
        error = ofl_msg_unpack_stats_request_group(os, len, msg, errbuf);
        break;
    }
    case OFPST_GROUP_DESC: {
        error = ofl_msg_unpack_stats_request_empty(os, len, msg);
        break;
    }
	case OFPST_PROCESSOR: {
        error = ofl_msg_unpack_stats_request_processor(os, len, msg, errbuf);
	    break;
    }
	case OFPST_PROCESSOR_INST: {
        error = ofl_msg_unpack_stats_request_processor_inst(os, len, msg, errbuf);
	    break;
    }
    case OFPST_EXPERIMENTER: {
        if (exp == NULL || exp->stats == NULL || exp->stats->reply_unpack == NULL) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received EXPERIMENTER stats request, but no callback was given.");
            }
            error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
        } else {
            error = exp->stats->req_unpack(os, len, (struct ofl_msg_stats_request_header **)msg);
        }
        break;
    }
    default: {
        error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
        break;
    }
    }

    if (error) {
        return error;
    }

    ofls = (struct ofl_msg_stats_request_header *)(*msg);
    ofls->type = (enum ofp_stats_types)ntohs(os->type);
    ofls->flags = ntohs(os->flags);

    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_desc(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_desc_stats *sm;
    struct ofl_msg_stats_reply_desc *dm;

    if (*len < sizeof(struct ofp_desc_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received DESC stats reply has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_desc_stats);

    sm = (struct ofp_desc_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_desc *)malloc(sizeof(struct ofl_msg_stats_reply_desc));

    dm->mfr_desc =   (char *)strcpy((char *)malloc(strlen(sm->mfr_desc) + 1), sm->mfr_desc);
    dm->hw_desc =    (char *)strcpy((char *)malloc(strlen(sm->hw_desc) + 1), sm->hw_desc);
    dm->sw_desc =    (char *)strcpy((char *)malloc(strlen(sm->sw_desc) + 1), sm->sw_desc);
    dm->serial_num = (char *)strcpy((char *)malloc(strlen(sm->serial_num) + 1), sm->serial_num);
    dm->dp_desc =    (char *)strcpy((char *)malloc(strlen(sm->dp_desc) + 1), sm->dp_desc);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}


static ofl_err
ofl_msg_unpack_stats_reply_flow(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_flow_stats *stat;
    struct ofl_msg_stats_reply_flow *dm;
    ofl_err error;
    size_t i;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    stat = (struct ofp_flow_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_flow *)malloc(sizeof(struct ofl_msg_stats_reply_flow));

    error = ofl_utils_count_ofp_flow_stats(stat, *len, &dm->stats_num, errbuf);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_flow_stats **)malloc(dm->stats_num * sizeof(struct ofl_flow_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_flow_stats_unpack(stat, len, &(dm->stats[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3(dm->stats, i,
                                    ofl_structs_free_flow_stats, exp, errbuf);
            free (dm);
            return error;
        }
        stat = (struct ofp_flow_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_aggregate(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_aggregate_stats_reply *sm;
    struct ofl_msg_stats_reply_aggregate *dm;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    if (*len < sizeof(struct ofp_aggregate_stats_reply)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received AGGREGATE stats reply has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_aggregate_stats_reply);

    sm = (struct ofp_aggregate_stats_reply *)os->body;
    dm = (struct ofl_msg_stats_reply_aggregate *)malloc(sizeof(struct ofl_msg_stats_reply_aggregate));

    dm->packet_count = ntoh64(sm->packet_count);
    dm->byte_count =   ntoh64(sm->byte_count);
    dm->flow_count =   ntohl( sm->flow_count);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_table(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_table_stats *stat;
    struct ofl_msg_stats_reply_table *dm;
    ofl_err error;
    size_t i;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    stat = (struct ofp_table_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_table *)malloc(sizeof(struct ofl_msg_stats_reply_table));

    error = ofl_utils_count_ofp_table_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_table_stats **)malloc(dm->stats_num * sizeof(struct ofl_table_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_table_stats_unpack(stat, len, &(dm->stats[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR(dm->stats, i);
            free(dm);
            return error;
        }
        stat = (struct ofp_table_stats *)((uint8_t *)stat + sizeof(struct ofp_table_stats));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_port(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_port_stats *stat = (struct ofp_port_stats *)os->body;
    struct ofl_msg_stats_reply_port *dm = (struct ofl_msg_stats_reply_port *)malloc(sizeof(struct ofl_msg_stats_reply_port));
    ofl_err error;
    size_t i;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    stat = (struct ofp_port_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_port *)malloc(sizeof(struct ofl_msg_stats_reply_port));

    error = ofl_utils_count_ofp_port_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }

    dm->stats = (struct ofl_port_stats **)malloc(dm->stats_num * sizeof(struct ofl_port_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_port_stats_unpack(stat, len, &(dm->stats[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR(dm->stats, i);
            free(dm);
            return error;
        }
        stat = (struct ofp_port_stats *)((uint8_t *)stat + sizeof(struct ofp_port_stats));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_queue(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_queue_stats *stat = (struct ofp_queue_stats *)os->body;
    struct ofl_msg_stats_reply_queue *dm = (struct ofl_msg_stats_reply_queue *)malloc(sizeof(struct ofl_msg_stats_reply_queue));
    ofl_err error;
    size_t i;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    stat = (struct ofp_queue_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_queue *)malloc(sizeof(struct ofl_msg_stats_reply_queue));

    error = ofl_utils_count_ofp_queue_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_queue_stats **)malloc(dm->stats_num * sizeof(struct ofl_queue_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_queue_stats_unpack(stat, len, &(dm->stats[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR(dm->stats, i);
            free(dm);
            return error;
        }
        stat = (struct ofp_queue_stats *)((uint8_t *)stat + sizeof(struct ofp_queue_stats));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_group(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_group_stats *stat;
    struct ofl_msg_stats_reply_group *dm;
    ofl_err error;
    size_t i;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    stat = (struct ofp_group_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_group *)malloc(sizeof(struct ofl_msg_stats_reply_group));

    error = ofl_utils_count_ofp_group_stats(stat, *len, &dm->stats_num, errbuf);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_group_stats **)malloc(dm->stats_num * sizeof(struct ofl_group_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_group_stats_unpack(stat, len, &(dm->stats[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(dm->stats, i,
                                   ofl_structs_free_group_stats);
            free (dm);
            return error;
        }
        stat = (struct ofp_group_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_group_desc(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofp_group_desc_stats *stat;
    struct ofl_msg_stats_reply_group_desc *dm;
    ofl_err error;
    size_t i;

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply

    stat = (struct ofp_group_desc_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_group_desc *)malloc(sizeof(struct ofl_msg_stats_reply_group_desc));

    error = ofl_utils_count_ofp_group_desc_stats(stat, *len, &dm->stats_num, errbuf);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_group_desc_stats **)malloc(dm->stats_num * sizeof(struct ofl_group_desc_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_group_desc_stats_unpack(stat, len, &(dm->stats[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3 (dm->stats, i,
                                    ofl_structs_free_group_desc_stats, exp, NULL);
            free (dm);
            return error;
        }
        stat = (struct ofp_group_desc_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_processor(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_processor_stats_reply *stat;
    struct ofl_msg_stats_reply_processor *dm;
    ofl_err error;
	size_t stats_num;
    size_t i;

    stat = (struct ofp_processor_stats_reply *)os->body;

    error = ofl_utils_count_ofp_processor_stats(stat, *len, &stats_num, errbuf);
    if (error) {
        return error;
    }

	size_t sum_size = stats_num * sizeof(struct ofl_processor_stat) + sizeof(struct ofl_msg_stats_reply_processor);
    dm = (struct ofl_msg_stats_reply_processor *)malloc(sum_size);

    for (i = 0; i < stats_num; i++) {
        error = ofl_structs_processor_stat_unpack(&(stat->stats[i]), len, &(dm->stats[i]), errbuf);
        if (error) {
            free (dm);
            return error;
        }
    }

	dm->stats_num = stats_num;

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply_processor_inst(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_processor_inst_stats_reply *stat;
    struct ofl_msg_stats_reply_processor_inst *dm;
    ofl_err error;
	size_t stats_num;
    size_t i;

    stat = (struct ofp_processor_inst_stats_reply *)os->body;

    error = ofl_utils_count_ofp_processor_inst_stats(stat, *len, &stats_num, errbuf);
    if (error) {
        return error;
    }

	size_t sum_size = stats_num * sizeof(struct ofl_processor_inst_stat) + sizeof(struct ofl_msg_stats_reply_processor_inst);
    dm = (struct ofl_msg_stats_reply_processor_inst *)malloc(sum_size);

    for (i = 0; i < stats_num; i++) {
        error = ofl_structs_processor_inst_stat_unpack(&(stat->stats[i]), len, &(dm->stats[i]), errbuf);
        if (error) {
            free (dm);
            return error;
        }
    }

	dm->stats_num = stats_num;

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_stats_reply(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp *exp, char *errbuf) {
    struct ofl_msg_stats_reply_header *ofls;
    struct ofp_stats_reply *os;
    int error;

    if (*len < sizeof(struct ofp_stats_reply)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received STATS_REPLY message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_stats_reply);

    os = (struct ofp_stats_reply *)src;

    switch (ntohs(os->type)) {
    case OFPST_DESC: {
        error = ofl_msg_unpack_stats_reply_desc(os, len, msg, errbuf);
        break;
    }
    case OFPST_FLOW: {
        error = ofl_msg_unpack_stats_reply_flow(os, len, msg, exp, errbuf);
        break;
    }
    case OFPST_AGGREGATE: {
        error = ofl_msg_unpack_stats_reply_aggregate(os, len, msg, errbuf);
        break;
    }
    case OFPST_TABLE: {
        error = ofl_msg_unpack_stats_reply_table(os, len, msg, errbuf);
        break;
    }
    case OFPST_PORT: {
        error = ofl_msg_unpack_stats_reply_port(os, len, msg, errbuf);
        break;
    }
    case OFPST_QUEUE: {
        error = ofl_msg_unpack_stats_reply_queue(os, len, msg, errbuf);
        break;
    }
    case OFPST_GROUP: {
        error = ofl_msg_unpack_stats_reply_group(os, len, msg, errbuf);
        break;
    }
    case OFPST_GROUP_DESC: {
        error = ofl_msg_unpack_stats_reply_group_desc(os, len, msg, exp, errbuf);
        break;
    }
	case OFPST_PROCESSOR: {
        error = ofl_msg_unpack_stats_reply_processor(os, len, msg, errbuf);
	    break;
    }
	case OFPST_PROCESSOR_INST: {
        error = ofl_msg_unpack_stats_reply_processor_inst(os, len, msg, errbuf);
	    break;
    }
    case OFPST_EXPERIMENTER: {
        if (exp == NULL || exp->stats == NULL || exp->stats->reply_unpack == NULL) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received EXPERIMENTER stats reply, but no callback was given.");
            }
            error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
        } else {
            error = exp->stats->reply_unpack(os, len, (struct ofl_msg_stats_reply_header **)msg);
        }
        break;
    }
    default: {
        error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
        break;
    }
    }

    if (error) {
        return error;
    }

    ofls = (struct ofl_msg_stats_reply_header *)(*msg);
    ofls->type = (enum ofp_stats_types)ntohs(os->type);
    ofls->flags = ntohs(os->flags);

    return 0;
}

static ofl_err
ofl_msg_unpack_queue_get_config_request(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_queue_get_config_request *sr;
    struct ofl_msg_queue_get_config_request *dr;

    if (*len < sizeof(struct ofp_group_desc_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GET_CONFIG_REQUEST message has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sr = (struct ofp_queue_get_config_request *)src;

    if (ntohl(sr->port) == 0 || ntohl(sr->port) > OFPP_MAX) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GET_CONFIG_REQUEST message has invalid port (%u).", ntohl(sr->port));
        }
        return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    *len -= sizeof(struct ofp_queue_get_config_request);

    dr = (struct ofl_msg_queue_get_config_request *)malloc(sizeof(struct ofl_msg_queue_get_config_request));

    dr->port = ntohl(sr->port);

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}

static ofl_err
ofl_msg_unpack_queue_get_config_reply(struct ofp_header *src, size_t *len, struct ofl_msg_header **msg, char *errbuf) {
    struct ofp_queue_get_config_reply *sr;
    struct ofl_msg_queue_get_config_reply *dr;
    struct ofp_packet_queue *queue;
    ofl_err error;
    size_t i;

    if (*len < sizeof(struct ofp_queue_get_config_reply)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GET_CONFIG_REPLY has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_queue_get_config_reply);

    sr = (struct ofp_queue_get_config_reply *)src;
    dr = (struct ofl_msg_queue_get_config_reply *)malloc(sizeof(struct ofl_msg_queue_get_config_reply));

    dr->port = ntohl(sr->port);

    error = ofl_utils_count_ofp_packet_queues(&(sr->queues), *len, &dr->queues_num, errbuf);
    if (error) {
        free(dr);
        return error;
    }
    dr->queues = (struct ofl_packet_queue **)malloc(dr->queues_num * sizeof(struct ofl_packet_queue *));

    queue = sr->queues;
    for (i = 0; i < dr->queues_num; i++) {
        error = ofl_structs_packet_queue_unpack(queue, len, &(dr->queues[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(dr->queues, i,
                                   ofl_structs_free_packet_queue);
            free (dr);
            return error;
        }
        queue = (struct ofp_packet_queue *)((uint8_t *)queue + ntohs(queue->len));
    }

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}


static ofl_err
ofl_msg_unpack_empty(struct ofp_header *src UNUSED_ATTR, size_t *len, struct ofl_msg_header **msg) {

    // ofp_header length was checked at ofl_msg_unpack
    *len -= sizeof(struct ofp_header);

    *msg = (struct ofl_msg_header *)malloc(sizeof(struct ofl_msg_header));
    return 0;
}


ofl_err
ofl_msg_unpack(uint8_t *buf, size_t buf_len, struct ofl_msg_header **msg, uint32_t *xid, struct ofl_exp *exp, char *errbuf) {
    struct ofp_header *oh;
    size_t len = buf_len;
    ofl_err error = 0;

    if (len < sizeof(struct ofp_header)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received message is shorter than ofp_header.");
        }
        if (xid != NULL) {
            *xid = 0x00000000;
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    oh = (struct ofp_header *)buf;

    if (oh->version != OFP_VERSION) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received message has wrong version.");
        }
        return ofl_error(OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE);
    }

    if (xid != NULL) {
        *xid = ntohl(oh->xid);
    }

    if (len != ntohs(oh->length)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received message length does not match the length field.");
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (oh->type) {
        case OFPT_HELLO:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_ERROR:
            error = ofl_msg_unpack_error(oh, &len, msg, errbuf);
            break;
        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY:
            error = ofl_msg_unpack_echo(oh, &len, msg);
            break;
        case OFPT_EXPERIMENTER:
            if (exp == NULL || exp->msg == NULL || exp->msg->unpack == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received EXPERIMENTER message, but no callback was given.");
                }
                error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            } else {
                error = exp->msg->unpack(oh, &len, (struct ofl_msg_experimenter **)msg);
            }
            break;

        /* Switch configuration messages. */
        case OFPT_FEATURES_REQUEST:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_FEATURES_REPLY:
            error = ofl_msg_unpack_features_reply(oh, &len, msg, errbuf);
            break;
        case OFPT_GET_CONFIG_REQUEST:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_GET_CONFIG_REPLY:
            error = ofl_msg_unpack_get_config_reply(oh, &len, msg, errbuf);
            break;
        case OFPT_SET_CONFIG:
            error = ofl_msg_unpack_set_config(oh, &len, msg, errbuf);
            break;

        /* Asynchronous messages. */
        case OFPT_PACKET_IN:
            error = ofl_msg_unpack_packet_in(oh, &len, msg, errbuf);
            break;
        case OFPT_FLOW_REMOVED:
            error = ofl_msg_unpack_flow_removed(oh, &len, msg, exp, errbuf);
            break;
        case OFPT_PORT_STATUS:
            error = ofl_msg_unpack_port_status(oh, &len, msg, errbuf);
            break;

        /* Controller command messages. */
        case OFPT_PACKET_OUT:
            error = ofl_msg_unpack_packet_out(oh, &len, msg, exp, errbuf);
            break;
        case OFPT_FLOW_MOD:
            error = ofl_msg_unpack_flow_mod(oh, &len, msg, exp, errbuf);
            break;
        case OFPT_GROUP_MOD:
            error = ofl_msg_unpack_group_mod(oh, &len, msg, exp, errbuf);
            break;
        case OFPT_PORT_MOD:
            error = ofl_msg_unpack_port_mod(oh, &len, msg, errbuf);
            break;
        case OFPT_TABLE_MOD:
            error = ofl_msg_unpack_table_mod(oh, &len, msg, errbuf);
            break;
        case OFPT_PROCESSOR_MOD:
            error = ofl_msg_unpack_processor_mod(oh, &len, msg, errbuf);
            break;

        /* Statistics messages. */
        case OFPT_STATS_REQUEST:
            error = ofl_msg_unpack_stats_request(oh, &len, msg, exp, errbuf);
            break;
        case OFPT_STATS_REPLY:
            error = ofl_msg_unpack_stats_reply(oh, &len, msg, exp, errbuf);
            break;

        /* Barrier messages. */
        case OFPT_BARRIER_REQUEST:
        case OFPT_BARRIER_REPLY:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;

        /* Queue Configuration messages. */
        case OFPT_QUEUE_GET_CONFIG_REQUEST:
            error = ofl_msg_unpack_queue_get_config_request(oh, &len, msg, errbuf);
            break;
        case OFPT_QUEUE_GET_CONFIG_REPLY:
            error = ofl_msg_unpack_queue_get_config_reply(oh, &len, msg, errbuf);
            break;

	    /* Packet processor message */
        case OFPT_PROCESSOR_CTRL:
            error = ofl_msg_unpack_processor_ctrl(oh, &len, msg, errbuf);
            break;

        default: {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to unpack unknown message type.");
            }
            error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
        }
    }

    if (error) {
        return error;
    }

    /* Note: len must be decreased by the amount of buffer used by the
             unpack functions. At this point the whole message must be
             consumed, and len should equal to zero. */
    if (len != 0) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received message seemed to be valid, but it contained unused data (%zu).", len);
        }
    }

    (*msg)->type = (enum ofp_type)oh->type;

    return 0;
}
