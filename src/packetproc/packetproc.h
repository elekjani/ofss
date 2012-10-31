/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H 1

#include <ev.h>
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "oflib/ofl_messages.h"
#include "datapath/pipeline_packet.h"
#include "datapath/dp_int.h"

void 
pp_send_msg(struct packetproc *packetproc, struct pl_pkt *pl_pkt, uint32_t process_id, uint32_t input_id);

void
packetproc_add_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref);

void
packetproc_del_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref);

void
packetproc_add_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref /* processor_id */);

void
packetproc_del_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref);

struct ofl_msg_stats_reply_header*
packetproc_stats_reply_all(struct packetproc *packetproc);

struct ofl_msg_stats_reply_header*
packetproc_stats_reply(struct packetproc *packetproc, uint32_t type);

struct ofl_msg_stats_reply_header*
packetproc_inst_stats_reply_all(struct packetproc *packetproc, uint32_t proc_id);

struct ofl_msg_stats_reply_header*
packetproc_inst_stats_reply(struct packetproc *packetproc, uint32_t proc_id, uint32_t input);

struct packetproc* 
packetproc_new(struct dp *dp);

#endif /* PACKET_PROCESSOR_H */
