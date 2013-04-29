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

#include "packetproc_int.h"

/* Send pipeline packet to the specific packet porcessor 
 * Used by the dp. This is the main entry point for a packet from the pipeline */
void 
pp_send_msg(struct packetproc *packetproc, struct pl_pkt *pl_pkt, uint32_t process_id, uint32_t input_id);

/* Add flow reference to the specific packet processor 
 * Used by flow table manager if an entry point to the packet processor*/
void
packetproc_add_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref);

/* Remove flow reference from the specific packet processor 
 * Used by flow table manager if an entry get deleted from the table */
void
packetproc_del_flow_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t flow_ref);

/* Add packet processor reference to the specific packet processor
 * Used by other processors to signal the connection if its output is directed to the specific processor */
void
packetproc_add_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref /* processor_id */);

/* Remove packet processor reference from the specific packet processor
 * Used by other processors much like the packetproc_add_pp_ref function */
void
packetproc_del_pp_ref(struct packetproc *packetproc, uint32_t processor_id, uint32_t input_id, uint32_t pp_ref);

/* Create statistics about all type of packet porcessors 
 * More info at struct ofl_msg_stats_reply_processor and struct ofl_processor_stat */
struct ofl_msg_stats_reply_header*
packetproc_stats_reply_all(struct packetproc *packetproc);

/* Create a statistic about a specific type of packet processor 
 * More info at struct ofl_msg_stats_reply_processor and struct ofl_processor_stat */
struct ofl_msg_stats_reply_header*
packetproc_stats_reply(struct packetproc *packetproc, uint32_t type);

/* Create statistics about the inputs of a specific pp's instance
 * More info at struct ofl_processor_inst_stat and struct ofl_msg_stats_reply_processor_inst*/
struct ofl_msg_stats_reply_header*
packetproc_inst_stats_reply_all(struct packetproc *packetproc, uint32_t proc_id);

/* Crate a statistics about a specific input of a pp's instance
 * More info at struct ofl_processor_inst_stat and struct ofl_msg_stats_reply_processor_inst*/
struct ofl_msg_stats_reply_header*
packetproc_inst_stats_reply(struct packetproc *packetproc, uint32_t proc_id, uint32_t input);

/* Create the main structure for the packet processors
 * Used at initailization time, and the returning structure is stored in struct dp */
struct packetproc* 
packetproc_new(struct dp *dp);

/* Forward the packet processor modification or contreller messeage.
 * Used by the controller manager to forward OFPT_PROCESSOR_* messages.
 * The forwarding is done by calling the appropriate packet processor's mod_cb 
 * or ctrl_cb callback */
ssize_t
packetproc_proc_msg(struct packetproc *packetproc, struct ofl_msg_processor *msg);

#endif /* PACKET_PROCESSOR_H */
