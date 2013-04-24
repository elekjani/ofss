/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include <netinet/in.h>
#include <pthread.h>
#include <uthash/uthash.h>

#include "datapath/dp.h"
#include "datapath/dp_int.h"
#include "datapath/pipeline_packet.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/message_box.h"
#include "lib/logger_names.h"
#include "lib/pkt_buf.h"
#include "lib/thread_id.h"
#include "oflib/ofl_messages.h"
#include "openflow/openflow.h"
#include "packetproc/packetproc_int.h"

#include "lldp_int.h"
#include "lldp_mib.h"
#include "lldp_packetproc.h"
#include "lldp_LLDPU.h"
#include "lldp_msg.h"

#define MAX_PP_NUM 100

static int
lldp_mod(struct packetproc *packetproc, struct ofl_msg_processor_mod *req, struct pp *pp, struct pp_shared_data *pp_shared_data);

static int
lldp_ctrl(struct packetproc *packetproc, struct ofl_msg_processor_mod *req, struct pp *pp, struct pp_shared_data *pp_shared_data) {
    return 0;
}

static int
lldp_unpack(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf);

static int
lldp_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type);

static int
lldp_free(uint8_t *msg, enum ofp_type type);

static bool
lldp_process_msg(void *pp_, struct list_node *cmd_);

static void*
event_loop(void *lldp_loop_);

struct PP_types_list*
lldp_packetproc_init(struct packetproc *packetproc) {
  struct pp_shared_data *pp_shared_data = malloc(sizeof(struct pp_shared_data));
  pp_shared_data->type                  = LLDP;

  struct lldp_main *lldp_main           = malloc(sizeof(struct lldp_main));
  lldp_main->packetproc                 = packetproc;
  lldp_main->logger                     = logger_mgr_get(LOGGER_NAME_PP_TYPE, PP_types_name[LLDP]);

  struct lldp_loop *lldp_loop           = malloc(sizeof(struct lldp_loop));
  lldp_loop->loop                       = packetproc->loop;
  lldp_loop->logger                     = lldp_main->logger;
  lldp_main->lldp_loop                  = lldp_loop;

  int i;

  for (i = 0; i != MAX_PORTS; i++) {
    lldp_main->port_to_pp[i] = NULL;
  }

  //TODO: get names
  lldp_main->system_name         = "Ofss";
  lldp_main->system_description  = "OpenFlow sowfswitch with packet processors";
  lldp_main->system_capabilities = NULL;

  pp_shared_data->private       = lldp_main;
  HASH_ADD(hh, packetproc->pp_shared_data, type, sizeof(uint32_t), pp_shared_data);

  struct PP_types_list *PP_type = malloc(sizeof(struct PP_types_list));
  PP_type->PP_type              = LLDP;
  PP_type->mod_cb               = lldp_mod;
  PP_type->ctrl_cb              = lldp_ctrl;
  PP_type->unpack_cb            = lldp_unpack;
  PP_type->pack_cb              = lldp_pack;
  PP_type->free_cb              = lldp_free;
  PP_type->current_pp_num       = 0;
  PP_type->max_pp_num           = MAX_PP_NUM;
  PP_type->prev                 = NULL;
  PP_type->next                 = NULL;
  PP_type->logger               = lldp_main->logger;
  logger_log(PP_type->logger, LOG_DEBUG, "\"%s\" packet processor initiated. (%d)", PP_types_name[LLDP], LLDP);

  return PP_type;
}

static int
lldp_mod(struct packetproc *packetproc, struct ofl_msg_processor_mod *req, struct pp *pp, struct pp_shared_data *pp_shared_data) {
  struct PP_types_list *pp_type   = pp_types_get(req->type);
  struct lldp_pp_mod *lldp_pp_mod = (struct lldp_pp_mod *)req->data;
  struct lldp_main *lldp_main     = (struct lldp_main *)pp_shared_data->private;
  struct lldp_pp *lldp_pp         = (struct lldp_pp *)pp->private;

  switch (req->command) {
    case OFPPRC_ADD: {
      pp->inputs_num           = 1;
      pp->outputs_num          = 1;
      pp->msg_mbox             = mbox_new(lldp_main->lldp_loop->loop, pp, lldp_process_msg);

      struct lldp_pp *lldp_pp  = malloc(sizeof(struct lldp_pp));
      lldp_pp->lldp_main       = lldp_main;
      lldp_pp->pp              = pp;
      lldp_pp->dp              = packetproc->dp;
      lldp_pp->logger          = pp->logger;
      lldp_pp->lldpMIB         = makeMIB(lldp_pp_mod, lldp_pp);

      pp->private              = lldp_pp;

      break;
    }
    case OFPPRC_MODIFY: {
      modifyMIB(lldp_pp->lldpMIB, lldp_pp_mod);

      break;
    }
    case OFPPRC_DELETE: {
      logger_log(lldp_main->logger, LOG_DEBUG, "DELETE");
      deleteMIB(lldp_pp->lldpMIB);
      free(lldp_pp);

      break;
    }
  }

  return 0;
}

static int
lldp_unpack(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf) {
  if(type == OFPT_PROCESSOR_MOD) {
    int offset = 0;
    struct lldp_pp_mod *lldp_pp_mod = (struct lldp_pp_mod *)malloc(sizeof(struct lldp_pp_mod));
    lldp_pp_mod->lldpMessageTxInterval       = ntohs(*((uint16_t *)(src + offset)));
    offset += sizeof(uint16_t);
    lldp_pp_mod->lldpMessageTxHoldMultiplier = ntohs(*((uint16_t *)(src + offset)));
    offset += sizeof(uint16_t);
    lldp_pp_mod->lldpNotificationInterval    = ntohs(*((uint16_t *)(src + offset)));
    offset += sizeof(uint16_t);

    offset += 2;

    lldp_pp_mod->enabledPorts  = ntohl(*((uint32_t *)(src + offset)));
    offset += sizeof(uint32_t);
    lldp_pp_mod->disabledPorts = ntohl(*((uint32_t *)(src + offset)));
    offset += sizeof(uint32_t);

    *msg = (uint8_t *)lldp_pp_mod;
  } else if(type == OFPT_PROCESSOR_CTRL) {
    //make something
  }

  return 0;
}


void
lldp_pack_chassis_info(struct chassisInfo *msg, uint8_t *buf) {
  struct chassisInfo *chassis = (struct chassisInfo *)msg;
  uint8_t *tmp = buf;
  *tmp         = chassis->notifData.status << 4;
  *tmp        += chassis->notifData.notifType;
  tmp += sizeof(uint8_t);

  *((size_t*)tmp) = htonl(chassis->notifData.length);
  tmp += sizeof(size_t);

  *((enum LldpChassisIdSubtype*)tmp) = htonl(chassis->chassisIdSubtype);
  tmp += sizeof(enum LldpChassisIdSubtype);

  size_t length = strlen(chassis->chassisId) + 1;
  memcpy(tmp, chassis->chassisId, length);
  tmp += length;

  if(chassis->sysName == NULL) {
    length = 0;
    *tmp = 0;
  } else {
    length = strlen(chassis->sysName) + 1;
    memcpy(tmp, chassis->sysName, length);
  }

  tmp += length;

  if(chassis->sysDesc == NULL) {
    length = 0;
    *tmp = 0;
  } else {
    length = strlen(chassis->sysDesc) + 1;
    memcpy(tmp, chassis->sysDesc, length);
  }

  tmp += length;

  return;
}

void
lldp_pack_port_info(struct portInfo *msg, uint8_t *buf) {
  struct portInfo *port = (struct portInfo *)msg;
  uint8_t *tmp = buf;
  *tmp         = port->notifData.status << 4;
  *tmp        += port->notifData.notifType;
  tmp += sizeof(uint8_t);

  *((size_t*)tmp) = htonl(port->notifData.length);
  tmp += sizeof(size_t);

  lldp_pack_chassis_info(port->chassis, tmp);
  tmp += port->chassis->notifData.length;

  *((uint16_t *)tmp) = htons(port->portNumber);
  tmp += sizeof(uint16_t);

  *((enum LldpPortIdSubtype*)tmp) = htonl(port->portIdSubtype);
  tmp += sizeof(enum LldpPortIdSubtype);

  size_t length = strlen(port->portId) + 1;
  memcpy(tmp, port->portId, length);
  tmp += length;

  if(port->portDesc == NULL) {
    length = 0;
    *tmp = 0;
  } else {
    length = strlen(port->portDesc) + 1;
    memcpy(tmp, port->portDesc, length);
  }

  tmp += length;

  return;
}

void
lldp_pack_link_info(struct linkInfo *msg, uint8_t *buf) {
  struct linkInfo *link = (struct linkInfo *)msg;
  uint8_t *tmp = buf;
  *tmp         = link->notifData.status << 4;
  *tmp        += link->notifData.notifType;
  tmp += sizeof(uint8_t);

  *((size_t*)tmp) = htonl(link->notifData.length);
  tmp += sizeof(size_t);

  lldp_pack_port_info(link->srcPort, tmp);
  tmp += link->srcPort->notifData.length;

  lldp_pack_port_info(link->dstPort, tmp);
  tmp += link->srcPort->notifData.length;

  return;
}

static int
lldp_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type) {
  if(type == OFPT_PROCESSOR_MOD) {
    //no need for this, LLDP packet processor never send OFPT_PROCESSOR_MOD
  } else if(type == OFPT_PROCESSOR_CTRL) {
    struct notifData *notifData = (struct notifData *)msg;

    switch(notifData->notifType) {
      case CHASSIS_INFO:
        lldp_pack_chassis_info((struct chassisInfo *)msg, buf);
        break;
      case PORT_INFO:
        lldp_pack_port_info((struct portInfo *)msg, buf);
        break;
      case LINK_INFO:
        lldp_pack_link_info((struct linkInfo *)msg, buf);
        break;
    }
  }

  return 0;
}

static int
lldp_free(uint8_t *msg, enum ofp_type type) {
  if(type == OFPT_PROCESSOR_MOD) {
  } else if(type == OFPT_PROCESSOR_CTRL) {
    struct notifData *notifData = (struct notifData *)msg;

    switch(notifData->notifType) {
      case CHASSIS_INFO: {
        struct chassisInfo *chassis = (struct chassisInfo *)msg;
        free(chassis->chassisId);
        free(chassis->sysName);
        free(chassis->sysDesc);
        break;
      }
      case PORT_INFO: {
        struct portInfo *port = (struct portInfo *)msg;
        lldp_free((uint8_t*)port->chassis, type);
        free(port->portId);
        free(port->portDesc);
        break;
      }
      case LINK_INFO: {
        struct linkInfo *link = (struct linkInfo *)msg;
        lldp_free((uint8_t*)link->srcPort, type);
        lldp_free((uint8_t*)link->dstPort, type);
        break;
      }
    }

    free(msg);
  }

  return 0;
}

static bool
lldp_process_msg(void *pp_, struct list_node *cmd_) {
  struct pp *pp      = (struct pp *)pp_;
  struct pp_msg *pp_msg = (struct pp_msg *)cmd_;
  struct packetproc *packetproc = pp->packetproc;
  struct dp *dp = packetproc->dp;
  struct dp_loop *dp_loop = dp->dp_loop;
  struct pl_pkt *pl_pkt = pp_msg->pl_pkt;
  struct pkt_buf *pkt_buf = pl_pkt->pkt;
  struct lldp_pp *lldp_pp = (struct lldp_pp *)pp->private;

  logger_log(pp->logger, LOG_DEBUG, "Packet received. input: %u", pp_msg->input_id);

  char errbuf[BUFSIZ];
  struct LLDPU *LLDPU = create_LLDPU_from_TLV(pkt_buf->data, pkt_buf->data_len, errbuf);

  if(LLDPU == NULL) {
    logger_log(lldp_pp->logger, LOG_WARN, "Invalid LLDP TLV: %s", errbuf);
    return false;
  }

  refreshMIB(lldp_pp->lldpMIB, LLDPU, pl_pkt->in_port);
  free_LLDPU(LLDPU);

  pl_pkt_free(pp_msg->pl_pkt, true);
  free(pp_msg);

  return true;
}

