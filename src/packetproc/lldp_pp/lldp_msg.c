/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include "control/ctrl.h"
#include "datapath/dp_int.h"
#include "logger/logger_int.h"
#include "oflib/ofl_messages.h"
#include "packetproc/packetproc_int.h"

#include "lldp_mib_structs.h"
#include "lldp_msg.h"
#include "lldp_int.h"

void
makeSend_packet(struct LldpMIB *lldpMIB,struct notifData *n) {
    struct ofl_msg_processor_ctrl *ctrlMsg = malloc(sizeof(struct ofl_msg_processor_ctrl));
    ctrlMsg->header.type = OFPT_PROCESSOR_CTRL;
    ctrlMsg->proc_id     = lldpMIB->lldp_pp->pp->proc_id;
    ctrlMsg->type        = lldpMIB->lldp_pp->pp->type_id;
    ctrlMsg->data_length = n->length;
    ctrlMsg->data        = (uint8_t *)n;

    struct dp *dp = lldpMIB->lldp_pp->pp->packetproc->dp;
    ctrl_send_msg(dp->dp_loop->ctrl, CTRL_CONN_ALL, 0, (struct ofl_msg_header *)ctrlMsg);

    return;
}

struct chassisInfo *makeChassisInfo(struct LldpMIB *lldpMIB) {
    struct chassisInfo *chassis  = malloc(sizeof(struct chassisInfo));
    chassis->notifData.status    = lldpMIB->lldpLocalData->lldpStatus;
    chassis->notifData.notifType = CHASSIS_INFO;
    chassis->notifData.length    = sizeof(uint8_t) + sizeof(size_t);

    chassis->chassisIdSubtype    = lldpMIB->lldpLocalData->lldpLocChassisIdSubtype;
    chassis->notifData.length   += sizeof(enum LldpChassisIdSubtype);
    size_t length                = strlen(lldpMIB->lldpLocalData->lldpLocChassisId);
    chassis->chassisId           = strcpy(malloc(length + 1), lldpMIB->lldpLocalData->lldpLocChassisId);
    chassis->notifData.length   += length + 1;

    length = strlen(lldpMIB->lldpLocalData->lldpLocSysName);
    if(length > 0)
        chassis->sysName = strcpy(malloc(length + 1), lldpMIB->lldpLocalData->lldpLocSysName);
    else
        chassis->sysName = NULL;
    chassis->notifData.length += length + 1;

    length = strlen(lldpMIB->lldpLocalData->lldpLocSysDesc);
    if(length > 0)
        chassis->sysDesc = strcpy(malloc(length + 1), lldpMIB->lldpLocalData->lldpLocSysDesc);
    else
        chassis->sysDesc = NULL;
    chassis->notifData.length += length + 1;

    return chassis;
}

struct portInfo* makePortInfo(struct LldpMIB *lldpMIB, struct lldpLocPortEntry *locE) {
    struct portInfo *port     = malloc(sizeof(struct portInfo));
    port->notifData.status    = locE->lldpStatus;
    port->notifData.notifType = PORT_INFO;
    port->notifData.length    = sizeof(uint8_t) + sizeof(size_t);

    port->portNumber          = locE->lldpLocPortNum;
    port->notifData.length   += sizeof(uint16_t);

    port->portIdSubtype       = locE->lldpLocPortIdSubtype;
    port->notifData.length   += sizeof(enum LldpPortIdSubtype);

    size_t length = strlen(locE->lldpLocPortId);
    port->portId              = strcpy(malloc(length + 1), locE->lldpLocPortId);
    port->notifData.length   += length + 1;

    length = strlen(locE->lldpLocPortDesc);
    if(length > 0)
        port->portDesc = strcpy(malloc(length + 1), locE->lldpLocPortDesc);
    else
        port->portDesc = NULL;
    port->notifData.length += length + 1;

    port->chassis            = makeChassisInfo(lldpMIB);
    port->notifData.length  += port->chassis->notifData.length;

    return port;
}

struct linkInfo* makeLinkInfo(struct LldpMIB *lldpMIB, struct lldpRemEntry *remE, struct lldpLocPortEntry *locE) {
    struct linkInfo *link     = malloc(sizeof(struct linkInfo));
    link->notifData.status    = remE->lldpStatus;
    link->notifData.notifType = LINK_INFO;
    link->notifData.length    = sizeof(uint8_t) + sizeof(size_t);

    /*****srcPort*****/
    struct portInfo *srcPort     = malloc(sizeof(struct portInfo));
    srcPort->notifData.status    = LLDP_NONE;
    srcPort->notifData.notifType = PORT_INFO;
    srcPort->notifData.length    = sizeof(uint8_t) + sizeof(size_t);

    srcPort->portNumber        = 0;
    srcPort->notifData.length += sizeof(uint16_t);

    srcPort->portIdSubtype     = remE->lldpRemIndex.lldpRemPortIdSubtype;
    srcPort->notifData.length += sizeof(enum LldpPortIdSubtype);

    size_t length              = strlen(remE->lldpRemIndex.lldpRemPortId);
    srcPort->portId            = strcpy(malloc(length + 1), remE->lldpRemIndex.lldpRemPortId);
    srcPort->notifData.length += length + 1;

    length = strlen(remE->lldpRemPortDesc);
    if(length > 0)
        srcPort->portDesc = strcpy(malloc(length + 1), remE->lldpRemPortDesc);
    else
        srcPort->portDesc = NULL;
    srcPort->notifData.length += length + 1;

    /*****srcChassis****/
    struct chassisInfo *srcChassis  = malloc(sizeof(struct chassisInfo));
    srcChassis->notifData.status    = LLDP_NONE;
    srcChassis->notifData.notifType = CHASSIS_INFO;
    srcChassis->notifData.length    = sizeof(uint8_t) + sizeof(size_t);

    srcChassis->chassisIdSubtype  = remE->lldpRemIndex.lldpRemChassisIdSubtype;
    srcChassis->notifData.length += sizeof(enum LldpChassisIdSubtype);

    length                        = strlen(remE->lldpRemIndex.lldpRemChassisId);
    srcChassis->chassisId         = strcpy(malloc(length + 1), remE->lldpRemIndex.lldpRemChassisId);
    srcChassis->notifData.length += length + 1;

    length = strlen(remE->lldpRemSysName);
    if(length > 0) 
        srcChassis->sysName = strcpy(malloc(length + 1), remE->lldpRemSysName);
    else
        srcChassis->sysName = NULL;
    srcChassis->notifData.length += length + 1;

    length = strlen(remE->lldpRemSysDesc);
    if(length > 0)
        srcChassis->sysDesc = strcpy(malloc(length + 1), remE->lldpRemSysDesc);
    else
        srcChassis->sysDesc = NULL;
    srcChassis->notifData.length += length + 1;

    srcPort->chassis            = srcChassis;
    srcPort->notifData.length  += srcChassis->notifData.length;

    link->srcPort            = srcPort;
    link->notifData.length  += srcPort->notifData.length;

    /*******dstPort*****/
    struct portInfo *dstPort = makePortInfo(lldpMIB, locE);
    dstPort->notifData.status = LLDP_NONE;
    dstPort->chassis->notifData.status = LLDP_NONE;

    link->dstPort           = dstPort;
    link->notifData.length += dstPort->notifData.length;


    return link;
}

void
notifyCtrl(struct LldpMIB *lldpMIB) {
    logger_log(lldpMIB->logger, LOG_DEBUG, "notifyCtrl");

    struct chassisInfo *chassis = makeChassisInfo(lldpMIB);
    if(lldpMIB->lldpLocalData->lldpStatus == LLDP_ADDED) {
        logger_log(lldpMIB->logger, LOG_DEBUG, "Send chassis information.");
        makeSend_packet(lldpMIB, (struct notifData*)chassis);
    }

    if(lldpMIB->lldpLocalData->lldpStatus != LLDP_NONE) {
        struct lldpLocPortEntry *locE;
        for(locE = lldpMIB->lldpLocalData->lldpLocPortTable; locE != NULL; locE = locE->hh.next) {
            if( locE->lldpStatus != LLDP_NONE) {

                struct portInfo *port = makePortInfo(lldpMIB, locE);
                logger_log(lldpMIB->logger, LOG_DEBUG, "Send local port information about port %s", locE->lldpLocPortId);
                makeSend_packet(lldpMIB, (struct notifData*)port);

                if( locE->lldpStatus == LLDP_DELETED) {
                    HASH_DEL(lldpMIB->lldpLocalData->lldpLocPortTable, locE);
                    free(locE->lldpLocPortDesc);
                    free(locE);
                }else{
                    locE->lldpStatus = LLDP_NONE;
                }
            }
        }
        lldpMIB->lldpLocalData->lldpStatus = LLDP_NONE;
    }

    if(lldpMIB->lldpRemoteData->lldpStatus != LLDP_NONE) {
        struct lldpRemEntry *remE;
        for(remE = lldpMIB->lldpRemoteData->lldpRemTable; remE != NULL; remE = remE->hh.next) {
            if( remE->lldpStatus != LLDP_NONE) {

                struct lldpLocPortEntry *locE;
                HASH_FIND(hh, lldpMIB->lldpLocalData->lldpLocPortTable, &remE->lldpRemIndex.lldpRemLocalPortNum, sizeof(LldpPortNumber), locE);
                if(locE == NULL) {
                    //TODO: error & free
                    return;
                }

                struct linkInfo *link = makeLinkInfo(lldpMIB, remE, locE);
                logger_log(lldpMIB->logger, LOG_DEBUG, "Send remote information about chassis %s port %s",
                        remE->lldpRemIndex.lldpRemChassisId, remE->lldpRemIndex.lldpRemPortId);
                makeSend_packet(lldpMIB, (struct notifData*)link);

                if( remE->lldpStatus == LLDP_DELETED) {
                    HASH_DEL(lldpMIB->lldpRemoteData->lldpRemTable, remE);
                    free(remE);
                }else {
                    remE->lldpStatus = LLDP_NONE;
                }
            }
        }
        lldpMIB->lldpRemoteData->lldpStatus = LLDP_NONE;
    }

	return;
}

