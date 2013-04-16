/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include <ev.h>

#include "logger/logger.h"
#include "lib/openflow.h"
#include "lib/pkt_buf.h"
#include "datapath/dp_int.h"
#include "datapath/pipeline_packet.h"
#include "packetproc/packetproc_int.h"

#include "lldp_mib.h"
#include "lldp_int.h"
#include "lldp_LLDPU.h"
#include "lldp_msg.h"


void
send_TLV(uint8_t *msg, size_t length, of_port_no_t port, struct lldp_pp *lldp_pp) {
    struct lldp_main *lldp_main = lldp_pp->lldp_main;
    struct dp_loop *dp_loop = lldp_main->packetproc->dp->dp_loop;
    struct pkt_buf *pkt = pkt_buf_new_use(msg, length);
    struct pl_pkt *pl_pkt = pl_pkt_new(pkt, true, OFPP_LOCAL);
    logger_log(lldp_pp->logger, LOG_DEBUG, "send_TLV called with %d byte packet on port %d", length, port);

    dp_pl_pkt_to_port(dp_loop, port, length, pl_pkt);

    return;
}

void
lldpNotifCb(struct ev_loop *l UNUSED_ATTR, struct ev_timer *w, int revents UNUSED_ATTR) {
    struct LldpMIB *lldpMIB = (struct LldpMIB*)w->data;
    if(lldpMIB->lldpLocalData->lldpStatus != LLDP_NONE || lldpMIB->lldpRemoteData->lldpStatus != LLDP_NONE) {
        logger_log(lldpMIB->logger, LOG_DEBUG, "Controller notification is in progress");
        notifyCtrl(lldpMIB);
    } else {
        logger_log(lldpMIB->logger, LOG_DEBUG, "Controller notification initialized but nothing changed");
    }
    return;
}

void
lldpLocalCb(struct ev_loop *l UNUSED_ATTR, struct ev_timer *w, int revents UNUSED_ATTR) {
    struct LldpMIB *lldpMIB = (struct LldpMIB*)w->data;
    struct lldp_pp *lldp_pp = lldpMIB->lldp_pp;
    struct dp *dp = lldp_pp->dp;
    struct LLDPU *LLDPU = malloc(sizeof(struct LLDPU));

    LLDPU->chassisId.subtype = CST_CHASSIS_COMPONENT;
    LLDPU->chassisId.data_length = strlen(lldpMIB->lldpLocalData->lldpLocChassisId);
    LLDPU->chassisId.data = (uint8_t*)lldpMIB->lldpLocalData->lldpLocChassisId;

	LLDPU->TTL.seconds = lldpMIB->lldpConfig->lldpMessageTxInterval * lldpMIB->lldpConfig->lldpMessageTxHoldMultiplier;

    size_t i; 
    for(i = 1; i <= dp->ports_num; i++) {
        struct lldpPortConfigEntry *e;
        struct lldpLocPortEntry *f;
        HASH_FIND(hh, lldpMIB->lldpConfig->lldpPortConfigTable, &i, sizeof(uint16_t), e);
        HASH_FIND(hh, lldpMIB->lldpLocalData->lldpLocPortTable, &i, sizeof(uint16_t), f);
        if( e != NULL && f != NULL) {
            if( e->lldpPortConfigAdminStatus == TXANDRX || e->lldpPortConfigAdminStatus == TXONLY) {
                LLDPU->portId.subtype = f->lldpLocPortIdSubtype;
                LLDPU->portId.data_length = strlen(f->lldpLocPortId);
                LLDPU->portId.data = (uint8_t*)f->lldpLocPortId;

                if(e->lldpPortConfigTLVsTxEnable.portDesc) {
                    LLDPU->port_desc.data_length = strlen(f->lldpLocPortDesc);
                    LLDPU->port_desc.data = (uint8_t*)f->lldpLocPortDesc;
                } else {
                    LLDPU->port_desc.data_length = 0;
                }
                if(e->lldpPortConfigTLVsTxEnable.sysName) {
                    LLDPU->system_name.data_length = strlen(lldpMIB->lldpLocalData->lldpLocSysName);
                    LLDPU->system_name.data = (uint8_t*)lldpMIB->lldpLocalData->lldpLocSysName;
                } else {
                    LLDPU->system_name.data_length = 0;
                }
                if(e->lldpPortConfigTLVsTxEnable.sysDesc) {
                    LLDPU->system_desc.data_length = strlen(lldpMIB->lldpLocalData->lldpLocSysDesc);
                    LLDPU->system_desc.data = (uint8_t*)lldpMIB->lldpLocalData->lldpLocSysDesc;
                } else {
                    LLDPU->system_desc.data_length = 0;
                }
                if(e->lldpPortConfigTLVsTxEnable.sysCap) {
                    LLDPU->system_capabilities.use_it = true;
                    struct LldpSystemCapabilitiesMap *lldpSysCapMapS = &(lldpMIB->lldpLocalData->lldpLocSysCapSupported);
                    struct LldpSystemCapabilitiesMap *lldpSysCapMapE = &(lldpMIB->lldpLocalData->lldpLocSysCapEnabled);
                    uint16_t sup = ((lldpSysCapMapS->other << 7) |
                                   (lldpSysCapMapS->repeater << 6) |
                                   (lldpSysCapMapS->bridge << 5) |
                                   (lldpSysCapMapS->wlanAccessPoint << 4) |
                                   (lldpSysCapMapS->router << 3) |
                                   (lldpSysCapMapS->telephone << 2) |
                                   (lldpSysCapMapS->docsisCableDevices << 1) |
                                   (lldpSysCapMapS->stationOnly));
                    uint16_t ena = ((lldpSysCapMapE->other << 7) |
                                   (lldpSysCapMapE->repeater << 6) |
                                   (lldpSysCapMapE->bridge << 5) |
                                   (lldpSysCapMapE->wlanAccessPoint << 4) |
                                   (lldpSysCapMapE->router << 3) |
                                   (lldpSysCapMapE->telephone << 2) |
                                   (lldpSysCapMapE->docsisCableDevices << 1) |
                                   (lldpSysCapMapE->stationOnly));
                    sup = sup << 8;
                    sup = sup | lldpSysCapMapS->reserved;
                    ena = ena << 8;
                    ena = ena | lldpSysCapMapE->reserved;

                    LLDPU->system_capabilities.capabilities = sup;
                    LLDPU->system_capabilities.enabled = ena;
                } else {
                    LLDPU->system_capabilities.use_it = false;
                }

                uint8_t *msg;
                size_t length;
                create_TLV_from_LLDPU(lldpMIB, LLDPU, i, &msg, &length);
                send_TLV(msg, length, i, lldpMIB->lldp_pp);
                free(msg);
            }
        } else {
            //TODO: error?
            logger_log(lldp_pp->logger, LOG_ERR, "There is no port %d in the MIB", i);
            continue;
        }
    }

    free(LLDPU);

    return;
};

void
lldpRemEntryCb(struct ev_loop *l, struct ev_timer *w, int revents UNUSED_ATTR) {
    struct lldpRemEntry *lldpRemEntry = (struct lldpRemEntry*)w->data;
    struct LldpMIB *lldpMIB = lldpRemEntry->lldpMIB;
    struct lldpRemEntry *e;
    HASH_FIND(hh, lldpMIB->lldpRemoteData->lldpRemTable, &lldpRemEntry->lldpRemIndex, sizeof(struct lldpRemIndex), e);
    if(e == NULL) {
        //TODO: error
        return;
    }
    e->lldpStatus = LLDP_DELETED;
    ev_timer_stop(l, w);

    lldpMIB->lldpRemoteData->lldpStatus = LLDP_CHANGED;
       
    return;
};

void
makeLldpConf(struct LldpMIB* lldpMIB, struct lldp_pp_mod *lldp_pp_mod) {
    struct lldpConfiguration *lldpConfig;
    lldpConfig = malloc(sizeof(struct lldpConfiguration));

    lldpConfig->lldpMessageTxInterval       = lldp_pp_mod->lldpMessageTxInterval;
    lldpConfig->lldpMessageTxHoldMultiplier = lldp_pp_mod->lldpMessageTxHoldMultiplier;
    lldpConfig->lldpNotificationInterval    = lldp_pp_mod->lldpNotificationInterval;

    lldpConfig->lldpPortConfigTable    = NULL;

    struct dp *dp = lldpMIB->lldp_pp->dp;
    size_t i;
    size_t ports_num = dp->ports_num;
    for(i=1; i<=ports_num; i++) {
        if ((lldp_pp_mod->enabledPorts >> (i-1)) & 1) {
            logger_log(lldpMIB->logger,LOG_DEBUG,"Adding port %d to confMIB", i);
            struct lldpPortConfigEntry* lldpPortConfigEntry;
            lldpPortConfigEntry = malloc(sizeof(struct lldpPortConfigEntry));
            lldpPortConfigEntry->lldpPortConfigPortNum            = i;
            lldpPortConfigEntry->lldpPortConfigAdminStatus        = TXANDRX;
            lldpPortConfigEntry->lldpPortConfigNotificationEnable = false;

            lldpPortConfigEntry->lldpPortConfigTLVsTxEnable.portDesc = 1;
            lldpPortConfigEntry->lldpPortConfigTLVsTxEnable.sysName  = 1;
            lldpPortConfigEntry->lldpPortConfigTLVsTxEnable.sysDesc  = 1;
            lldpPortConfigEntry->lldpPortConfigTLVsTxEnable.sysCap   = 1;

            HASH_ADD(hh, lldpConfig->lldpPortConfigTable, lldpPortConfigPortNum, sizeof(LldpPortNumber), lldpPortConfigEntry);
        }
    }

    lldpMIB->lldpConfig = lldpConfig;
};

void
makeLldpStat(struct LldpMIB* lldpMIB, struct lldp_pp_mod *lldp_pp_mod) {
    struct lldpStatistics *lldpStat;
    lldpStat = malloc(sizeof(struct lldpStatistics));
    struct dp *dp = lldpMIB->lldp_pp->dp;

    time_t nowt; struct tm nowtm;
    time(&nowt);
    localtime_r(&nowt, &nowtm);
    lldpStat->lldpStatsRemTablesLastChangeTime = nowtm.tm_sec;
    lldpStat->lldpStatsRemTablesInserts        = 0;
    lldpStat->lldpStatsRemTablesDeletes        = 0;
    lldpStat->lldpStatsRemTablesDrops          = 0;
    lldpStat->lldpStatsRemTablesAgeouts        = 0;

    lldpStat->lldpStatsTxPortTable        = NULL;
    lldpStat->lldpStatsRxPortTable        = NULL;

    size_t i;
    for(i=1;i<=dp->ports_num; i++) {
        if ((lldp_pp_mod->enabledPorts >> (i-1)) & 1) {
            logger_log(lldpMIB->logger,LOG_DEBUG,"Adding port %d to statMIB", i);
            struct lldpStatsTxPortEntry* lldpStatsTxPortEntry = malloc(sizeof(struct lldpStatsTxPortEntry));
            lldpStatsTxPortEntry->lldpStatsTxPortNum = i;
            lldpStatsTxPortEntry->lldpStatsTxPortFramesTotal = 0;
            HASH_ADD(hh, lldpStat->lldpStatsTxPortTable, lldpStatsTxPortNum, sizeof(LldpPortNumber), lldpStatsTxPortEntry);

            struct lldpStatsRxPortEntry* lldpStatsRxPortEntry = malloc(sizeof(struct lldpStatsRxPortEntry));
            lldpStatsRxPortEntry->lldpStatsRxPortNum = i;
            lldpStatsRxPortEntry->lldpStatsRxPortFramesDiscardedTotal = 0;
            lldpStatsRxPortEntry->lldpStatsRxPortFramesErrors = 0;
            lldpStatsRxPortEntry->lldpStatsRxPortFramesTotal = 0;
            lldpStatsRxPortEntry->lldpStatsRxPortTLVsDiscardedTotal = 0;
            lldpStatsRxPortEntry->lldpStatsRxPortTLVsUnrecognizedTotal = 0;
            lldpStatsRxPortEntry->lldpStatsRxPortAgeoutsTotal = 0;
            HASH_ADD(hh, lldpStat->lldpStatsRxPortTable, lldpStatsRxPortNum, sizeof(LldpPortNumber), lldpStatsRxPortEntry);
        }
    }

    lldpMIB->lldpStat = lldpStat;
};

void
makeLldpLocalData(struct LldpMIB* lldpMIB, struct lldp_pp_mod *lldp_pp_mod) {
    struct lldpLocalSystemData *lldpLocalData;
    lldpLocalData = malloc(sizeof(struct lldpLocalSystemData));
    memset(lldpLocalData,0,sizeof(struct lldpLocalSystemData));
    struct dp *dp = lldpMIB->lldp_pp->dp;

    lldpLocalData->lldpLocChassisIdSubtype = CST_CHASSIS_COMPONENT;
    lldpLocalData->lldpLocChassisId = malloc(sizeof(char) * 512);
    memset(lldpLocalData->lldpLocChassisId, 0, sizeof(char) * 512);
    sprintf(lldpLocalData->lldpLocChassisId,"%llX", dp->dpid); 
    lldpLocalData->lldpLocSysName = "Ofss - packet processor";
    lldpLocalData->lldpLocSysDesc = "Openflow softswitch with packet processors";
    memset(&lldpLocalData->lldpLocSysCapSupported ,0,sizeof(struct LldpSystemCapabilitiesMap));
    lldpLocalData->lldpLocSysCapSupported.other = 1;
    memset(&lldpLocalData->lldpLocSysCapEnabled ,0,sizeof(struct LldpSystemCapabilitiesMap));
    lldpLocalData->lldpLocSysCapEnabled.other = 1;
    lldpLocalData->lldpStatus = LLDP_ADDED;

    lldpLocalData->lldpLocPortTable = NULL;

    size_t i;
    size_t ports_num = dp->ports_num;
    for(i=1;i<=ports_num; i++) {
        if ((lldp_pp_mod->enabledPorts >> (i-1)) & 1) {
            logger_log(lldpMIB->logger,LOG_DEBUG,"Adding port %d to localMIB", i);
            struct lldpLocPortEntry* lldpLocPortEntry = malloc(sizeof(struct lldpLocPortEntry));
            memset(lldpLocPortEntry, 0, sizeof(struct lldpLocPortEntry));
            lldpLocPortEntry->lldpLocPortNum = i;
            lldpLocPortEntry->lldpLocPortIdSubtype = PST_INTERFACE_ALIAS;
            sprintf(lldpLocPortEntry->lldpLocPortId, "%d", i);
            lldpLocPortEntry->lldpLocPortDesc = malloc(sizeof(char) * 512);
            memset(lldpLocPortEntry->lldpLocPortDesc, 0, sizeof(char) * 512);
            sprintf(lldpLocPortEntry->lldpLocPortDesc, "local port");
            lldpLocPortEntry->lldpStatus = LLDP_ADDED;
            HASH_ADD(hh, lldpLocalData->lldpLocPortTable, lldpLocPortNum, sizeof(LldpPortNumber), lldpLocPortEntry);
        }
    }

    ev_timer_init(&lldpLocalData->sendTimer, lldpLocalCb, lldpMIB->lldpConfig->lldpMessageTxInterval, lldpMIB->lldpConfig->lldpMessageTxInterval);
    lldpLocalData->sendTimer.data = (void*)lldpMIB;
    ev_timer_start(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpLocalData->sendTimer);

    ev_timer_init(&lldpLocalData->notifTimer, lldpNotifCb, lldpMIB->lldpConfig->lldpNotificationInterval, lldpMIB->lldpConfig->lldpNotificationInterval);
    lldpLocalData->notifTimer.data = (void*)lldpMIB;
    ev_timer_start(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpLocalData->notifTimer);

    lldpMIB->lldpLocalData = lldpLocalData;
};

void
makeLldpRemoteData(struct LldpMIB* lldpMIB, struct lldp_pp_mod *lldp_pp_mod UNUSED_ATTR) {
    struct lldpRemoteSystemData *lldpRemoteData;
    lldpRemoteData = malloc(sizeof(struct lldpRemoteSystemData));

    lldpRemoteData->lldpRemTable = NULL;
    lldpRemoteData->lldpStatus   = LLDP_NONE;

    lldpMIB->lldpRemoteData = lldpRemoteData;
};

struct LldpMIB*
makeMIB(struct lldp_pp_mod *lldp_pp_mod, struct lldp_pp *lldp_pp) {
    struct LldpMIB *lldpMIB = (struct LldpMIB*)malloc(sizeof(struct LldpMIB));
    lldpMIB->lldp_pp = lldp_pp;
    lldpMIB->logger  = lldp_pp->logger;
    makeLldpConf(lldpMIB, lldp_pp_mod);
    makeLldpStat(lldpMIB, lldp_pp_mod);
    makeLldpRemoteData(lldpMIB, lldp_pp_mod);
    makeLldpLocalData(lldpMIB, lldp_pp_mod);

    return lldpMIB;
};

void
modifyMIB(struct LldpMIB *lldpMIB, struct lldp_pp_mod *lldp_pp_mod) {
};

void
refreshMIB(struct LldpMIB *lldpMIB, struct LLDPU* LLDPU, of_port_no_t in_port ) {
    struct lldpRemoteSystemData *lldpRemoteData = lldpMIB->lldpRemoteData;
    struct lldpRemIndex lldpRemIndex;
    memset(&lldpRemIndex, 0x0, sizeof(struct lldpRemIndex));
    lldpRemIndex.lldpRemLocalPortNum = (LldpPortNumber)in_port;
    lldpRemIndex.lldpRemChassisIdSubtype = LLDPU->chassisId.subtype;
    memcpy(lldpRemIndex.lldpRemChassisId, LLDPU->chassisId.data, LLDPU->chassisId.data_length);
    lldpRemIndex.lldpRemPortIdSubtype = LLDPU->portId.subtype;
    memcpy(lldpRemIndex.lldpRemPortId, LLDPU->portId.data, LLDPU->portId.data_length);
    /*logger_log(lldpMIB->logger, LOG_DEBUG, "in_port: %d; c_subtype: %d; c_id: %s; p_subtype: %d; p_id: %s",
               lldpRemIndex.lldpRemLocalPortNum, lldpRemIndex.lldpRemChassisIdSubtype, lldpRemIndex.lldpRemChassisId,
               lldpRemIndex.lldpRemPortIdSubtype, lldpRemIndex.lldpRemPortId);*/

    struct lldpRemEntry *lldpRemEntry;
    HASH_FIND(hh, lldpRemoteData->lldpRemTable, &lldpRemIndex, sizeof(struct lldpRemIndex), lldpRemEntry);
    if(lldpRemEntry == NULL) {
        logger_log(lldpMIB->logger, LOG_DEBUG, "New remote entry");
        lldpRemEntry = malloc(sizeof(struct lldpRemEntry));
        memset(lldpRemEntry, 0, sizeof(struct lldpRemEntry));
        memcpy(&lldpRemEntry->lldpRemIndex, &lldpRemIndex, sizeof(struct lldpRemIndex));
        memcpy(&lldpRemEntry->lldpRemPortDesc, LLDPU->port_desc.data, LLDPU->port_desc.data_length);
        memcpy(&lldpRemEntry->lldpRemSysName, LLDPU->system_name.data, LLDPU->system_name.data_length);
        memcpy(&lldpRemEntry->lldpRemSysDesc, LLDPU->system_desc.data, LLDPU->system_desc.data_length);
        memcpy(&lldpRemEntry->lldpRemSysCapSupported, &LLDPU->system_capabilities.capabilities, 16);
        memcpy(&lldpRemEntry->lldpRemSysCapEnabled, &LLDPU->system_capabilities.enabled, 16);

        lldpRemEntry->lldpStatus = LLDP_ADDED;

        ev_timer_init(&lldpRemEntry->TTL_timer, lldpRemEntryCb, LLDPU->TTL.seconds, LLDPU->TTL.seconds);
        lldpRemEntry->TTL_timer.data = (void*)lldpRemEntry;
        ev_timer_start(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpRemEntry->TTL_timer);

        lldpRemEntry->lldpMIB = lldpMIB;

        HASH_ADD(hh, lldpRemoteData->lldpRemTable, lldpRemIndex, sizeof(struct lldpRemIndex), lldpRemEntry);

        lldpRemoteData->lldpStatus = LLDP_CHANGED;
    } else {
        //TODO: check port desc & sys desc & sys name & capabilities
        ev_timer_again(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpRemEntry->TTL_timer);
    }

    return;
};

void
deleteLldpConf(struct LldpMIB *lldpMIB) {
    logger_log(lldpMIB->logger, LOG_DEBUG, "deleteLldpConf");
    struct lldpConfiguration *lldpConfig = lldpMIB->lldpConfig;
    struct lldpPortConfigEntry *lldpPortConfigEntry, *tmp;
    HASH_ITER(hh, lldpConfig->lldpPortConfigTable, lldpPortConfigEntry, tmp) {
        HASH_DEL(lldpConfig->lldpPortConfigTable, lldpPortConfigEntry);
        free(lldpPortConfigEntry);
    }

    free(lldpConfig);

    return;
}

void
deleteLldpStat(struct LldpMIB *lldpMIB) {
    logger_log(lldpMIB->logger, LOG_DEBUG, "deleteLldpStat");
    struct lldpStatistics *lldpStat = lldpMIB->lldpStat;
    struct lldpStatsTxPortEntry *lldpStatsTxPortEntry, *tmpTx;
    struct lldpStatsRxPortEntry *lldpStatsRxPortEntry, *tmpRx;
    HASH_ITER(hh, lldpStat->lldpStatsTxPortTable, lldpStatsTxPortEntry, tmpTx) {
        HASH_DEL(lldpStat->lldpStatsTxPortTable, lldpStatsTxPortEntry);
        free(lldpStatsTxPortEntry);
    }

    HASH_ITER(hh, lldpStat->lldpStatsRxPortTable, lldpStatsRxPortEntry, tmpRx) {
        HASH_DEL(lldpStat->lldpStatsRxPortTable, lldpStatsRxPortEntry);
        free(lldpStatsRxPortEntry);
    }

    free(lldpStat);

    return;
}

void
deleteRemoteData(struct LldpMIB *lldpMIB) {
    logger_log(lldpMIB->logger, LOG_DEBUG, "deleteLldpRemoteData");
    struct lldpRemoteSystemData *lldpRemoteData = lldpMIB->lldpRemoteData;
    struct lldpRemEntry *lldpRemEntry, *tmp;
    HASH_ITER(hh, lldpRemoteData->lldpRemTable, lldpRemEntry, tmp) {
        ev_timer_stop(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpRemEntry->TTL_timer);
        HASH_DEL(lldpRemoteData->lldpRemTable, lldpRemEntry);
        free(lldpRemEntry);
    }

    free(lldpRemoteData);

    return;
}

void
deleteLldpLocalData(struct LldpMIB *lldpMIB) {
    logger_log(lldpMIB->logger, LOG_DEBUG, "deleteLldpLocalData");
    struct lldpLocalSystemData *lldpLocalData = lldpMIB->lldpLocalData;
    struct lldpLocPortEntry *lldpLocPortEntry, *tmp;
    HASH_ITER(hh, lldpLocalData->lldpLocPortTable, lldpLocPortEntry, tmp) {
        free(lldpLocPortEntry->lldpLocPortDesc);
        HASH_DEL(lldpLocalData->lldpLocPortTable, lldpLocPortEntry);
        free(lldpLocPortEntry);
    }

    free(lldpLocalData->lldpLocChassisId);
    ev_timer_stop(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpLocalData->sendTimer);
    ev_timer_stop(lldpMIB->lldp_pp->lldp_main->lldp_loop->loop, &lldpLocalData->notifTimer);

    free(lldpLocalData);

    return;
}

void
deleteMIB(struct LldpMIB *lldpMIB) {
    deleteLldpConf(lldpMIB);
    deleteLldpStat(lldpMIB);
    deleteRemoteData(lldpMIB);
    deleteLldpLocalData(lldpMIB);

    free(lldpMIB);

    return;
};

void
TTL_timout_cb(struct ev_loop* l, struct ev_timer* t, int revents) {
};
