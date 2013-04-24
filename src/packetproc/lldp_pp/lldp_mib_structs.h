/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 *
 * This header contains a partial realization of the LLDP MIB.
 * More information can be found in the IEEE 802.1AB standard.
 *
 */

#ifndef LLDP_MIB_STRUCTS_H
#define LLDP_MIB_STRUCTS_H 1

#include "uthash/uthash.h"
#include "lldp_int.h"
#include "ev.h"


/* Describe the status of the MIB or a specific entity in the MIB. */
enum LldpStatus {
    LLDP_NONE    = 0,
    LLDP_ADDED   = 1,
    LLDP_DELETED = 2,
    LLDP_CHANGED = 3,
};

enum LldpChassisIdSubtype {
    CST_CHASSIS_COMPONENT = 1,
    CST_INTERFACEALIAS   = 2,
    CST_PORT_COMPONENT    = 3,
    CST_MAC_ADDRESS       = 4,
    CST_NETWORK_ADDRESS   = 5,
    CST_INTERFACE_NAME    = 6,
    CST_LOCAL            = 7,
};

typedef char LldpChassisId[256];

enum LldpPortIdSubtype {
    PST_INTERFACE_ALIAS = 1,
    PST_PORT_COMPONENT  = 2,
    PST_MAC_ADDRESS     = 3,
    PST_NETWORK_ADDRESS = 4,
    PST_INTERFACE_NAME  = 5,
    PST_AGENT_CIRCUIT_ID = 6,
    PST_LOCAL          = 7,
};

typedef char LldpPortId[256];

enum LldpManAddressIfSubtype {
    UNKNOWN          = 1,
    IF_INDEX          = 2,
    SYSTEM_PORT_NUMBER = 3,
};

typedef char LldpManAddress[32];

struct LldpSystemCapabilitiesMap {
    uint8_t other:1; //0
    uint8_t repeater:1; //1
    uint8_t bridge:1; //2
    uint8_t wlanAccessPoint:1; //3
    uint8_t router:1; //4
    uint8_t telephone:1; //5
    uint8_t docsisCableDevices:1; //6
    uint8_t stationOnly:1; //7

    uint8_t reserved;
};

typedef uint16_t LldpPortNumber;
typedef uint8_t LldpPortList[512]; //[512]

enum LldpPortConfigAdminStatus {
    TXONLY = 1,
    RXONLY = 2,
    TXANDRX = 3,
    DISABLED = 4,
};

struct LldpPortConfigTLVsTxEnable {
    uint8_t portDesc:1;
    uint8_t sysName:1;
    uint8_t sysDesc:1;
    uint8_t sysCap:1;
};

/*********Configuration*********/
struct lldpPortConfigEntry {
    LldpPortNumber lldpPortConfigPortNum; //INDEX
    enum LldpPortConfigAdminStatus lldpPortConfigAdminStatus; // = txAndRx
    bool     lldpPortConfigNotificationEnable; // = false
    struct LldpPortConfigTLVsTxEnable lldpPortConfigTLVsTxEnable;

    UT_hash_handle hh;
};

struct lldpConfiguration {
    uint16_t lldpMessageTxInterval; // = 30;
    uint16_t  lldpMessageTxHoldMultiplier; // = 4;
    uint16_t lldpNotificationInterval; // = 5;

    struct lldpPortConfigEntry* lldpPortConfigTable;
};

/*********Statistics*************/
struct lldpStatsTxPortEntry {
    LldpPortNumber lldpStatsTxPortNum;  //INDEX
    uint32_t lldpStatsTxPortFramesTotal;

    UT_hash_handle hh;
};

struct lldpStatsRxPortEntry {
    LldpPortNumber lldpStatsRxPortNum; //INDEX
    uint32_t lldpStatsRxPortFramesDiscardedTotal;
    uint32_t lldpStatsRxPortFramesErrors;
    uint32_t lldpStatsRxPortFramesTotal;
    uint32_t lldpStatsRxPortTLVsDiscardedTotal;
    uint32_t lldpStatsRxPortTLVsUnrecognizedTotal;
    uint32_t lldpStatsRxPortAgeoutsTotal;

    UT_hash_handle hh;
};

struct lldpStatistics {
    uint32_t lldpStatsRemTablesLastChangeTime;
    uint32_t lldpStatsRemTablesInserts;
    uint32_t lldpStatsRemTablesDeletes;
    uint32_t lldpStatsRemTablesDrops;
    uint32_t lldpStatsRemTablesAgeouts;

    struct lldpStatsTxPortEntry* lldpStatsTxPortTable;
    struct lldpStatsRxPortEntry* lldpStatsRxPortTable;
};

/************Local system data*******/
struct lldpLocPortEntry {
    LldpPortNumber lldpLocPortNum; //INDEX
    enum LldpPortIdSubtype lldpLocPortIdSubtype;
    LldpPortId lldpLocPortId;
    char* lldpLocPortDesc;

    enum LldpStatus lldpStatus;

    UT_hash_handle hh;
};

struct lldpLocalSystemData {
    enum LldpChassisIdSubtype lldpLocChassisIdSubtype;
    char*     lldpLocChassisId;
    char*     lldpLocSysName;
    char*     lldpLocSysDesc;
    struct LldpSystemCapabilitiesMap lldpLocSysCapSupported;
    struct LldpSystemCapabilitiesMap lldpLocSysCapEnabled;

    struct lldpLocPortEntry* lldpLocPortTable;

    enum LldpStatus lldpStatus;

    struct ev_timer sendTimer;
    struct ev_timer notifTimer;
};

/***********Remote Systems Data************/
struct lldpRemIndex {
    LldpPortNumber lldpRemLocalPortNum; 
    enum LldpChassisIdSubtype lldpRemChassisIdSubtype;
    LldpChassisId lldpRemChassisId;
    enum LldpPortIdSubtype lldpRemPortIdSubtype;
    LldpPortId lldpRemPortId;
};
 
struct lldpRemEntry {
    struct lldpRemIndex lldpRemIndex;

    char lldpRemPortDesc[256];
    char lldpRemSysName[256];
    char lldpRemSysDesc[256];
    struct LldpSystemCapabilitiesMap lldpRemSysCapSupported;
    struct LldpSystemCapabilitiesMap lldpRemSysCapEnabled;

    struct ev_timer TTL_timer;

    struct LldpMIB *lldpMIB;

    enum LldpStatus lldpStatus;

    UT_hash_handle hh;
};

struct lldpRemoteSystemData {
    struct lldpRemEntry* lldpRemTable;

    enum LldpStatus lldpStatus;
};

/**************************************************/

struct LldpMIB {
    struct lldpConfiguration *lldpConfig;
    struct lldpStatistics *lldpStat;
    struct lldpLocalSystemData *lldpLocalData;
    struct lldpRemoteSystemData *lldpRemoteData;

	struct lldp_pp *lldp_pp;
    struct logger  *logger;
};

#endif /* LLDP_MIB_STRUCTS_H */
