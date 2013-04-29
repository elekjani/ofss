/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef LLDP_INT_H
#define LLDP_INT_H 1

#define MAX_PORTS 16

#include <pthread.h>
#include <uthash/uthash.h>
#include <stdbool.h>

struct lldp_loop {
    struct lldp_main *lldp_main;
    struct logger    *logger;
    struct ev_loop   *loop;
};

/* Shared object between the LLDP packet processors */
struct lldp_main {
    struct packetproc      *packetproc;
    struct logger          *logger;

    struct lldp_loop       *lldp_loop;

    char*                   system_name;
    char*                   system_description;
    char*                   system_capabilities;
};

/* The private object of a specific LLDP packet processor */
struct lldp_pp {
    struct lldp_main  *lldp_main;
    struct pp         *pp;
    struct dp         *dp;

    struct logger     *logger;

	struct LldpMIB    *lldpMIB;
};

/* Used by the controller to communicate the main configuration parameters
 * for the packet processor */
struct lldp_pp_mod {
    uint16_t lldpMessageTxInterval;
    uint16_t lldpMessageTxHoldMultiplier;
    uint16_t lldpNotificationInterval;

    uint8_t  pad[2];

    uint32_t enabledPorts;
    uint32_t disabledPorts;
};

#endif /* LLDP_INT_H */
