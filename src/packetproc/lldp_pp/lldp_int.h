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

struct lldp_main {
    struct packetproc      *packetproc;
    struct logger          *logger;

    struct lldp_loop       *lldp_loop;

    struct pp              *port_to_pp[MAX_PORTS];  /* map of entries based on their unique ID. */

    char*                   system_name;
    char*                   system_description;
    char*                   system_capabilities;
};

struct lldp_pp {
    struct lldp_main  *lldp_main;
    struct pp         *pp;
    struct dp         *dp;

    struct logger     *logger;

	struct LldpMIB    *lldpMIB;
};

struct lldp_pp_mod {
    uint16_t lldpMessageTxInterval;
    uint16_t lldpMessageTxHoldMultiplier;
    uint16_t lldpNotificationInterval;

    uint8_t  pad[2];

    uint32_t enabledPorts;
    uint32_t disabledPorts;
};

#endif /* LLDP_INT_H */
