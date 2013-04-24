/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef GRE_STURCTS_H
#define GRE_STURCTS_H

#include <inttypes.h>
#include <stdbool.h>

/* Configuration structure. This is sent by the controller to create a new pp */
struct gre_pp_mod {
    uint32_t local_ip;
    uint32_t local_tunnel_ip;
    uint32_t remote_ip;
    uint32_t remote_tunnel_ip;
    uint32_t interface;
};

struct gre_pp {
    struct pp *pp;
    struct dp *dp;
    struct packetproc *packetproc;

    struct logger *logger;

    uint32_t remote_ip;
    uint32_t local_ip;
    uint32_t interface;
};

#endif /* GRE_STURCTS_H */
