/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef LLDP_PACKETPROC_H
#define LLDP_PACKETPROC_H 1

#include "packetproc/packetproc_types.h"
#include "packetproc/packetproc_int.h"

struct PP_types_list* 
lldp_packetproc_init(struct packetproc *packetproc);

#endif /* LLDP_PACKETPROC_H */
