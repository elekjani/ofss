/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef DEFAULT_PACKETPROC_H
#define DEFAULT_PACKETPROC_H 1

#include "openflow/openflow.h"
#include "packetproc_types.h"

struct PP_types_list* 
default_packetproc_init(struct packetproc *packetproc);

#endif /* DEFAULT_PACKETPROC_H */
