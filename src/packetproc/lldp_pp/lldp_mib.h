/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef LLDP_MIB_H
#define LLDP_MIB_H 1

#include "lldp_int.h"
#include "lldp_mib_structs.h"
#include "lldp_LLDPU_structs.h"

#include "lib/openflow.h"

struct LldpMIB*
makeMIB(struct lldp_pp_mod *lldp_pp_mod, struct lldp_pp *lldp_pp);

void
modifyMIB(struct LldpMIB *lldpMIB, struct lldp_pp_mod *lldp_pp_mod);

void
refreshMIB(struct LldpMIB *lldpMIB, struct LLDPU* LLDPU, of_port_no_t in_port );

void
deleteMIB(struct LldpMIB *lldpMIB);

#endif /* LLDP_MIB_H */
