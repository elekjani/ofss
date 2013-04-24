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

/* Create and initialize the main MIB structure */
struct LldpMIB*
makeMIB(struct lldp_pp_mod *lldp_pp_mod, struct lldp_pp *lldp_pp);

/* Called when a OFPPRC_MODIFY message has arrived.
 * Not implemented yet. */
void
modifyMIB(struct LldpMIB *lldpMIB, struct lldp_pp_mod *lldp_pp_mod);

/* If a new LLDP messages arrive, this function refresh or add a new entry
 * to the lldpRemoteSystemData */
void
refreshMIB(struct LldpMIB *lldpMIB, struct LLDPU* LLDPU, of_port_no_t in_port );

/* Free the allocated structure. Used when the packet processor is being deleted. */
void
deleteMIB(struct LldpMIB *lldpMIB);

#endif /* LLDP_MIB_H */
