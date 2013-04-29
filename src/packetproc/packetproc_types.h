/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef PACKETPROC_TYPES_H
#define PACKETPROC_TYPES_H 1

#include <uthash/utlist.h>

#include "packetproc_int.h"

#include "lldp_pp/lldp_packetproc.h"
#include "logger/logger.h"
#include "openflow/openflow.h"
#include "oflib/ofl_messages.h"

/***Add here the new packet processor***/
/*TYPE, string name, callback specifier*/

#include "default_pp/default_packetproc.h"
#include "lldp_pp/lldp_packetproc.h"
#include "gre_pp/gre_packetproc.h"

#define PP_TYPES_TABLE() \
    ADD_PP(DEFAULT, "Default", default) \
    ADD_PP(LLDP,    "lldp",    lldp)    \
    ADD_PP(GRE,     "gre",     gre)

/***************************************/

/******callback types********/
/* The mod and ctrl callback is needed to message handling. This two callback get the OFPT_PROCESSOR_MOD and OFPT_PROCESSOR_CTRL messages.
 * The unpack and pack callback is used to convert bettween OFPT_PROCESSOR_* buffer and internal structure. This two callback interpret
 * the data member of ofp_processor_* structures if there is any.
 * The free callback is used to free memory in a OFPT_PROCESSOR_* message. */
typedef int (*unpack_callback)(uint8_t *src, uint8_t **msg, enum ofp_type type, char *errbuf);
typedef int (*pack_callback)(uint8_t *msg, uint8_t *buf, enum ofp_type type);
typedef int (*free_callback)(uint8_t *msg, enum ofp_type type);
typedef int (*mod_callback)(struct packetproc *packetproc, struct ofl_msg_processor_mod *req, struct pp *pp, struct pp_shared_data *pp_shared_data );
typedef int (*ctrl_callback)(struct packetproc *packetproc, struct ofl_msg_processor_ctrl *req, struct pp *pp, struct pp_shared_data *pp_shared_data );
/****************************/

#define ADD_PP(TYPE, TYPE_NAME, CB) TYPE,
enum PP_Types {
    PP_TYPES_TABLE()
};
#undef ADD_PP

/* Array of packe processor's names. (e.g. PP_types_name[DEFAULT] == "Default") */
char **PP_types_name;

struct PP_types_list {
    uint32_t                PP_type;

    unpack_callback         unpack_cb;
    pack_callback           pack_cb;
    mod_callback            mod_cb;
    ctrl_callback           ctrl_cb;
	free_callback			free_cb;

    uint32_t                current_pp_num;
    uint32_t                max_pp_num;

    struct logger           *logger;

    struct PP_types_list    *prev;
    struct PP_types_list    *next;
} *PP_types_list;

/* Initialize packet processor:
 * i,  Initialize PP_types_name array
 * ii, Call for every registered pp type the initializer
 *     (e.g default_packetproc_init) */
void init_packetprocessors(struct packetproc *packetproc);

/* Return PP_types_list for a specific packet processor type. */
struct PP_types_list *pp_types_get(uint32_t type);

#endif /* PACKETPROC_TYPES_H */
