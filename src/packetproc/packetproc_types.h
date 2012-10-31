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
#include "openflow/openflow.h"
#include "default_packetproc.h"
#include "logger/logger.h"

//TYPE, string name, callback specifier
#define PP_TYPES_TABLE() \
    ADD_PP(DEFAULT, "Default", default)

typedef void (*pp_mod_callback)(struct packetproc *packetproc, uint32_t type, uint32_t proc_id, uint16_t command, void *data);
typedef int (*unpack_callback)(uint8_t *src, uint8_t *msg, enum ofp_type type, char *errbuf);
typedef int (*pack_callback)(uint8_t *msg, uint8_t *buf, enum ofp_type type);

#define ADD_PP(TYPE, TYPE_NAME, CB) TYPE,
enum PP_Types {
    PP_TYPES_TABLE()
};
#undef ADD_PP

char **PP_types_name;

struct PP_types_list {
    uint32_t                PP_type;

    pp_mod_callback         mod_cb;
    unpack_callback         unpack_cb;
    pack_callback           pack_cb;

    uint32_t                PP_msg_data_len;
    uint32_t                current_pp_num;
    uint32_t                max_pp_num;

    struct PP_types_list    *prev;
    struct PP_types_list    *next;
} *PP_types_list;

void init_packetprocessors(struct packetproc *packetproc);

struct PP_types_list *pp_types_get(uint32_t type);

#endif /* PACKETPROC_TYPES_H */
