/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include "packetproc_types.h"

#define PP_INIT_NAME(CB) CB##_packetproc_init
#define PP_INIT(CB) pp_type = PP_INIT_NAME(CB) (packetproc)

#define INIT(TYPE, TYPE_NAME, CB) \
PP_INIT(CB); \
DL_APPEND(PP_types_list, pp_type); \

void init_packetprocessors(struct packetproc *packetproc){
    logger_log(packetproc->logger,LOG_DEBUG,"Init packetprocessors.");
    PP_types_list = NULL;

    struct PP_types_list *pp_type;
#define ADD_PP(TYPE, TYPE_NAME, CB) INIT(TYPE, TYPE_NAME, CB)
    PP_TYPES_TABLE();
#undef ADD_PP

#define ADD_PP(TYPE, TYPE_NAME, CB) [TYPE]=TYPE_NAME,
    char *PP_names[] = {
        PP_TYPES_TABLE()
    };
    PP_types_name = PP_names;
#undef ADD_PP
}

int cmp_pp_types(struct PP_types_list *a, struct PP_types_list *b) {
    return (a->PP_type == b->PP_type) ? 0 : 1 ;
}

struct PP_types_list *pp_types_get(uint32_t type){
    struct PP_types_list pp;
    pp.PP_type = type;
    struct PP_types_list *pp_type;
    DL_SEARCH(PP_types_list, pp_type, &pp, cmp_pp_types);
    return pp_type;
}
