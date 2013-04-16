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

#include <pthread.h>

#define PP_INIT_NAME(CB) CB##_packetproc_init
#define PP_INIT(CB) pp_type = PP_INIT_NAME(CB) (packetproc)

#define INIT(TYPE, TYPE_NAME, CB) \
PP_INIT(CB); \
DL_APPEND(PP_types_list, pp_type); \

void init_packetprocessors(struct packetproc *packetproc){
    pthread_mutex_lock(packetproc->mutex);
    logger_log(packetproc->logger,LOG_DEBUG,"Init packetprocessors.");
    PP_types_list = NULL;

    int count = 0;
#define ADD_PP(TYPE, TYPE_NAME, CB) count++;
    PP_TYPES_TABLE();
#undef ADD_PP

    PP_types_name = malloc(count * sizeof(char*));
    count = 0;
#define ADD_PP(TYPE, TYPE_NAME, CB) PP_types_name[count++] = TYPE_NAME;
    PP_TYPES_TABLE()
#undef ADD_PP

    struct PP_types_list *pp_type;
#define ADD_PP(TYPE, TYPE_NAME, CB) INIT(TYPE, TYPE_NAME, CB)
    PP_TYPES_TABLE();
#undef ADD_PP
    pthread_mutex_unlock(packetproc->mutex);

}

int cmp_pp_types(struct PP_types_list *a, struct PP_types_list *b) {
    return (a->PP_type == b->PP_type) ? 0 : 1;
}

struct PP_types_list *pp_types_get(uint32_t type){
    if( type == 0xfffffffe) {
        return PP_types_list;
    }else {
        struct PP_types_list pp;
        pp.PP_type = type;
        struct PP_types_list *pp_type;
        DL_SEARCH(PP_types_list, pp_type, &pp, cmp_pp_types);
        return pp_type;
    }
}
